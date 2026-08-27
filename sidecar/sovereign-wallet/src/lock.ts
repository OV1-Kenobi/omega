//! Data-root lock, waved pid/lock, stale-waved reaping, single-waved
//! enforcement, and Windows process-tree termination (SEC-2026-049).
//!
//! - The sidecar takes an exclusive lock on `run/sidecar.lock` (O_EXCL-style
//!   create) and reports ALREADY_RUNNING if it is held.
//! - waved's pid is recorded at `run/waved.pid`; before spawning a new waved,
//!   the sidecar reaps a stale waved (graceful stop, then tree kill) and
//!   refuses a second waved on the same data dir (single-waved enforcement).
//! - When the sidecar is force-terminated on Windows, the supervisor uses
//!   `taskkill /T` (job-object-equivalent) so the waved tree dies with it.

import { execFileSync, spawnSync } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

export class LockHeldError extends Error {}

export interface LockHandle {
  release(): Promise<void>;
}

/**
 * Exclusive advisory lock via O_EXCL create of a pid file. Stale detection:
 * if the pid in the file is not alive, the lock is reclaimed.
 */
export async function acquireLock(lockPath: string, owner: string): Promise<LockHandle> {
  await fs.mkdir(path.dirname(lockPath), { recursive: true });
  const payload = `${process.pid}|${owner}|${Date.now()}\n`;
  try {
    const handle = await fs.open(lockPath, "wx", 0o600);
    await handle.writeFile(payload, "utf8");
    await handle.sync();
    await handle.close();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const existing = await readLock(lockPath);
      if (existing && isPidAlive(existing.pid)) {
        throw new LockHeldError(
          `lock held by pid ${existing.pid} (${existing.owner}); refusing to start (ALREADY_RUNNING)`,
        );
      }
      // Stale lock: remove and retry once.
      await fs.rm(lockPath, { force: true });
      const handle = await fs.open(lockPath, "wx", 0o600);
      await handle.writeFile(payload, "utf8");
      await handle.sync();
      await handle.close();
    } else {
      throw error;
    }
  }
  let released = false;
  return {
    async release(): Promise<void> {
      if (released) return;
      released = true;
      await fs.rm(lockPath, { force: true });
    },
  };
}

interface LockRecord {
  pid: number;
  owner: string;
}

async function readLock(lockPath: string): Promise<LockRecord | null> {
  try {
    const raw = await fs.readFile(lockPath, "utf8");
    const [pid, owner] = raw.split("|");
    const parsed = Number.parseInt(pid ?? "", 10);
    if (!Number.isFinite(parsed)) return null;
    return { pid: parsed, owner: owner ?? "unknown" };
  } catch {
    return null;
  }
}

/** True when a process with `pid` exists. Windows uses tasklist; POSIX uses kill(pid, 0). */
export function isPidAlive(pid: number): boolean {
  if (pid <= 0) return false;
  if (process.platform === "win32") {
    const result = spawnSync("tasklist", ["/FI", `PID eq ${pid}`, "/NH"], {
      windowsHide: true,
      encoding: "utf8",
    });
    // tasklist prints the process row when it exists; "INFO: No tasks" when not.
    return result.status === 0 && result.stdout.includes(String(pid));
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Terminate a process and its whole tree on Windows (`taskkill /T`), or
 * SIGTERM-then-KILL on POSIX. `graceMs` is the wait before escalation.
 */
export async function terminateTree(pid: number, graceMs = 2000): Promise<void> {
  if (!isPidAlive(pid)) return;
  if (process.platform === "win32") {
    // First a soft TerminateProcess via node (matches the effectd supervisor's
    // non-Unix path), then the tree kill as the authoritative sweep.
    try {
      process.kill(pid);
    } catch {
      // already gone
    }
    await sleep(graceMs);
    if (isPidAlive(pid)) {
      execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    }
    return;
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    return;
  }
  await sleep(graceMs);
  if (isPidAlive(pid)) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // gone
    }
  }
}

/**
 * Reap a stale waved for this data root: if `run/waved.pid` names a live
 * process, terminate its tree (graceful stop first, then tree kill). If a
 * live waved exists AND `sidecar.lock` is held by another live sidecar, refuse
 * (single-waved enforcement) rather than killing a healthy owner's daemon.
 */
export async function reapStaleWaved(
  runDir: string,
  opts: { refuseIfOwnedByLiveSidecar: boolean; sidecarLockPath: string },
): Promise<void> {
  const pidPath = path.join(runDir, "waved.pid");
  const record = await readLock(pidPath);
  if (!record || !isPidAlive(record.pid)) {
    await fs.rm(pidPath, { force: true });
    return;
  }
  if (opts.refuseIfOwnedByLiveSidecar) {
    const sidecar = await readLock(opts.sidecarLockPath);
    if (sidecar && isPidAlive(sidecar.pid)) {
      throw new LockHeldError(
        `waved pid ${record.pid} is owned by a live sidecar (pid ${sidecar.pid}); refusing a second waved on this data root`,
      );
    }
  }
  await terminateTree(record.pid);
  await fs.rm(pidPath, { force: true });
}

export async function writeWavedPid(runDir: string, pid: number): Promise<void> {
  await fs.mkdir(runDir, { recursive: true });
  await fs.writeFile(path.join(runDir, "waved.pid"), `${pid}|waved|${Date.now()}\n`, {
    mode: 0o600,
  });
}

export async function clearWavedPid(runDir: string): Promise<void> {
  await fs.rm(path.join(runDir, "waved.pid"), { force: true });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export { fsConstants };