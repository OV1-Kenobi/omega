//! Data-root lock and stale-lock reaping (SEC-2026-049 heritage).
//!
//! OMEGA-DELTA-0303 (rail swap): the waved launch/probe/PID machinery
//! (`waved.pid`, stale-waved reaping, single-waved enforcement, the Windows
//! process-tree termination used only for waved) is REMOVED — the sidecar is a
//! client-only process for the phoenixd rail (design §2, deletion disposition
//! §8.1); no daemon child is spawned, supervised, or tree-killed.
//!
//! - The sidecar takes an exclusive lock on `run/sidecar.lock` (O_EXCL-style
//!   create) and reports ALREADY_RUNNING if it is held.
//! - Stale-lock detection: if the pid in the lock file is not alive, the lock
//!   is reclaimed.

import { spawnSync } from "node:child_process";
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

export { fsConstants };