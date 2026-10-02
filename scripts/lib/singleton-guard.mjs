// singleton-guard.mjs — Shared singleton-reuse guard library (spawn-path chokepoint)
//
// ONE shared module imported by every launcher before it may spawn anything.
// When a healthy instance already holds the lock, the guard REFUSES to spawn —
// duplication becomes structurally impossible regardless of caller behavior.
//
// Technical authority: approved WP2 design note
//   planning/2026/09-september/13-plan-resource-hygiene/wp2-design/singleton-reuse-design.md
// Enforcement layer for the Resource Hygiene rules (founder-approved 2026-09-13).
//
// Scope contract:
//   - Node.js stdlib ONLY (fs, path, child_process, net). No npm dependencies.
//   - Lockfiles live under Temp\opencode\locks (agent boundary, per Decision 4).
//   - Logs go to stderr ONLY (stdout is the MCP/stdio protocol channel).
//   - Browser-reuse probe is READ-ONLY detection: it never kills, terminates, or
//     touches existing browser instances (founder-manual domain, Decision 4).
//
// Lockfile JSON schema (lockfileVersion 1):
//   { service, pid, port, startTime, lockfileVersion, healthEndpoint, ownerWindow,
//     staleThresholdMs, lastHeartbeat, updatedAt }

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import net from 'node:net';

// ---------------------------------------------------------------------------
// Constants and configuration
// ---------------------------------------------------------------------------

// Canonical lock directory: %LOCALAPPDATA%\Temp\opencode\locks
// SINGLETON_GUARD_LOCK_DIR overrides for hermetic tests / rollback fallback
// (design Assumption 3); the default is the design-specified path.
const LOCK_DIR =
  process.env.SINGLETON_GUARD_LOCK_DIR ||
  join(process.env.LOCALAPPDATA || '', 'Temp', 'opencode', 'locks');

const STALE_THRESHOLD_MS = 30000; // lock considered abandoned after this without heartbeat
const HEARTBEAT_INTERVAL_MS = 10000; // long-running servers update lastHeartbeat every 10s
const LOCKFILE_VERSION = 1;
const TCP_TIMEOUT_MS = 500; // TCP connect probe timeout
const HTTP_TIMEOUT_MS = 2000; // protocol health-check fetch timeout
const REAP_WAIT_MS = 3000; // SIGTERM -> wait -> SIGKILL
const PORT_RELEASE_WAIT_MS = 5000; // max wait for port release after reap
const MAX_ACQUIRE_DEPTH = 3; // recursion cap for lock acquisition races

let QUIET = false;

function logInfo(service, message) {
  if (QUIET) return;
  process.stderr.write(`[singleton-guard] ${service}: ${message}\n`);
}

function logWarn(service, message) {
  process.stderr.write(`[singleton-guard] ${service}: WARN ${message}\n`);
}

/** Suppress info-level logging (warnings always shown). */
export function setQuiet(quiet) {
  QUIET = Boolean(quiet);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function execFileAsync(file, args) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true }, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve({ stdout, stderr });
    });
  });
}

/** Service names flow into file paths; sanitize to a safe filename fragment. */
function sanitizeServiceName(service) {
  const safe = String(service).replace(/[^a-zA-Z0-9._-]/g, '-');
  if (!safe) {
    throw new TypeError(`singleton-guard: invalid service name "${service}"`);
  }
  return safe;
}

// ---------------------------------------------------------------------------
// Lockfile primitives
// ---------------------------------------------------------------------------

/** Resolve (and ensure) the lockfile path for a service. */
export async function getLockPath(service) {
  await fs.mkdir(LOCK_DIR, { recursive: true });
  return join(LOCK_DIR, `${sanitizeServiceName(service)}.lock`);
}

/** Build the lock record for the current process. */
export function createLockData(service, options = {}) {
  const now = new Date().toISOString();
  return {
    service: sanitizeServiceName(service),
    pid: process.pid,
    port: options.port ?? null,
    startTime: now,
    lockfileVersion: LOCKFILE_VERSION,
    healthEndpoint: options.healthEndpoint ?? null,
    ownerWindow: options.ownerWindow ?? process.env.OPENCODE_WINDOW_ID ?? 'unknown-window',
    staleThresholdMs: options.staleThresholdMs ?? STALE_THRESHOLD_MS,
    lastHeartbeat: now,
    updatedAt: now,
  };
}

/** Read and parse a lockfile; throws on unreadable/corrupt content. */
export async function readLockFile(lockPath) {
  const raw = await fs.readFile(lockPath, 'utf8');
  return JSON.parse(raw);
}

/** Atomic write via temp file + rename (Windows MoveFileEx replace semantics). */
export async function writeLockFile(lockPath, data) {
  const tmpPath = `${lockPath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  try {
    await fs.rename(tmpPath, lockPath);
  } catch (err) {
    await fs.rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
  return data;
}

/** Read-modify-write a lockfile atomically (used for pid/port updates at startup).
 *  Requires an EXISTING lock: throws on missing/corrupt rather than re-creating —
 *  a zombie re-creation would defeat the heartbeat ownership guard. */
export async function updateLockfile(lockPath, updates = {}) {
  const lock = await readLockFile(lockPath);
  const merged = { ...lock, ...updates, updatedAt: new Date().toISOString() };
  await writeLockFile(lockPath, merged);
  return merged;
}

/** Heartbeat-only in-place update via open('r+'). Throws ENOENT if the lockfile
 *  was deleted between the ownership read and the write, so a released/stolen
 *  lock is never resurrected by an in-flight heartbeat (closes the delete-vs-
 *  rename TOCTOU that temp+rename cannot). Single writer by design. */
export async function updateHeartbeat(lockPath) {
  const fd = await fs.open(lockPath, 'r+');
  try {
    const lock = JSON.parse(await fd.readFile('utf8'));
    lock.lastHeartbeat = new Date().toISOString();
    lock.updatedAt = lock.lastHeartbeat;
    const json = JSON.stringify(lock, null, 2);
    await fd.truncate(0);
    await fd.write(json, 0, 'utf8'); // explicit position 0 — truncate does not reset the file position
  } finally {
    await fd.close();
  }
}

/** Delete a lockfile; missing file is not an error. */
export async function deleteLockfile(lockPath) {
  await fs.rm(lockPath, { force: true });
}

// ---------------------------------------------------------------------------
// Lock acquisition protocol (design § Lockfile Acquisition Protocol)
// ---------------------------------------------------------------------------

/**
 * Acquire the singleton lock for a service.
 *
 * Returns:
 *   { acquired: true,  lockPath, lock, reuse: false, degraded?: false, stolen?: true }
 *   { acquired: false, lockPath, existingLock, reuse: true }   // healthy instance exists
 *   { acquired: false, lockPath: null, reuse: false, degraded: true, reason }  // fallback
 *
 * Graceful degradation: if lockfile creation fails for environmental reasons
 * (permissions, disk full), log a warning and return degraded — the caller may
 * spawn-without-lock. The guard never blocks a service on environmental failure.
 */
export async function acquireLock(service, options = {}, depth = 0) {
  let lockPath;
  try {
    lockPath = await getLockPath(service);
  } catch (err) {
    // Environmental failure (locks-dir mkdir denied, etc.) — degrade, never
    // block the service (library contract). Condition-1 hardening (WP1 gate).
    logWarn(service, `locks directory unavailable (${err.code || err.message}); falling back to spawn-without-lock`);
    return { acquired: false, lockPath: null, lock: null, reuse: false, degraded: true, reason: err.code || 'lock-dir-unavailable' };
  }
  const data = createLockData(service, options);

  // 1. Atomic create-with-content (O_EXCL): fails with EEXIST if lock exists.
  try {
    await fs.writeFile(lockPath, JSON.stringify(data, null, 2), { flag: 'wx', encoding: 'utf8' });
    logInfo(service, `acquired singleton lock at ${lockPath} (PID ${process.pid})`);
    return { acquired: true, lockPath, lock: data, reuse: false, degraded: false };
  } catch (err) {
    if (err.code !== 'EEXIST') {
      // Environmental failure — degrade, never block the service.
      logWarn(service, `lockfile create failed (${err.code}); falling back to spawn-without-lock`);
      return { acquired: false, lockPath: null, lock: null, reuse: false, degraded: true, reason: err.code };
    }
  }

  // 2. Lock exists — read and validate.
  let existing = null;
  let readError = null;
  try {
    existing = await readLockFile(lockPath);
  } catch (err) {
    readError = err;
  }

  if (existing === null && readError === null) {
    // File disappeared between create-fail and read (owner released) — retry.
    if (depth < MAX_ACQUIRE_DEPTH) return acquireLock(service, options, depth + 1);
  }

  if (!existing) {
    // Corrupt/unreadable lockfile — treat as stale and attempt steal.
    logWarn(service, `lockfile unreadable (${readError?.code || 'corrupt'}); attempting stale steal`);
    const stolen = await tryStealLock(lockPath, service, options);
    if (stolen) {
      logInfo(service, `stole stale lock at ${lockPath} (PID ${process.pid})`);
      return { acquired: true, lockPath, lock: stolen, reuse: false, degraded: false, stolen: true };
    }
    if (depth < MAX_ACQUIRE_DEPTH) return acquireLock(service, options, depth + 1);
  }

  // 3. Stale detection: dead PID OR unhealthy port OR heartbeat age exceeded.
  const stale = await isLockStale(lockPath, existing);
  if (stale) {
    const stolen = await tryStealLock(lockPath, service, options);
    if (stolen) {
      logInfo(service, `stole stale lock at ${lockPath} (PID ${process.pid})`);
      return { acquired: true, lockPath, lock: stolen, reuse: false, degraded: false, stolen: true };
    }
    if (depth < MAX_ACQUIRE_DEPTH) return acquireLock(service, options, depth + 1);
  }

  // 4. Healthy existing instance — REUSE.
  // Max-depth exhaustion can leave `existing` null (file vanished repeatedly, or
  // a corrupt lock we could not steal). Never dereference null here: degrade per
  // the library contract rather than throwing uncaught. Condition-1 hardening
  // (WP1 gate).
  if (!existing) {
    logWarn(service, `lock state undetermined after ${depth + 1} attempts; falling back to spawn-without-lock`);
    return { acquired: false, lockPath: null, lock: null, reuse: false, degraded: true, reason: 'lock-state-undetermined' };
  }
  logInfo(service, `singleton lock held by PID ${existing.pid}; reusing existing instance`);
  return { acquired: false, lockPath, existingLock: existing, reuse: true, degraded: false };
}

/**
 * Stale if: process not alive, OR (network service AND port unhealthy),
 * OR age since lastHeartbeat (fallback startTime) > staleThresholdMs.
 */
export async function isLockStale(lockPath, lock) {
  if (!lock) return true;

  if (Number.isInteger(lock.pid) && lock.pid > 0) {
    const alive = await isProcessAlive(lock.pid);
    if (!alive) return true;
  }

  if (lock.port) {
    const probe = await probePort(lock.port, lock.healthEndpoint || undefined);
    if (!probe.healthy) return true;
  }

  const threshold = Number.isFinite(lock.staleThresholdMs) ? lock.staleThresholdMs : STALE_THRESHOLD_MS;
  const ref = lock.lastHeartbeat || lock.startTime;
  if (ref) {
    const age = Date.now() - new Date(ref).getTime();
    if (Number.isFinite(age) && age > threshold) return true;
  }

  return false;
}

/** Write temp file + atomic rename over the existing lockfile. */
async function tryStealLock(lockPath, service, options) {
  const data = createLockData(service, options);
  const tmpPath = `${lockPath}.${process.pid}.${Date.now()}.steal.tmp`;
  try {
    await fs.writeFile(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    // Environmental failure writing the steal temp (permissions, disk full) —
    // cannot steal; return null so the caller degrades instead of throwing
    // uncaught. Condition-1 hardening (WP1 gate).
    logWarn(service, `steal temp write failed (${err.code || err.message}); lock not stolen`);
    return null;
  }
  try {
    await fs.rename(tmpPath, lockPath);
  } catch {
    await fs.rm(tmpPath, { force: true }).catch(() => {});
    return null; // lost the race — another process holds it now
  }
  return data;
}

// ---------------------------------------------------------------------------
// Heartbeat and release
// ---------------------------------------------------------------------------

/**
 * Update lastHeartbeat every 10s. Stops automatically if the lock is no longer
 * owned by this process (stolen/deleted) — a zombie heartbeat must never
 * re-write a lock a new owner holds. Returns a stop() function.
 */
export function startHeartbeat(lockPath, options = {}) {
  const intervalMs = options.intervalMs ?? HEARTBEAT_INTERVAL_MS;
  let stopped = false;
  let warned = false;

  const tick = async () => {
    if (stopped) return;
    try {
      const lock = await readLockFile(lockPath);
      if (lock && lock.pid === process.pid) {
        await updateHeartbeat(lockPath);
      } else {
        if (!warned) {
          warned = true;
          logWarn(lock?.service || 'service', `lock at ${lockPath} no longer owned by PID ${process.pid}; heartbeat stopped`);
        }
        stop();
      }
    } catch {
      if (stopped) return;
      try {
        await fs.access(lockPath);
        // File exists but unreadable/corrupt — contested; stop with warning.
        if (!warned) {
          warned = true;
          logWarn('service', `lock at ${lockPath} unreadable; heartbeat stopped`);
        }
        stop();
      } catch {
        // File missing — cleanly released/stolen; stop quietly (never re-create).
        stop();
      }
    }
  };

  const interval = setInterval(tick, intervalMs);
  interval.unref?.();
  tick(); // immediate first beat so the lock is never born stale

  function stop() {
    if (stopped) return;
    stopped = true;
    clearInterval(interval);
  }

  return stop;
}

/**
 * Register lock release on clean shutdown (SIGTERM, SIGINT, stdin-end).
 * Only releases if this process still owns the lock. Returns an unregister fn.
 * Servers with their own shutdown() should call deleteLockfile() there instead.
 */
export function registerLockRelease(lockPath) {
  let released = false;
  const release = async () => {
    if (released) return;
    released = true;
    try {
      const lock = await readLockFile(lockPath);
      if (lock && lock.pid === process.pid) {
        await deleteLockfile(lockPath);
        logInfo(lock.service || 'service', `released singleton lock at ${lockPath}`);
      }
    } catch {
      // Best-effort release; crash-path stale locks self-heal on next acquire.
    }
  };
  process.once('SIGTERM', release);
  process.once('SIGINT', release);
  process.stdin?.once('end', release);
  return () => {
    process.removeListener('SIGTERM', release);
    process.removeListener('SIGINT', release);
    process.stdin?.removeListener('end', release);
  };
}

// ---------------------------------------------------------------------------
// Port probe logic (design § Probe Logic for Network Services)
// ---------------------------------------------------------------------------

/** TCP connect with timeout. Resolves boolean. */
export function tcpConnect(host, port, timeoutMs = TCP_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let settled = false;
    const done = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

/**
 * Probe a network service: TCP connect (500ms) -> protocol health check
 * (fetch, 2s timeout) -> result. stdio services (no port) are healthy by
 * definition and rely on lockfile + PID only.
 */
export async function probePort(port, healthEndpoint) {
  if (!port) return { healthy: true, reason: 'stdio-service' };

  const tcpOk = await tcpConnect('127.0.0.1', port, TCP_TIMEOUT_MS);
  if (!tcpOk) return { healthy: false, reason: 'tcp-connect-failed' };

  if (healthEndpoint) {
    try {
      const res = await fetch(healthEndpoint, {
        method: 'GET',
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      if (res.ok) return { healthy: true, reason: 'http-ok' };
      return { healthy: false, reason: `http-${res.status}` };
    } catch {
      return { healthy: false, reason: 'http-fetch-failed' };
    }
  }

  return { healthy: true, reason: 'tcp-ok' };
}

/**
 * Headless Edge debug-port probe (default 9233). Reusable only when a
 * Chromium-family signature is verified on /json/version; a confirmed
 * non-browser responder on the port is NOT reusable (do not reuse a
 * stranger's process) — including a responder that returns a non-ok
 * HTTP status (fail closed, F-4). If the version fetch fails after TCP
 * success, TCP success is sufficient for reuse (design), reported as
 * 'tcp-only'.
 */
export async function probeEdgeDebugPort(port = 9233) {
  const endpoint = `http://127.0.0.1:${port}/json/version`;
  const tcpOk = await tcpConnect('127.0.0.1', port, TCP_TIMEOUT_MS);
  if (!tcpOk) return { reusable: false, reason: 'tcp-connect-failed', version: null };

  try {
    const res = await fetch(endpoint, { signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
    if (!res.ok) return { reusable: false, reason: 'http-status-not-ok', version: null };
    const version = await res.json();
    const browser = String(version?.Browser || '');
    if (/edge|edg|chromium|chrome/i.test(browser)) {
      return { reusable: true, reason: 'signature-verified', version };
    }
    if (version?.webSocketDebuggerUrl) {
      return { reusable: true, reason: 'chromium-family-cdp', version };
    }
    return { reusable: false, reason: 'not-browser-signature', version };
  } catch {
    return { reusable: true, reason: 'tcp-only', version: null };
  }
}

/** Wait until a TCP port stops accepting connections, or timeout. */
export async function waitForPortFree(port, timeoutMs = PORT_RELEASE_WAIT_MS) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await tcpConnect('127.0.0.1', port, 300);
    if (!ok) return true;
    await delay(250);
  }
  return false;
}

// ---------------------------------------------------------------------------
// PID utilities
// ---------------------------------------------------------------------------

/**
 * Windows-safe PID liveness: process.kill(pid, 0) first (POSIX semantics),
 * tasklist fallback on win32 per design (process.kill(pid,0) semantics differ
 * on Windows). EPERM means the process exists but is not ours — alive.
 */
export async function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (err && err.code === 'EPERM') return true;
  }
  if (process.platform === 'win32') {
    try {
      const { stdout } = await execFileAsync('tasklist', ['/FI', `PID eq ${pid}`, '/NH']);
      return new RegExp(`^\\s*\\S+\\s+${pid}\\s`, 'm').test(stdout);
    } catch {
      return false;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Browser-reuse probe (founder directive 2026-09-13: no browser-per-search)
// ---------------------------------------------------------------------------

/** Read-only tasklist scan for running browser main processes. Never touches them. */
async function findRunningProcesses(processNames) {
  if (process.platform !== 'win32') return [];
  const found = [];
  for (const name of processNames) {
    try {
      const { stdout } = await execFileAsync('tasklist', ['/FI', `IMAGENAME eq ${name}`, '/NH']);
      for (const line of stdout.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || /^INFO:/i.test(trimmed)) continue;
        const m = trimmed.match(/^(\S+)\s+(\d+)/);
        if (m) found.push({ name: m[1], pid: Number(m[2]) });
      }
    } catch {
      // ignore per-name failures
    }
  }
  return found;
}

/**
 * Probe for an existing healthy browser instance before an automation spawner
 * opens a new window/tab. Returns reusable:true when an existing instance or
 * profile lock is found (spawner must NOT open another window), reusable:false
 * when it is safe to spawn. READ-ONLY: detects, never kills or controls
 * browser instances (Decision 4 boundary).
 *
 * options: { processNames?, profilePath?, debugPort? }
 */
export async function probeBrowserReuse(options = {}) {
  const {
    processNames = ['msedge.exe', 'chrome.exe'],
    profilePath = null,
    debugPort = null,
  } = options;

  if (debugPort) {
    const edge = await probeEdgeDebugPort(debugPort);
    if (edge.reusable) {
      return { reusable: true, reason: `debug-port-${debugPort}`, details: edge };
    }
  }

  const running = await findRunningProcesses(processNames);
  if (running.length > 0) {
    return { reusable: true, reason: 'existing-browser-process', details: { processes: running } };
  }

  if (profilePath) {
    const lockFile = join(profilePath, 'SingletonLock');
    try {
      await fs.access(lockFile);
      return { reusable: true, reason: 'profile-lock-present', details: { lockFile } };
    } catch {
      // no profile lock — proceed to must-spawn
    }
  }

  return {
    reusable: false,
    reason: 'no-existing-instance',
    details: { checked: { processNames, profilePath, debugPort } },
  };
}

// ---------------------------------------------------------------------------
// PID manifest helpers (checkpoint-file integration, LRN-2026-120)
// ---------------------------------------------------------------------------

/**
 * Normalize a manifest entry to the canonical PID manifest format:
 * { pid, service, command, startTime, lockfilePath, port, expectedExit, reapVerified }
 */
export function normalizeManifestEntry(entry) {
  return {
    pid: entry.pid,
    service: entry.service ?? 'unknown',
    command: entry.command ?? '',
    startTime: entry.startTime ?? new Date().toISOString(),
    lockfilePath: entry.lockfilePath ?? null,
    port: entry.port ?? null,
    expectedExit: entry.expectedExit ?? 'sigterm',
    reapVerified: false,
  };
}

/** Append a PID manifest entry to the checkpoint file's childPids array. */
export async function appendChildPid(checkpointPath, entry) {
  let checkpoint = {};
  try {
    checkpoint = JSON.parse(await fs.readFile(checkpointPath, 'utf8'));
  } catch {
    // no valid checkpoint yet — create structure
  }
  const childPids = Array.isArray(checkpoint.childPids) ? checkpoint.childPids : [];
  childPids.push(normalizeManifestEntry(entry));
  checkpoint.childPids = childPids;
  await fs.writeFile(checkpointPath, JSON.stringify(checkpoint, null, 2), 'utf8');
  return childPids.length;
}

/**
 * Reap children recorded in a checkpoint: SIGTERM -> wait 3s -> SIGKILL,
 * verify port release for network services, mark reapVerified, persist the
 * updated checkpoint. Returns { allReaped, details }.
 */
export async function reapChildProcesses(checkpointPath) {
  let checkpoint = null;
  try {
    checkpoint = JSON.parse(await fs.readFile(checkpointPath, 'utf8'));
  } catch (err) {
    return {
      allReaped: false,
      details: [{ error: `checkpoint-unreadable: ${err.code || err.message}` }],
    };
  }

  const childPids = Array.isArray(checkpoint.childPids) ? checkpoint.childPids : [];
  const results = [];

  for (const child of childPids) {
    if (child.reapVerified) {
      results.push({ pid: child.pid, reaped: true, alreadyVerified: true });
      continue;
    }

    let terminated = false;
    const alive = await isProcessAlive(child.pid);
    if (alive) {
      try {
        process.kill(child.pid, 'SIGTERM');
      } catch {
        // already gone
      }
      await delay(REAP_WAIT_MS);
      let stillAlive = await isProcessAlive(child.pid);
      if (stillAlive) {
        try {
          process.kill(child.pid, 'SIGKILL');
        } catch {
          // already gone
        }
        await delay(500);
        stillAlive = await isProcessAlive(child.pid);
      }
      terminated = !stillAlive;
    }

    let portReleased = null;
    if (child.port) {
      portReleased = await waitForPortFree(child.port, PORT_RELEASE_WAIT_MS);
    }

    results.push({ pid: child.pid, reaped: true, terminated, portReleased });
    child.reapVerified = true;
  }

  await fs
    .writeFile(checkpointPath, JSON.stringify({ ...checkpoint, childPids }, null, 2), 'utf8')
    .catch((err) => {
      results.push({ error: `checkpoint-write-failed: ${err.code || err.message}` });
    });

  return { allReaped: results.every((r) => r.reaped !== false), details: results };
}

export {
  LOCK_DIR,
  STALE_THRESHOLD_MS,
  HEARTBEAT_INTERVAL_MS,
  LOCKFILE_VERSION,
};