//! Owner-only Windows ACL posture on the whole sidecar data root (SEC-2026-045).
//!
//! On Windows, POSIX 0600 semantics are advisory; the enforcement surface is
//! ACLs. This module disables inherited ACEs on the data root and every
//! subdirectory/file, removes all non-owner grants, and grants the current
//! user full control. It fails closed: if icacls cannot be applied, the
//! sidecar refuses to start.

import { execFileSync } from "node:child_process";
import { chmodSync, statSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import path from "node:path";

const ICACLS = "icacls.exe";

function isWindows(): boolean {
  return process.platform === "win32";
}

/** Best-effort current-user identity for the icacls grant. */
function currentUserIdentity(): string {
  const username = userInfo().username;
  const domain = process.env.USERDOMAIN ?? process.env.COMPUTERNAME ?? "";
  return domain ? `${domain}\\${username}` : username;
}

function runIcacls(args: string[]): string {
  return execFileSync(ICACLS, args, {
    windowsHide: true,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
}

/** Make `target` owner-only: disable inheritance, remove inherited ACEs, replace all grants with current-user full control. */
export function lockdownPath(target: string): void {
  if (!isWindows()) {
    chmodSync(target, 0o700);
    return;
  }
  const identity = currentUserIdentity();
  const output = runIcacls([target, "/inheritance:r", "/grant:r", `${identity}:(OI)(CI)F`]);
  if (!/successfully processed/i.test(output)) {
    throw new Error(`icacls lockdown failed for ${target}: ${output}`);
  }
}

/** Recursively apply the owner-only posture to a directory tree. */
export function lockdownTree(root: string): void {
  lockdownPath(root);
  if (isWindows()) {
    // The recursive pass grants BOTH an inherit-only propagation ACE
    // `(OI)(CI)(IO)F` AND a direct plain `F` to every node. A bare
    // `(OI)(CI)F` applied to a FILE does not confer file access (OI/CI are
    // container-inheritance flags), which made files created before a
    // RE-lockdown (the supervisor restart path re-runs this on the same data
    // root) undeletable — `EPERM` on the sidecar's stale-lock reclamation.
    // Verified empirically: existing files, new files, and nested directories
    // all remain writable/deletable by the owner after this pass.
    const output = runIcacls([
      root,
      "/T",
      "/grant:r",
      `${currentUserIdentity()}:(OI)(CI)(IO)F`,
      "/grant:r",
      `${currentUserIdentity()}:F`,
    ]);
    if (!/successfully processed/i.test(output)) {
      throw new Error(`icacls tree lockdown failed for ${root}: ${output}`);
    }
  }
}

/** Apply the owner-only posture to a single file (used for atomic-write temp files). */
export function lockdownFile(target: string): void {
  if (!isWindows()) {
    chmodSync(target, 0o600);
    return;
  }
  const output = runIcacls([target, "/inheritance:r", "/grant:r", `${currentUserIdentity()}:F`]);
  if (!/successfully processed/i.test(output)) {
    throw new Error(`icacls file lockdown failed for ${target}: ${output}`);
  }
}

/** Human-readable current ACL state (for QA evidence / status reporting). */
export function describeAcl(target: string): string {
  if (!isWindows()) {
    return `posix ${statSync(target).mode.toString(8)}`;
  }
  return runIcacls([target]).trim();
}

export function homeDataRootDefault(): string {
  return path.join(homedir(), ".omega-sovereign-wallet");
}

export { isWindows };