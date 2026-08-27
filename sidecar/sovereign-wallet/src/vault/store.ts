//! Desktop file-store storage backend for the sovereign wallet vault (WP-4).
//!
//! satnam's vault is OPFS-backed; Node has no `navigator.storage`, so the
//! `StorageBackend` abstraction is adapted to `node:fs` over
//! `<data_root>/sovereign-wallet/vault/`. The cryptographic envelope is
//! identical to satnam — only the persistence layer differs.
//!
//! ## File-permissions posture (SEC-2026-045)
//!
//! Vault files are written with mode `0o600` (owner read/write only) and
//! directories `0o700`, matching the Rust `FileSecretStore` discipline. Writes
//! are atomic: write to a temp file in the same directory, then rename over the
//! destination, so a crash cannot leave a half-written ciphertext that reads as
//! a valid entry. On Windows the POSIX mode is advisory — the real ACL lockdown
//! is applied by `src/acl.ts` (`lockdownTree`) over the whole data root.

import fs from "node:fs/promises";
import path from "node:path";

/** Minimal file-system-like interface (satnam StorageBackend, adapted). */
export interface StorageBackend {
  read(p: string): Promise<Uint8Array | null>;
  write(p: string, data: Uint8Array): Promise<void>;
  delete(p: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
  exists(p: string): Promise<boolean>;
}

/**
 * Desktop file-system backend. Paths are relative to the vault root.
 * Atomic-write-then-rename matches the Rust `AtomicWriteFile` discipline.
 */
export class FileBackend implements StorageBackend {
  readonly #root: string;

  constructor(root: string) {
    this.#root = root;
  }

  /** Resolve a dot-separated path to an absolute path under the vault root. */
  #resolve(p: string): string {
    return path.join(this.#root, ...p.split("/").filter((part) => part !== ""));
  }

  async read(p: string): Promise<Uint8Array | null> {
    try {
      const data = await fs.readFile(this.#resolve(p));
      return new Uint8Array(data);
    } catch {
      return null;
    }
  }

  async write(p: string, data: Uint8Array): Promise<void> {
    const full = this.#resolve(p);
    const dir = path.dirname(full);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    // Atomic write: temp sibling then rename (avoids a torn write being read
    // back as a valid entry, and keeps the same ACL application surface).
    const temp = `${full}.tmp-${process.pid}-${Math.random().toString(36).slice(2)}`;
    // vault-file write (S4: this module is the vault persistence backend; the
    // temp sibling lives in the same vault directory before the atomic rename).
    await fs.writeFile(temp, data, { mode: 0o600 });
    try {
      await fs.rename(temp, full);
    } catch (error) {
      await fs.rm(temp, { force: true }).catch(() => {});
      throw error;
    }
  }

  async delete(p: string): Promise<void> {
    try {
      await fs.rm(this.#resolve(p), { force: true });
    } catch {
      // not found is acceptable for delete
    }
  }

  async list(prefix: string): Promise<string[]> {
    const dir = this.#resolve(prefix);
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      return entries
        .filter((entry) => entry.isFile() || entry.isDirectory())
        .map((entry) => entry.name);
    } catch {
      return [];
    }
  }

  async exists(p: string): Promise<boolean> {
    const data = await this.read(p);
    return data !== null;
  }
}
