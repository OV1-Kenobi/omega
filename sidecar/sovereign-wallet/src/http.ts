//! Loopback HTTP surface (design §2.5) with SEC-2026-053 hardening:
//! - 127.0.0.1 IPv4-only bind on a dynamically allocated port
//! - per-launch bearer token (32 bytes from the supervisor), constant-time
//!   comparison, never echoed in any response
//! - fail-closed startup: no token -> no HTTP surface (named state)
//! - request body limit (64 KiB, matching the frame bound), connection and
//!   read timeouts, 401 before any projection logic on a wrong token

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createHash } from "node:crypto";

export const HTTP_BODY_LIMIT_BYTES = 64 * 1024;
export const HTTP_READ_TIMEOUT_MS = 30_000;

export interface HttpSurfaceState {
  bound: boolean;
  port: number;
  reason?: string;
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Constant-time comparison over SHA-256 digests (equalizes length). */
export function tokenMatches(expected: string, provided: string | undefined): boolean {
  if (!provided) return false;
  return timingSafeEqual(sha256(expected), sha256(provided));
}

/** Generate a fresh 32-byte loopback token (supervisor does this; test helper here). */
export function generateLoopbackToken(): string {
  return randomBytes(32).toString("hex");
}

export interface LoopbackHttpOptions {
  token: string;
  onStatus: () => unknown;
  onBalance: () => Promise<unknown>;
}

export class LoopbackHttpServer {
  readonly #server: Server;
  readonly #token: string;
  readonly #opts: LoopbackHttpOptions;

  private constructor(server: Server, token: string, opts: LoopbackHttpOptions) {
    this.#server = server;
    this.#token = token;
    this.#opts = opts;
  }

  static async bind(opts: LoopbackHttpOptions): Promise<LoopbackHttpServer> {
    const server = createServer((req, res) => this.#handle(req, res, opts));
    server.requestTimeout = HTTP_READ_TIMEOUT_MS;
    server.headersTimeout = 15_000;
    server.keepAliveTimeout = 5_000;
    server.maxHeadersCount = 64;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      // IPv4-only loopback bind (SEC-2026-053).
      server.listen(0, "127.0.0.1", resolve);
    });
    return new LoopbackHttpServer(server, opts.token, opts);
  }

  static #handle(req: IncomingMessage, res: ServerResponse, opts: LoopbackHttpOptions): void {
    // Auth gate: wrong/missing token is refused 401 before ANY projection logic.
    const provided = req.headers.authorization;
    const token = provided?.startsWith("Bearer ") ? provided.slice("Bearer ".length) : undefined;
    if (!tokenMatches(opts.token, token)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "unauthorized" } }));
      return;
    }

    let body = "";
    let aborted = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
      if (body.length > HTTP_BODY_LIMIT_BYTES) {
        aborted = true;
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "payload_too_large" } }));
        req.destroy();
      }
    });

    const finish = (status: number, payload: unknown): void => {
      if (aborted || res.writableEnded) return;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };

    req.on("end", () => {
      if (aborted) return;
      const method = req.method ?? "GET";
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (method === "GET" && url.pathname === "/v1/status") {
        finish(200, opts.onStatus());
        return;
      }
      if (method === "GET" && url.pathname === "/v1/balance") {
        void opts
          .onBalance()
          .then((balance) => finish(200, { balance }))
          .catch((error: unknown) =>
            finish(500, { error: { code: "internal", message: error instanceof Error ? error.message : "internal" } }),
          );
        return;
      }
      finish(404, { error: { code: "not_found" } });
    });
  }

  port(): number {
    const address = this.#server.address();
    if (address === null || typeof address === "string") {
      throw new Error("loopback HTTP server is not bound");
    }
    return address.port;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.#server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

/** Fail-closed startup check (SEC-2026-053): token absent/malformed -> no HTTP surface. */
export function validateLoopbackToken(token: string | undefined): string | null {
  if (!token) return "OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN is not set; the loopback HTTP surface is disabled";
  if (!/^[0-9a-f]{64}$/.test(token)) return "OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN is not 32 bytes of hex; the loopback HTTP surface is disabled";
  return null;
}