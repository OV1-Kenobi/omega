//! Framed loopback protocol for `openagents.omega.sovereign-wallet.v1`.
//!
//! Adopted from the verified omega_effectd frame discipline (one JSON object
//! per newline, bounded frames, generation fencing) with the wavecli-style
//! error envelope (`code`/`message`/`details`/`retryable`/`remediation`).
//! Design: 02-wp1-system-design.md §2.

export const PROTOCOL_SCHEMA = "openagents.omega.sovereign-wallet.v1";
export const PROTOCOL_VERSION = 1;
export const SERVICE_VERSION = "0.1.0";
/** Newline-framed JSON frames must stay under this byte budget (design §2.1). */
export const MAX_FRAME_BYTES = 64 * 1024;

/** Stable machine-readable error codes (wavecli-style; design §2.3). */
export type ErrorCode =
  | "INVALID_ARGS"
  | "WALLET_NOT_CREATED"
  | "WALLET_LOCKED"
  | "WALLET_SYNCING"
  | "NOT_FOUND"
  | "METHOD_NOT_FOUND"
  | "CONFIRMATION_REQUIRED"
  | "INSUFFICIENT_BALANCE"
  | "INVOICE_EXPIRED"
  | "CANCELED"
  | "DEADLINE_EXCEEDED"
  | "ABORTED"
  | "WAIT_TIMEOUT"
  | "MAINNET_REFUSED"
  | "PAYMENT_HASH_MISMATCH"
  | "CREDENTIAL_CONSUMED"
  | "STALE_GENERATION"
  | "ALREADY_RUNNING"
  | "EXPORT_ALREADY_CONSUMED"
  | "WAVED_BINARY_MISSING"
  | "WAVED_WALLET_API_UNAVAILABLE"
  | "INCOMPATIBLE_VERSION"
  | "INTERNAL";

export interface ErrorEnvelope {
  code: ErrorCode;
  message: string;
  details: string;
  retryable: boolean;
  remediation: string;
}

export interface RequestFrame {
  schema: string;
  kind: "request";
  id: string;
  generation: number;
  method: string;
  params?: unknown;
}

export interface ResponseFrame {
  schema: string;
  kind: "response";
  id: string;
  generation: number;
  ok: boolean;
  result?: unknown;
  error?: ErrorEnvelope;
}

export interface EventFrame {
  schema: string;
  kind: "event";
  id: "0";
  generation: number;
  method: string;
  params: unknown;
}

export type Frame = RequestFrame | ResponseFrame | EventFrame;

export function errorEnvelope(
  code: ErrorCode,
  message: string,
  opts: { details?: string; retryable?: boolean; remediation?: string } = {},
): ErrorEnvelope {
  return {
    code,
    message,
    details: opts.details ?? "",
    retryable: opts.retryable ?? false,
    remediation: opts.remediation ?? "",
  };
}

/** Methods that move funds must never be blindly retried after a timeout (wavecli rule). */
export function isBlindRetryUnsafe(code: ErrorCode): boolean {
  return (
    code === "DEADLINE_EXCEEDED" ||
    code === "ABORTED" ||
    code === "WAIT_TIMEOUT" ||
    code === "CANCELED"
  );
}

export function encodeResponse(frame: ResponseFrame): string {
  return `${JSON.stringify(frame)}\n`;
}

export function encodeEvent(generation: number, method: string, params: unknown): string {
  const frame: EventFrame = {
    schema: PROTOCOL_SCHEMA,
    kind: "event",
    id: "0",
    generation,
    method,
    params,
  };
  return `${JSON.stringify(frame)}\n`;
}