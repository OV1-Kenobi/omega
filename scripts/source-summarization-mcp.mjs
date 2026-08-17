#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PROTOCOL_VERSION = "2025-11-25";
export const SERVER_NAME = "omega-source-summarization";
export const SERVER_VERSION = "0.1.0";
export const MAX_SOURCE_CONTENT_BYTES = 1024 * 1024;
export const DEFAULT_MAX_PASSAGES = 5;
export const MAX_PASSAGES = 20;
export const MAX_PASSAGE_QUOTE_CHARS = 4000;

const SOURCE_SUMMARIZATION_DIR = dirname(fileURLToPath(import.meta.url));
const UNSUPPORTED_SOURCE_EXTENSIONS = new Set([
  ".aac",
  ".avi",
  ".bmp",
  ".doc",
  ".docx",
  ".gif",
  ".jpeg",
  ".jpg",
  ".m4a",
  ".mkv",
  ".mov",
  ".mp3",
  ".mp4",
  ".mpeg",
  ".png",
  ".ppt",
  ".pptx",
  ".pdf",
  ".srt",
  ".wav",
  ".webm",
  ".xls",
  ".xlsx",
]);
const UNSUPPORTED_CONTENT_TYPES = [
  "application/octet-stream",
  "application/pdf",
  "application/msword",
  "application/vnd.",
  "audio/",
  "image/",
  "video/",
];
const GROUNDING_STATUSES = new Set(["grounded", "partially_grounded", "not_in_source"]);

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const LOCAL_WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
};

const MODEL_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    summary: { type: "string", description: "Faithful summary supplied by the calling model." },
    key_points: {
      type: "array",
      description: "Structured key points supplied by the calling model.",
      items: { type: ["string", "object"] },
    },
    answer: { type: "string", description: "Grounded answer supplied by the calling model." },
    grounded_passages: {
      type: "array",
      description: "Passages supplied by the calling model for deterministic validation.",
      items: {
        type: "object",
        properties: {
          digest: { type: "string" },
          content_quote: { type: "string" },
          location: { type: "string" },
        },
        required: ["digest", "content_quote", "location"],
        additionalProperties: false,
      },
    },
    passages: {
      type: "array",
      description: "Alias for grounded_passages in the caller-model seam.",
      items: { type: "object" },
    },
    grounding_status: {
      type: "string",
      enum: ["grounded", "partially_grounded", "not_in_source"],
    },
  },
  additionalProperties: false,
};

export const TOOLS = [
  {
    name: "summarize_source",
    description:
      "Create a signed SourceArtifact from caller-provided Markdown or text for an HTTP(S) URL. " +
      "Use the calling model's explicit summary and key points; this tool never fetches or invents them. " +
      "The content is bounded, digest-checked, and kept local to the caller.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Canonical HTTP(S) source URL." },
        content: { type: "string", description: "Already-fetched Markdown or text; no network fetch occurs here." },
        source_title: { type: "string", description: "Optional source title." },
        content_type: { type: "string", description: "Optional content type from the caller's fetch step." },
        content_digest_override: {
          type: "string",
          description: "Optional claimed SHA-256 digest; it is verified rather than trusted.",
        },
        language: { type: "string", description: "Optional target language code." },
        summary: { type: "string", description: "Explicit caller-model summary output." },
        key_points: {
          type: "array",
          description: "Explicit caller-model structured takeaways.",
          items: { type: ["string", "object"] },
        },
        model_output: MODEL_OUTPUT_SCHEMA,
      },
      required: ["url", "content"],
      additionalProperties: false,
    },
    annotations: { title: "Summarize a source", ...LOCAL_WRITE },
  },
  {
    name: "ask_source",
    description:
      "Answer a question against a SourceArtifact using explicit caller-model output. " +
      "Validate every supplied passage against the artifact digest and source text when available. " +
      "Require the caller to state grounded, partially_grounded, or not_in_source; never invent an answer or citation.",
    inputSchema: {
      type: "object",
      properties: {
        artifact: { type: "object", description: "Signed SourceArtifact to question." },
        question: { type: "string" },
        source_content: { type: "string", description: "Optional source text for citation validation." },
        max_passages: { type: "integer", minimum: 1, maximum: MAX_PASSAGES },
        answer: { type: "string", description: "Explicit caller-model answer." },
        grounded_passages: { type: "array", items: { type: "object" } },
        passages: { type: "array", items: { type: "object" } },
        grounding_status: {
          type: "string",
          enum: ["grounded", "partially_grounded", "not_in_source"],
        },
        model_output: MODEL_OUTPUT_SCHEMA,
      },
      required: ["artifact", "question"],
      additionalProperties: false,
    },
    annotations: { title: "Ask a source", ...READ_ONLY, idempotentHint: false },
  },
  {
    name: "save_source_analysis",
    description:
      "Persist a signed SourceArtifact into the local personal analysis library through Omega's library_cli bridge. " +
      "Use only for local personal storage; shared scope is rejected. This tool never invokes Cargo or writes operator logs.",
    inputSchema: {
      type: "object",
      properties: {
        artifact: { type: "object", description: "Signed SourceArtifact to mirror locally." },
        record_title: { type: "string", description: "Optional library title." },
        scope: { type: "string", enum: ["personal", "shared"] },
        folder: { type: "string" },
        tags: { type: "array", items: { type: "string" } },
        category: { type: "string" },
      },
      required: ["artifact"],
      additionalProperties: false,
    },
    annotations: { title: "Save a source analysis", ...LOCAL_WRITE },
  },
  {
    name: "get_saved_analysis",
    description:
      "Retrieve one complete signed personal SourceArtifact from the local library bridge by record id. " +
      "Recompute its artifact digest and verify it with the injected publisher signer before returning it.",
    inputSchema: {
      type: "object",
      properties: { record_id: { type: "string" } },
      required: ["record_id"],
      additionalProperties: false,
    },
    annotations: { title: "Get a saved source analysis", ...READ_ONLY },
  },
  {
    name: "list_saved_analyses",
    description:
      "List metadata-only personal saved analyses through the local library search bridge. " +
      "The response excludes artifact bodies and source content; an optional keyword narrows the personal list.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 100 },
        offset: { type: "integer", minimum: 0 },
      },
      additionalProperties: false,
    },
    annotations: { title: "List saved source analyses", ...READ_ONLY },
  },
  {
    name: "export_source_analysis",
    description:
      "Return a saved SourceArtifact as founder-approved minimal Markdown or plain text containing its summary, " +
      "key points, conversation, and integrity references. PDF, DOCX, and SRT exports are not implemented.",
    inputSchema: {
      type: "object",
      properties: {
        record_id: { type: "string", description: "Saved-analysis record id." },
        artifact: { type: "object", description: "Signed artifact already held by the caller." },
        format: { type: "string", enum: ["markdown", "text"] },
      },
      additionalProperties: false,
    },
    annotations: { title: "Export a source analysis", ...READ_ONLY },
  },
];

const TOOL_NAMES = new Set(TOOLS.map((tool) => tool.name));

export class ToolFailure extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "ToolFailure";
    this.code = code;
    this.details = details;
  }
}

class LibraryBridgeFailure extends Error {
  constructor(operation, unavailable = false) {
    super("library bridge operation failed");
    this.name = "LibraryBridgeFailure";
    this.operation = operation;
    this.unavailable = unavailable;
  }
}

function fail(code, message, details = {}) {
  throw new ToolFailure(code, message, details);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireObject(value, field = "arguments") {
  if (!isObject(value)) {
    fail("invalid_input", "Input must be a JSON object.", { field });
  }
  return value;
}

function optionalString(value, field, { allowEmpty = false } = {}) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || (!allowEmpty && value.trim() === "")) {
    fail("invalid_input", "The input field must be a non-empty string.", { field });
  }
  return value;
}

function requiredString(value, field) {
  const result = optionalString(value, field);
  if (result === undefined) {
    fail("invalid_input", "A required input field is missing.", { field });
  }
  return result;
}

function integerOption(value, field, fallback, minimum, maximum) {
  const result = value === undefined ? fallback : value;
  if (!Number.isInteger(result) || result < minimum || result > maximum) {
    fail("invalid_input", "The input field must be a bounded integer.", {
      field,
      minimum,
      maximum,
    });
  }
  return result;
}

export function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_input", "Canonical data contains a non-finite number.");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
  if (isObject(value)) {
    const entries = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  fail("invalid_input", "Canonical data contains an unsupported value.");
}

export function sha256Hex(value) {
  return createHash("sha256").update(typeof value === "string" ? Buffer.from(value) : value).digest("hex");
}

export function uuidV7(nowMilliseconds = Date.now()) {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Math.max(0, Math.floor(nowMilliseconds)));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isValidDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}

function isIpLiteral(hostname) {
  const lower = hostname.toLowerCase();
  if (lower.includes(":")) return true;
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(lower)) return false;
  return lower.split(".").every((part) => Number(part) <= 255);
}

function isUnsupportedSourceUrl(parsedUrl) {
  const hostname = parsedUrl.hostname.toLowerCase();
  if (hostname === "youtube.com" || hostname.endsWith(".youtube.com") || hostname === "youtu.be") return true;
  const path = parsedUrl.pathname.toLowerCase();
  for (const extension of UNSUPPORTED_SOURCE_EXTENSIONS) {
    if (path.endsWith(extension)) return true;
  }
  return false;
}

function validateSourceUrl(rawUrl) {
  const url = requiredString(rawUrl, "url").trim();
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail("invalid_url", "The source URL is not a valid URL.", { field: "url" });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    fail("unsupported_scheme", "Only HTTP(S) source URLs are supported.", { field: "url" });
  }
  if (!parsed.hostname || isIpLiteral(parsed.hostname)) {
    fail("unsupported_source_type", "IP-literal source hosts are outside the V1 source boundary.");
  }
  if (isUnsupportedSourceUrl(parsed)) {
    fail("unsupported_source_type", "This source type is outside V1; transcript or binary extraction is deferred.");
  }
  return url;
}

function validateContentType(value) {
  const contentType = optionalString(value, "content_type")?.toLowerCase();
  if (!contentType) return;
  if (UNSUPPORTED_CONTENT_TYPES.some((unsupported) => contentType.startsWith(unsupported))) {
    fail("unsupported_source_type", "Binary, audio, video, and document extraction is outside V1.");
  }
}

function validateContent(value) {
  if (typeof value !== "string") {
    fail("invalid_input", "The source content must be a string.", { field: "content" });
  }
  if (value.trim() === "") {
    fail("no_textual_content", "The source contains no textual content.");
  }
  if (value.includes("\u0000")) {
    fail("unsupported_source_type", "The supplied source content is not textual.");
  }
  const sizeBytes = Buffer.byteLength(value, "utf8");
  if (sizeBytes > MAX_SOURCE_CONTENT_BYTES) {
    fail("too_large", "The source content exceeds the named V1 content limit.", {
      limit_bytes: MAX_SOURCE_CONTENT_BYTES,
      size_bytes: sizeBytes,
    });
  }
  return { value, sizeBytes };
}

function resolveSummaryModelOutput(args) {
  const supplied = args.model_output === undefined ? args : args.model_output;
  if (!isObject(supplied)) {
    fail("model_output_required", "The calling model must supply summary and key points explicitly.", {
      missing: ["summary", "key_points"],
    });
  }
  const summary = supplied.summary;
  const keyPoints = supplied.key_points;
  const missing = [];
  if (summary === undefined) missing.push("summary");
  if (keyPoints === undefined) missing.push("key_points");
  if (missing.length > 0) {
    fail("model_output_required", "The calling model must supply summary and key points explicitly.", { missing });
  }
  if (typeof summary !== "string" || summary.trim() === "") {
    fail("invalid_model_output", "The model summary must be a non-empty string.", { field: "summary" });
  }
  return {
    summary: summary.trim(),
    key_points: normalizeKeyPoints(keyPoints),
  };
}

function normalizeKeyPoints(value) {
  if (!Array.isArray(value)) {
    fail("invalid_model_output", "The model key points must be an array.", { field: "key_points" });
  }
  return value.map((point, index) => {
    if (typeof point === "string") {
      if (point.trim() === "") {
        fail("invalid_model_output", "A model key point must not be empty.", { field: `key_points[${index}]` });
      }
      return point.trim();
    }
    if (!isObject(point) || Object.keys(point).length === 0) {
      fail("invalid_model_output", "Each model key point must be text or a non-empty object.", {
        field: `key_points[${index}]`,
      });
    }
    return JSON.parse(JSON.stringify(point));
  });
}

function keyPointText(point) {
  if (typeof point === "string") return point;
  if (typeof point.text === "string") return point.text;
  if (typeof point.point === "string") return point.point;
  return canonicalize(point);
}

function deriveRecordTitle(summary) {
  const compact = summary.replace(/\s+/g, " ").trim();
  return compact.length <= 120 ? compact : `${compact.slice(0, 117)}...`;
}

function isoTime(clock) {
  const value = clock();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) fail("internal_error", "The local clock returned an invalid time.");
  return date.toISOString();
}

function artifactDigestPayload(artifact) {
  return {
    ...artifact,
    integrity: {
      content_digest_sha256: artifact.content_digest,
    },
  };
}

export function computeArtifactDigest(artifact) {
  return sha256Hex(canonicalize(artifactDigestPayload(artifact)));
}

function signerUnavailable(productionMode) {
  fail(
    "publisher_signer_unavailable",
    productionMode
      ? "No configured local publisher signer is available in production mode."
      : "No local publisher signer is configured; signing is fail-closed.",
  );
}

async function signArtifact(artifact, signer, clock, productionMode) {
  if (!signer || typeof signer.sign !== "function") signerUnavailable(productionMode);
  const artifactDigest = computeArtifactDigest(artifact);
  let signed;
  try {
    signed = await signer.sign({
      artifact_digest: artifactDigest,
      content_digest: artifact.content_digest,
    });
  } catch {
    fail("publisher_signer_unavailable", "The configured publisher signer could not sign the artifact.");
  }
  const signature = typeof signed === "string" ? signed : signed?.publisher_signature ?? signed?.signature;
  const publisherNpub =
    (typeof signed === "object" && signed !== null ? signed.publisher_npub ?? signed.npub : undefined) ??
    signer.publisher_npub ??
    signer.publisherNpub;
  if (typeof signature !== "string" || signature.trim() === "" || typeof publisherNpub !== "string" || publisherNpub.trim() === "") {
    fail("publisher_signer_unavailable", "The configured publisher signer returned incomplete identity data.");
  }
  return {
    ...artifact,
    integrity: {
      content_digest_sha256: artifact.content_digest,
      artifact_digest_sha256: artifactDigest,
      publisher_signature: signature,
      publisher_npub: publisherNpub,
      signed_at: isoTime(clock),
    },
  };
}

function assertArtifactShape(value) {
  if (!isObject(value)) fail("invalid_artifact", "The artifact must be a JSON object.", { field: "artifact" });
  const requiredFields = [
    "id",
    "kind",
    "created_at",
    "source_url",
    "source_title",
    "content_digest",
    "summary",
    "key_points",
    "conversation",
    "integrity",
    "record",
  ];
  for (const field of requiredFields) {
    if (!(field in value)) fail("invalid_artifact", "The artifact is missing a required field.", { field });
  }
  if (value.kind !== "source-analysis") fail("invalid_artifact", "The artifact kind is unsupported.", { field: "kind" });
  for (const field of ["id", "created_at", "source_url", "source_title", "summary"]) {
    if (typeof value[field] !== "string" || value[field].trim() === "") {
      fail("invalid_artifact", "The artifact has an invalid text field.", { field });
    }
  }
  if (!isValidDigest(value.content_digest)) {
    fail("invalid_artifact", "The artifact content digest is not a SHA-256 hex digest.", {
      field: "content_digest",
    });
  }
  normalizeKeyPoints(value.key_points);
  if (!Array.isArray(value.conversation)) fail("invalid_artifact", "The artifact conversation must be an array.", { field: "conversation" });
  if (!isObject(value.integrity)) fail("invalid_artifact", "The artifact integrity block is invalid.", { field: "integrity" });
  if (value.integrity.content_digest_sha256 !== value.content_digest) {
    fail("integrity_mismatch", "The artifact content digest and integrity digest differ.");
  }
  if (!isValidDigest(value.integrity.artifact_digest_sha256)) {
    fail("invalid_artifact", "The artifact digest is not a SHA-256 hex digest.", {
      field: "integrity.artifact_digest_sha256",
    });
  }
  if (typeof value.integrity.publisher_signature !== "string" || value.integrity.publisher_signature.trim() === "") {
    fail("invalid_artifact", "The artifact publisher signature is missing.", { field: "integrity.publisher_signature" });
  }
  if (typeof value.integrity.publisher_npub !== "string" || value.integrity.publisher_npub.trim() === "") {
    fail("invalid_artifact", "The artifact publisher identity is missing.", { field: "integrity.publisher_npub" });
  }
  if (typeof value.integrity.signed_at !== "string" || Number.isNaN(Date.parse(value.integrity.signed_at))) {
    fail("invalid_artifact", "The artifact signed_at value is invalid.", { field: "integrity.signed_at" });
  }
  if (!isObject(value.record)) fail("invalid_artifact", "The artifact record linkage is invalid.", { field: "record" });
  if (value.record.record_id !== null && typeof value.record.record_id !== "string") {
    fail("invalid_artifact", "The artifact record id linkage is invalid.", { field: "record.record_id" });
  }
  if (typeof value.record.record_title !== "string" || value.record.record_title.trim() === "") {
    fail("invalid_artifact", "The artifact record title linkage is invalid.", { field: "record.record_title" });
  }
  if (value.source_content !== undefined) {
    if (typeof value.source_content !== "string") fail("invalid_artifact", "The artifact source content is invalid.", { field: "source_content" });
    const sourceSize = Buffer.byteLength(value.source_content, "utf8");
    if (sourceSize > MAX_SOURCE_CONTENT_BYTES) {
      fail("too_large", "The artifact source content exceeds the named V1 content limit.", {
        limit_bytes: MAX_SOURCE_CONTENT_BYTES,
        size_bytes: sourceSize,
      });
    }
    if (sha256Hex(value.source_content) !== value.content_digest) {
      fail("integrity_mismatch", "The artifact source content does not match its content digest.");
    }
  }
  return value;
}

function normalizeWhitespace(value) {
  return value.replace(/\s+/g, " ").trim();
}

function citationCorpus(artifact, sourceContent) {
  if (sourceContent !== undefined && sourceContent !== null) return sourceContent;
  return [artifact.summary, ...artifact.key_points.map(keyPointText)].join("\n");
}

function validatePassages(rawPassages, artifact, sourceContent, maxPassages) {
  if (!Array.isArray(rawPassages)) {
    fail("invalid_model_output", "Grounded passages must be an array.", { field: "grounded_passages" });
  }
  if (rawPassages.length > maxPassages) {
    fail("citation_invalid", "The model supplied more passages than requested.", { max_passages: maxPassages });
  }
  const corpus = citationCorpus(artifact, sourceContent);
  const normalizedCorpus = normalizeWhitespace(corpus);
  const seen = new Set();
  return rawPassages.map((passage, index) => {
    if (!isObject(passage)) fail("citation_invalid", "Each grounded passage must be an object.", { field: `grounded_passages[${index}]` });
    const digest = passage.digest ?? passage.content_digest;
    const quote = passage.content_quote;
    const location = passage.location;
    if (digest !== artifact.content_digest) {
      fail("citation_invalid", "A grounded passage is not bound to the artifact content digest.", {
        field: `grounded_passages[${index}].digest`,
      });
    }
    if (typeof quote !== "string" || quote.trim() === "" || quote.length > MAX_PASSAGE_QUOTE_CHARS) {
      fail("citation_invalid", "A grounded passage quote is empty or exceeds the bounded quote limit.", {
        field: `grounded_passages[${index}].content_quote`,
      });
    }
    if (typeof location !== "string" || location.trim() === "") {
      fail("citation_invalid", "A grounded passage location is required.", {
        field: `grounded_passages[${index}].location`,
      });
    }
    const normalizedQuote = normalizeWhitespace(quote);
    const found = corpus.includes(quote) || normalizedCorpus.includes(normalizedQuote);
    if (!found) {
      fail("citation_invalid", "A grounded passage quote could not be resolved in the artifact source.", {
        field: `grounded_passages[${index}]`,
      });
    }
    const key = `${digest}\u0000${quote}\u0000${location}`;
    if (seen.has(key)) fail("citation_invalid", "Duplicate grounded passages are not allowed.");
    seen.add(key);
    return { digest, content_quote: quote, location };
  });
}

function validateArtifactConversation(artifact, sourceContent) {
  for (let index = 0; index < artifact.conversation.length; index += 1) {
    const entry = artifact.conversation[index];
    if (!isObject(entry)) fail("invalid_artifact", "An artifact conversation entry is invalid.", { field: `conversation[${index}]` });
    if (typeof entry.question !== "string" || entry.question.trim() === "") {
      fail("invalid_artifact", "An artifact conversation question is invalid.", { field: `conversation[${index}].question` });
    }
    if (entry.answer !== null && typeof entry.answer !== "string") {
      fail("invalid_artifact", "An artifact conversation answer is invalid.", { field: `conversation[${index}].answer` });
    }
    if (!GROUNDING_STATUSES.has(entry.grounding_status)) {
      fail("invalid_artifact", "An artifact conversation grounding status is invalid.", {
        field: `conversation[${index}].grounding_status`,
      });
    }
    const passages = validatePassages(entry.grounded_passages, artifact, sourceContent, MAX_PASSAGES);
    if (entry.grounding_status === "not_in_source" && passages.length !== 0) {
      fail("invalid_artifact", "A not_in_source conversation entry cannot carry passages.");
    }
    if (entry.grounding_status !== "not_in_source" && passages.length === 0) {
      fail("invalid_artifact", "A grounded conversation entry must carry a passage.");
    }
  }
}

async function verifyArtifact(artifact, signer, productionMode) {
  assertArtifactShape(artifact);
  const sourceContent = artifact.source_content;
  validateArtifactConversation(artifact, sourceContent);
  const computedDigest = computeArtifactDigest(artifact);
  if (computedDigest !== artifact.integrity.artifact_digest_sha256) {
    fail("integrity_mismatch", "The artifact digest does not match its canonical envelope.");
  }
  if (!signer || typeof signer.verify !== "function") signerUnavailable(productionMode);
  let verified = false;
  try {
    verified = await signer.verify({
      artifact_digest: computedDigest,
      content_digest: artifact.content_digest,
      publisher_signature: artifact.integrity.publisher_signature,
      publisher_npub: artifact.integrity.publisher_npub,
    });
  } catch {
    fail("publisher_signer_unavailable", "The configured publisher signer could not verify the artifact.");
  }
  if (verified !== true) fail("signature_invalid", "The artifact publisher signature could not be verified.");
  return artifact;
}

function resolveAskModelOutput(args) {
  const supplied = args.model_output === undefined ? args : args.model_output;
  if (!isObject(supplied)) {
    fail("model_output_required", "The calling model must supply answer, passages, and grounding status explicitly.", {
      missing: ["answer", "grounded_passages", "grounding_status"],
    });
  }
  const missing = [];
  const status = supplied.grounding_status;
  const passages = supplied.grounded_passages ?? supplied.passages;
  if (status === undefined) missing.push("grounding_status");
  if (passages === undefined) missing.push("grounded_passages");
  if (missing.length > 0) {
    fail("model_output_required", "The calling model must supply answer, passages, and grounding status explicitly.", {
      missing,
    });
  }
  if (typeof status !== "string" || !GROUNDING_STATUSES.has(status)) {
    fail("invalid_model_output", "The model grounding status is unsupported.", { field: "grounding_status" });
  }
  const answer = supplied.answer;
  if (status !== "not_in_source" && (typeof answer !== "string" || answer.trim() === "")) {
    fail("model_output_required", "A grounded model answer is required for this grounding status.", { missing: ["answer"] });
  }
  if (answer !== undefined && answer !== null && typeof answer !== "string") {
    fail("invalid_model_output", "The model answer must be a string when supplied.", { field: "answer" });
  }
  return {
    answer: typeof answer === "string" ? answer.trim() : null,
    grounded_passages: passages,
    grounding_status: status,
  };
}

function selectAskSourceContent(args, artifact) {
  const candidate = args.source_content ?? args.content ?? artifact.source_content;
  if (candidate === undefined) return undefined;
  if (typeof candidate !== "string") fail("invalid_input", "The optional source content must be a string.", { field: "source_content" });
  if (sha256Hex(candidate) !== artifact.content_digest) {
    fail("integrity_mismatch", "The supplied source content does not match the artifact content digest.");
  }
  return candidate;
}

function validateScope(value) {
  if (value === undefined || value === null) return "personal";
  if (value !== "personal" && value !== "shared") {
    fail("invalid_input", "The library scope must be personal or shared.", { field: "scope" });
  }
  return value;
}

function normalizeRecordTitle(value, artifact) {
  const title = value === undefined ? artifact.record.record_title : optionalString(value, "record_title");
  if (!title) fail("invalid_input", "A record title is required.", { field: "record_title" });
  return title.trim();
}

function normalizeRecordOptions(args) {
  const folder = optionalString(args.folder, "folder");
  const category = optionalString(args.category, "category");
  if (args.tags !== undefined && (!Array.isArray(args.tags) || args.tags.some((tag) => typeof tag !== "string" || tag.trim() === ""))) {
    fail("invalid_input", "Tags must be a list of non-empty strings.", { field: "tags" });
  }
  return {
    folder,
    category,
    tags: args.tags?.map((tag) => tag.trim()) ?? [],
  };
}

function bridgeRecordId(value) {
  if (typeof value === "string") return value;
  if (isObject(value) && typeof value.record_id === "string") return value.record_id;
  fail("library_bridge_error", "The local library bridge returned no record id.");
}

function recordFromBridgeValue(value) {
  if (isObject(value) && isObject(value.record)) return value.record;
  return value;
}

function metadataFromBridge(value) {
  if (!isObject(value)) return null;
  if (value.scope !== "personal") return null;
  return {
    record_id: value.record_id,
    record_kind: value.record_kind,
    title: value.title,
    scope: value.scope,
    saved_at: value.saved_at,
    folder: value.folder ?? null,
    tags: Array.isArray(value.tags) ? value.tags : [],
    category: value.category ?? null,
    snippet: value.snippet ?? null,
  };
}

function toolJson(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function toolText(value, structuredContent) {
  const result = { content: [{ type: "text", text: value }] };
  if (structuredContent !== undefined) result.structuredContent = structuredContent;
  return result;
}

function errorResult(error) {
  if (error instanceof ToolFailure) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: { code: error.code, message: error.message, ...error.details } }, null, 2),
        },
      ],
      isError: true,
    };
  }
  if (error instanceof LibraryBridgeFailure) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: {
                code: error.unavailable ? "library_bridge_unavailable" : "library_bridge_error",
                message: "The local library bridge did not complete the requested operation.",
              },
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { error: { code: "internal_error", message: "The local source-analysis operation failed." } },
          null,
          2,
        ),
      },
    ],
    isError: true,
  };
}

function defaultLibraryCliPath() {
  const executable = process.platform === "win32" ? "library_cli.exe" : "library_cli";
  return resolve(SOURCE_SUMMARIZATION_DIR, "..", "target", "debug", executable);
}

function invokeLibraryCli(command, args, input, operation) {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = execFile(
        command,
        args,
        { windowsHide: true, maxBuffer: Math.max(4 * 1024 * 1024, MAX_SOURCE_CONTENT_BYTES * 4) },
        (error, stdout) => {
          if (error) {
            rejectPromise(new LibraryBridgeFailure(operation, error.code === "ENOENT"));
            return;
          }
          try {
            const parsed = JSON.parse(stdout.trim());
            resolvePromise(parsed);
          } catch {
            rejectPromise(new LibraryBridgeFailure(operation));
          }
        },
      );
    } catch {
      rejectPromise(new LibraryBridgeFailure(operation, true));
      return;
    }
    child.stdin.end(input === undefined ? "" : JSON.stringify(input));
  });
}

export function createLibraryBridge({ command, dbPath } = {}) {
  const bridgeCommand = command ?? process.env.OMEGA_LIBRARY_CLI ?? defaultLibraryCliPath();
  const configuredDbPath = dbPath ?? process.env.OMEGA_LIBRARY_DB;
  const baseArgs = configuredDbPath ? ["--db", configuredDbPath] : [];
  return {
    async save(record) {
      const response = await invokeLibraryCli(bridgeCommand, [...baseArgs, "save"], record, "save");
      if (!response?.ok || typeof response.record_id !== "string") throw new LibraryBridgeFailure("save");
      return response.record_id;
    },
    async get(recordId) {
      const response = await invokeLibraryCli(bridgeCommand, [...baseArgs, "get", recordId], "", "get");
      if (response?.ok === false && response.error === "not_found") return null;
      if (!response?.ok || !response.record) throw new LibraryBridgeFailure("get");
      return response.record;
    },
    async search(request) {
      const response = await invokeLibraryCli(bridgeCommand, [...baseArgs, "search"], request, "search");
      if (!response?.ok || !Array.isArray(response.results)) throw new LibraryBridgeFailure("search");
      return response.results;
    },
  };
}

function renderKeyPoint(point, markdown) {
  const text = keyPointText(point).replace(/\r?\n/g, markdown ? "\n  " : "\n");
  return markdown ? `- ${text}` : `- ${text}`;
}

function renderMarkdown(artifact) {
  const title = artifact.record.record_title || artifact.source_title;
  const lines = [
    `# ${title.replace(/\r?\n/g, " ")}`,
    "",
    "## Summary",
    artifact.summary,
    "",
    "## Key points",
    ...(artifact.key_points.length > 0 ? artifact.key_points.map((point) => renderKeyPoint(point, true)) : ["_No key points recorded._"]),
    "",
    "## Conversation",
  ];
  if (artifact.conversation.length === 0) {
    lines.push("_No conversation recorded._");
  } else {
    for (const entry of artifact.conversation) {
      lines.push("", `### Question`, entry.question, "", `### Answer`, entry.answer ?? "_No model answer supplied._", "", `**Grounding:** ${entry.grounding_status}`);
      if (entry.grounded_passages.length > 0) {
        lines.push("", "#### Grounded passages");
        for (const passage of entry.grounded_passages) {
          lines.push(`- ${passage.location}: \"${passage.content_quote.replace(/\r?\n/g, " ")}\"`);
        }
      }
    }
  }
  lines.push(
    "",
    "## Integrity",
    `- Content SHA-256: \`${artifact.integrity.content_digest_sha256}\``,
    `- Artifact SHA-256: \`${artifact.integrity.artifact_digest_sha256}\``,
    `- Publisher signature: \`${artifact.integrity.publisher_signature}\``,
    `- Publisher npub: \`${artifact.integrity.publisher_npub}\``,
    `- Signed at: ${artifact.integrity.signed_at}`,
  );
  return lines.join("\n");
}

function renderText(artifact) {
  const title = artifact.record.record_title || artifact.source_title;
  const lines = [
    title.replace(/\r?\n/g, " "),
    "",
    "SUMMARY",
    artifact.summary,
    "",
    "KEY POINTS",
    ...(artifact.key_points.length > 0 ? artifact.key_points.map((point) => renderKeyPoint(point, false)) : ["- No key points recorded."]),
    "",
    "CONVERSATION",
  ];
  if (artifact.conversation.length === 0) {
    lines.push("No conversation recorded.");
  } else {
    for (const entry of artifact.conversation) {
      lines.push("", "QUESTION", entry.question, "", "ANSWER", entry.answer ?? "No model answer supplied.", "", `GROUNDING: ${entry.grounding_status}`);
      for (const passage of entry.grounded_passages) {
        lines.push(`PASSAGE (${passage.location}): ${passage.content_quote.replace(/\r?\n/g, " ")}`);
      }
    }
  }
  lines.push(
    "",
    "INTEGRITY",
    `Content SHA-256: ${artifact.integrity.content_digest_sha256}`,
    `Artifact SHA-256: ${artifact.integrity.artifact_digest_sha256}`,
    `Publisher signature: ${artifact.integrity.publisher_signature}`,
    `Publisher npub: ${artifact.integrity.publisher_npub}`,
    `Signed at: ${artifact.integrity.signed_at}`,
  );
  return lines.join("\n");
}

export function createServer({
  bridge,
  signer,
  clock = () => new Date(),
  idFactory = () => uuidV7(),
  productionMode = process.env.NODE_ENV === "production",
} = {}) {
  const libraryBridge = bridge ?? createLibraryBridge();

  async function summarizeSource(rawArgs) {
    const args = requireObject(rawArgs);
    const sourceUrl = validateSourceUrl(args.url);
    validateContentType(args.content_type);
    const content = validateContent(args.content).value;
    const contentDigest = sha256Hex(content);
    if (args.content_digest_override !== undefined) {
      const override = requiredString(args.content_digest_override, "content_digest_override").toLowerCase();
      if (!isValidDigest(override)) {
        fail("invalid_digest", "The content digest override must be a SHA-256 hex digest.", {
          field: "content_digest_override",
        });
      }
      if (override !== contentDigest) {
        fail("integrity_mismatch", "The supplied content digest does not match the source content.", {
          expected_digest: contentDigest,
        });
      }
    }
    const modelOutput = resolveSummaryModelOutput(args);
    const sourceTitle = optionalString(args.source_title, "source_title") ?? "Untitled source";
    const language = optionalString(args.language, "language");
    const artifact = {
      id: idFactory(),
      kind: "source-analysis",
      created_at: isoTime(clock),
      source_url: sourceUrl,
      source_title: sourceTitle.trim(),
      content_digest: contentDigest,
      source_content: content,
      ...(language ? { language: language.trim() } : {}),
      summary: modelOutput.summary,
      key_points: modelOutput.key_points,
      conversation: [],
      integrity: { content_digest_sha256: contentDigest },
      record: {
        record_id: null,
        record_title: deriveRecordTitle(modelOutput.summary),
      },
    };
    return signArtifact(artifact, signer, clock, productionMode);
  }

  async function askSource(rawArgs) {
    const args = requireObject(rawArgs);
    const artifact = assertArtifactShape(args.artifact);
    const question = requiredString(args.question, "question").trim();
    const maxPassages = integerOption(args.max_passages, "max_passages", DEFAULT_MAX_PASSAGES, 1, MAX_PASSAGES);
    const modelOutput = resolveAskModelOutput(args);
    const sourceContent = selectAskSourceContent(args, artifact);
    const passages = validatePassages(modelOutput.grounded_passages, artifact, sourceContent, maxPassages);
    if (modelOutput.grounding_status === "not_in_source" && passages.length !== 0) {
      fail("citation_invalid", "A not_in_source result must not contain citations.");
    }
    if (modelOutput.grounding_status !== "not_in_source" && passages.length === 0) {
      fail("citation_invalid", "A grounded result must contain at least one validated passage.");
    }
    await verifyArtifact(artifact, signer, productionMode);
    const updatedArtifact = {
      ...artifact,
      conversation: [
        ...artifact.conversation,
        {
          question,
          answer: modelOutput.answer,
          grounded_passages: passages,
          grounding_status: modelOutput.grounding_status,
        },
      ],
    };
    const signedArtifact = await signArtifact(updatedArtifact, signer, clock, productionMode);
    return {
      answer: modelOutput.answer,
      grounded_passages: passages,
      grounding_status: modelOutput.grounding_status,
      artifact: signedArtifact,
    };
  }

  async function saveSourceAnalysis(rawArgs) {
    const args = requireObject(rawArgs);
    const artifact = assertArtifactShape(args.artifact);
    const scope = validateScope(args.scope ?? args.artifact.scope);
    if (scope === "shared") fail("shared_scope_not_allowed", "Shared library records are not writable in V1.");
    const recordTitle = normalizeRecordTitle(args.record_title, artifact);
    const recordOptions = normalizeRecordOptions(args);
    await verifyArtifact(artifact, signer, productionMode);
    const recordId = idFactory();
    const linkedArtifact = {
      ...artifact,
      record: { record_id: recordId, record_title: recordTitle },
    };
    const signedArtifact = await signArtifact(linkedArtifact, signer, clock, productionMode);
    const savedAt = isoTime(clock);
    const record = {
      record_kind: "saved-analysis",
      record_id: recordId,
      record_title: recordTitle,
      saved_at: savedAt,
      scope: "personal",
      artifact_id: signedArtifact.id,
      artifact_digest: signedArtifact.integrity.artifact_digest_sha256,
      publisher_signature: signedArtifact.integrity.publisher_signature,
      publisher_npub: signedArtifact.integrity.publisher_npub,
      folder: recordOptions.folder ?? null,
      tags: recordOptions.tags,
      category: recordOptions.category ?? null,
      search_text: [recordTitle, ...signedArtifact.key_points.map(keyPointText)].join(" "),
      artifact_body: canonicalize(signedArtifact),
    };
    let bridgeResult;
    try {
      bridgeResult = await libraryBridge.save(record);
    } catch (error) {
      if (error instanceof LibraryBridgeFailure) throw error;
      throw new LibraryBridgeFailure("save");
    }
    const savedRecordId = bridgeRecordId(bridgeResult);
    if (savedRecordId !== recordId) fail("library_bridge_error", "The local library bridge returned a mismatched record id.");
    return {
      ok: true,
      record_id: savedRecordId,
      artifact_id: signedArtifact.id,
      content_digest: signedArtifact.content_digest,
      artifact_digest: signedArtifact.integrity.artifact_digest_sha256,
      artifact: signedArtifact,
    };
  }

  async function loadSavedArtifact(recordId) {
    const normalizedId = requiredString(recordId, "record_id");
    let stored;
    try {
      stored = await libraryBridge.get(normalizedId);
    } catch (error) {
      if (error instanceof LibraryBridgeFailure) throw error;
      throw new LibraryBridgeFailure("get");
    }
    const record = recordFromBridgeValue(stored);
    if (!record) fail("analysis_not_found", "The requested saved analysis was not found.");
    if (record.record_kind !== "saved-analysis" || typeof record.artifact_body !== "string") {
      fail("library_bridge_error", "The local library bridge returned a non-analysis record.");
    }
    let artifact;
    try {
      artifact = JSON.parse(record.artifact_body);
    } catch {
      fail("integrity_mismatch", "The saved analysis artifact body is not valid JSON.");
    }
    assertArtifactShape(artifact);
    if (record.record_id !== undefined && record.record_id !== normalizedId) {
      fail("integrity_mismatch", "The saved analysis record id does not match the requested id.");
    }
    if (record.artifact_digest !== undefined && record.artifact_digest !== artifact.integrity.artifact_digest_sha256) {
      fail("integrity_mismatch", "The saved analysis record digest does not match its artifact body.");
    }
    if (record.publisher_signature !== undefined && record.publisher_signature !== artifact.integrity.publisher_signature) {
      fail("integrity_mismatch", "The saved analysis record signature does not match its artifact body.");
    }
    await verifyArtifact(artifact, signer, productionMode);
    return artifact;
  }

  async function getSavedAnalysis(rawArgs) {
    const args = requireObject(rawArgs);
    return loadSavedArtifact(args.record_id);
  }

  async function listSavedAnalyses(rawArgs) {
    const args = requireObject(rawArgs ?? {});
    const query = optionalString(args.query, "query");
    const limit = integerOption(args.limit, "limit", 50, 1, 100);
    const offset = integerOption(args.offset, "offset", 0, 0, Number.MAX_SAFE_INTEGER);
    let results;
    try {
      results = await libraryBridge.search({
        query: query ?? null,
        filters: { record_kind: "saved-analysis", scope: "personal" },
        limit,
        offset,
      });
    } catch (error) {
      if (error instanceof LibraryBridgeFailure) throw error;
      throw new LibraryBridgeFailure("search");
    }
    const rawResults = Array.isArray(results) ? results : results?.results;
    if (!Array.isArray(rawResults)) throw new LibraryBridgeFailure("search");
    const analyses = rawResults.map(metadataFromBridge).filter(Boolean);
    return { count: analyses.length, analyses };
  }

  async function exportSourceAnalysis(rawArgs) {
    const args = requireObject(rawArgs);
    const format = args.format ?? "markdown";
    if (format !== "markdown" && format !== "text") {
      fail("unsupported_export_format", "Only minimal Markdown and text exports are supported in Chunk B.", {
        field: "format",
      });
    }
    if (args.artifact !== undefined && args.record_id !== undefined) {
      fail("invalid_input", "Provide a record id or an artifact, not both.");
    }
    const artifact = args.artifact !== undefined ? assertArtifactShape(args.artifact) : await loadSavedArtifact(args.record_id);
    await verifyArtifact(artifact, signer, productionMode);
    const content = format === "markdown" ? renderMarkdown(artifact) : renderText(artifact);
    return toolText(content, { format, artifact_id: artifact.id, artifact_digest: artifact.integrity.artifact_digest_sha256 });
  }

  const handlers = {
    summarize_source: summarizeSource,
    ask_source: askSource,
    save_source_analysis: saveSourceAnalysis,
    get_saved_analysis: getSavedAnalysis,
    list_saved_analyses: listSavedAnalyses,
    export_source_analysis: exportSourceAnalysis,
  };

  async function callTool(name, args = {}) {
    if (!TOOL_NAMES.has(name)) return errorResult(new ToolFailure("unknown_tool", "The requested tool is not registered."));
    try {
      const result = await handlers[name](args);
      if (result?.content) return result;
      return toolJson(result);
    } catch (error) {
      return errorResult(error);
    }
  }

  return {
    tools: TOOLS,
    callTool,
    async handleRequest(request) {
      if (!isObject(request) || request.jsonrpc !== "2.0" || typeof request.method !== "string") {
        return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid JSON-RPC request." } };
      }
      const hasId = Object.prototype.hasOwnProperty.call(request, "id");
      const id = request.id;
      const respond = (result) => (hasId ? { jsonrpc: "2.0", id, result } : null);
      const respondError = (code, message) => (hasId ? { jsonrpc: "2.0", id, error: { code, message } } : null);
      switch (request.method) {
        case "initialize":
          return respond({
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          });
        case "ping":
          return respond({});
        case "tools/list":
          return respond({ tools: TOOLS });
        case "tools/call": {
          if (!isObject(request.params) || typeof request.params.name !== "string") {
            return respondError(-32602, "Invalid tools/call parameters.");
          }
          const result = await callTool(request.params.name, request.params.arguments ?? {});
          return respond(result);
        }
        default:
          return respondError(-32601, "Method not found.");
      }
    },
  };
}

export async function parseAndHandleLine(server, line) {
  if (line.trim() === "") return null;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error." } };
  }
  try {
    return await server.handleRequest(request);
  } catch {
    return { jsonrpc: "2.0", id: isObject(request) && "id" in request ? request.id : null, error: { code: -32603, message: "Internal error." } };
  }
}

export function runStdio(server = createServer()) {
  const input = createInterface({ input: process.stdin });
  input.on("line", (line) => {
    void parseAndHandleLine(server, line).then((response) => {
      if (response !== null) process.stdout.write(`${JSON.stringify(response)}\n`);
    });
  });
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) runStdio();
