import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  MAX_SOURCE_CONTENT_BYTES,
  TOOLS,
  canonicalize,
  computeArtifactDigest,
  createServer,
  parseAndHandleLine,
  sha256Hex,
} from "./source-summarization-mcp.mjs";

const SCRIPT_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "source-summarization-mcp.mjs");
const FIXED_TIME = new Date("2026-08-16T12:00:00.000Z");

function syntheticSigner() {
  const publisherNpub = "npub1syntheticpublisher";
  return {
    publisher_npub: publisherNpub,
    async sign({ artifact_digest }) {
      return { publisher_signature: `synthetic-signature-${artifact_digest}`, publisher_npub: publisherNpub };
    },
    async verify({ artifact_digest, publisher_signature, publisher_npub }) {
      return publisher_npub === publisherNpub && publisher_signature === `synthetic-signature-${artifact_digest}`;
    },
  };
}

function fakeBridge({ failSave = false, failGet = false, failSearch = false } = {}) {
  const records = new Map();
  return {
    records,
    async save(record) {
      if (failSave) throw new Error("synthetic bridge failure");
      records.set(record.record_id, structuredClone(record));
      return record.record_id;
    },
    async get(recordId) {
      if (failGet) throw new Error("synthetic bridge failure");
      return records.get(recordId) ?? null;
    },
    async search() {
      if (failSearch) throw new Error("synthetic bridge failure");
      return [...records.values()].map((record) => ({
        record_id: record.record_id,
        record_kind: record.record_kind,
        title: record.record_title,
        scope: record.scope,
        saved_at: record.saved_at,
        folder: record.folder,
        tags: record.tags,
        category: record.category,
        snippet: record.search_text.slice(0, 40),
      }));
    },
  };
}

function deterministicIdFactory() {
  let counter = 1;
  return () => `0197f000-0000-7000-8000-${String(counter++).padStart(12, "0")}`;
}

function makeServer(overrides = {}) {
  return createServer({
    signer: syntheticSigner(),
    bridge: fakeBridge(),
    clock: () => FIXED_TIME,
    idFactory: deterministicIdFactory(),
    ...overrides,
  });
}

function parseTool(result) {
  return JSON.parse(result.content[0].text);
}

async function summarize(server, overrides = {}) {
  const result = await server.callTool("summarize_source", {
    url: "https://example.test/source",
    content: "Alpha fact.\nBeta fact.",
    source_title: "Synthetic source",
    summary: "Alpha and beta are stated in the source.",
    key_points: ["Alpha fact.", "Beta fact."],
    ...overrides,
  });
  const value = parseTool(result);
  assert.equal(result.isError, undefined);
  return value;
}

test("initialize, ping, tools/list, and tools/call use the MCP protocol", async () => {
  const server = makeServer();
  const initialize = await parseAndHandleLine(
    server,
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } }),
  );
  assert.equal(initialize.result.protocolVersion, "2025-11-25");
  assert.deepEqual(initialize.result.capabilities, { tools: {} });

  const ping = await parseAndHandleLine(server, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }));
  assert.deepEqual(ping.result, {});

  const listed = await parseAndHandleLine(server, JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list" }));
  assert.equal(listed.result.tools.length, 6);

  const called = await parseAndHandleLine(
    server,
    JSON.stringify({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "list_saved_analyses", arguments: {} },
    }),
  );
  assert.equal(called.result.isError, undefined);
  assert.deepEqual(parseTool(called.result), { count: 0, analyses: [] });
});

test("the six tool names, schemas, and MCP annotations are bounded and explicit", () => {
  assert.deepEqual(TOOLS.map((tool) => tool.name), [
    "summarize_source",
    "ask_source",
    "save_source_analysis",
    "get_saved_analysis",
    "list_saved_analyses",
    "export_source_analysis",
  ]);
  for (const tool of TOOLS) {
    assert.match(tool.name, /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
    assert.equal(tool.inputSchema.type, "object");
    assert.equal(typeof tool.annotations.title, "string");
    assert.equal(typeof tool.annotations.readOnlyHint, "boolean");
    assert.equal(typeof tool.annotations.destructiveHint, "boolean");
    assert.equal(typeof tool.annotations.idempotentHint, "boolean");
    assert.equal(typeof tool.annotations.openWorldHint, "boolean");
  }
  assert.deepEqual(TOOLS.find((tool) => tool.name === "summarize_source").inputSchema.required, ["url", "content"]);
});

test("URL, source type, content, digest, and bounded-size validation return honest codes", async () => {
  const server = makeServer();
  const cases = [
    [{ url: "ftp://example.test/source" }, "unsupported_scheme"],
    [{ url: "https://127.0.0.1/source" }, "unsupported_source_type"],
    [{ url: "https://example.test/video.mp4" }, "unsupported_source_type"],
    [{ content_type: "application/pdf" }, "unsupported_source_type"],
    [{ content: "   " }, "no_textual_content"],
    [{ content_digest_override: "0".repeat(64) }, "integrity_mismatch"],
    [{ content_digest_override: "not-a-digest" }, "invalid_digest"],
  ];
  for (const [override, expectedCode] of cases) {
    const result = await server.callTool("summarize_source", {
      url: "https://example.test/source",
      content: "Alpha fact.",
      summary: "Alpha fact.",
      key_points: ["Alpha fact."],
      ...override,
    });
    assert.equal(parseTool(result).error.code, expectedCode);
  }

  const tooLarge = await server.callTool("summarize_source", {
    url: "https://example.test/source",
    content: "a".repeat(MAX_SOURCE_CONTENT_BYTES + 1),
    summary: "Too large.",
    key_points: ["Too large."],
  });
  assert.equal(parseTool(tooLarge).error.code, "too_large");
});

test("the server never fabricates summary or key-point output", async () => {
  const server = makeServer();
  const result = await server.callTool("summarize_source", {
    url: "https://example.test/source",
    content: "Alpha fact.",
  });
  const error = parseTool(result).error;
  assert.equal(error.code, "model_output_required");
  assert.deepEqual(error.missing, ["summary", "key_points"]);
});

test("artifact canonicalization and digest are deterministic", async () => {
  const firstServer = makeServer();
  const secondServer = makeServer();
  const first = await summarize(firstServer);
  const second = await summarize(secondServer);
  assert.equal(canonicalize({ b: 2, a: { d: 4, c: 3 } }), canonicalize({ a: { c: 3, d: 4 }, b: 2 }));
  assert.equal(computeArtifactDigest(first), first.integrity.artifact_digest_sha256);
  assert.equal(computeArtifactDigest(second), second.integrity.artifact_digest_sha256);
  assert.equal(first.integrity.artifact_digest_sha256, second.integrity.artifact_digest_sha256);
  assert.equal(first.content_digest, sha256Hex("Alpha fact.\nBeta fact."));
});

test("ask_source validates grounded passages and preserves not_in_source", async () => {
  const server = makeServer();
  const artifact = await summarize(server);
  const grounded = await server.callTool("ask_source", {
    artifact,
    question: "What is the alpha fact?",
    model_output: {
      answer: "The source states the alpha fact.",
      grounded_passages: [{ digest: artifact.content_digest, content_quote: "Alpha fact.", location: "paragraph 1" }],
      grounding_status: "grounded",
    },
  });
  const groundedValue = parseTool(grounded);
  assert.equal(groundedValue.grounding_status, "grounded");
  assert.equal(groundedValue.artifact.conversation.length, 1);

  const invalidCitation = await server.callTool("ask_source", {
    artifact,
    question: "What is invented?",
    model_output: {
      answer: "The source states an invented fact.",
      grounded_passages: [{ digest: artifact.content_digest, content_quote: "Invented fact.", location: "paragraph 99" }],
      grounding_status: "grounded",
    },
  });
  assert.equal(parseTool(invalidCitation).error.code, "citation_invalid");

  const notInSource = await server.callTool("ask_source", {
    artifact,
    question: "What is the price?",
    model_output: { grounded_passages: [], grounding_status: "not_in_source" },
  });
  const notInSourceValue = parseTool(notInSource);
  assert.equal(notInSourceValue.grounding_status, "not_in_source");
  assert.equal(notInSourceValue.answer, null);
  assert.deepEqual(notInSourceValue.grounded_passages, []);

  const missingModelOutput = await server.callTool("ask_source", { artifact, question: "What is missing?" });
  assert.equal(parseTool(missingModelOutput).error.code, "model_output_required");
});

test("save, get, and list use an injected library bridge and reject shared scope", async () => {
  const bridge = fakeBridge();
  const server = makeServer({ bridge });
  const artifact = await summarize(server);
  const saved = await server.callTool("save_source_analysis", {
    artifact,
    record_title: "Synthetic saved analysis",
    folder: "research",
    tags: ["synthetic", "source"],
    category: "reference",
  });
  const savedValue = parseTool(saved);
  assert.equal(savedValue.ok, true);
  assert.equal(savedValue.record_id, savedValue.artifact.record.record_id);

  const fetched = await server.callTool("get_saved_analysis", { record_id: savedValue.record_id });
  const fetchedValue = parseTool(fetched);
  assert.equal(fetchedValue.record.record_id, savedValue.record_id);
  assert.equal(fetchedValue.integrity.artifact_digest_sha256, savedValue.artifact_digest);
  assert.equal(fetchedValue.source_content, "Alpha fact.\nBeta fact.");

  const listed = await server.callTool("list_saved_analyses", {});
  const listedValue = parseTool(listed);
  assert.equal(listedValue.count, 1);
  assert.equal(listedValue.analyses[0].title, "Synthetic saved analysis");
  assert.equal(Object.hasOwn(listedValue.analyses[0], "artifact_body"), false);
  assert.equal(Object.hasOwn(listedValue.analyses[0], "source_content"), false);

  const shared = await server.callTool("save_source_analysis", { artifact, scope: "shared" });
  assert.equal(parseTool(shared).error.code, "shared_scope_not_allowed");
});

test("library bridge errors are structured and do not expose bridge details", async () => {
  const server = makeServer({ bridge: fakeBridge({ failSave: true }) });
  const artifact = await summarize(server);
  const result = await server.callTool("save_source_analysis", { artifact });
  const error = parseTool(result).error;
  assert.equal(error.code, "library_bridge_error");
  assert.equal(JSON.stringify(error).includes("synthetic bridge failure"), false);
});

test("minimal Markdown and text exports contain analysis and integrity but not source content", async () => {
  const bridge = fakeBridge();
  const server = makeServer({ bridge });
  const artifact = await summarize(server);
  const asked = parseTool(
    await server.callTool("ask_source", {
      artifact,
      question: "What is alpha?",
      model_output: {
        answer: "Alpha is stated.",
        grounded_passages: [{ digest: artifact.content_digest, content_quote: "Alpha fact.", location: "paragraph 1" }],
        grounding_status: "grounded",
      },
    }),
  );
  const saved = parseTool(await server.callTool("save_source_analysis", { artifact: asked.artifact, record_title: "Export fixture" }));
  const markdown = await server.callTool("export_source_analysis", { record_id: saved.record_id, format: "markdown" });
  assert.match(markdown.content[0].text, /## Summary/);
  assert.match(markdown.content[0].text, /Alpha and beta are stated/);
  assert.match(markdown.content[0].text, /What is alpha\?/);
  assert.match(markdown.content[0].text, /Content SHA-256/);
  assert.equal(markdown.content[0].text.includes("Alpha fact.\nBeta fact."), false);

  const text = await server.callTool("export_source_analysis", { artifact: saved.artifact, format: "text" });
  assert.match(text.content[0].text, /SUMMARY/);
  assert.match(text.content[0].text, /INTEGRITY/);
  const unsupported = await server.callTool("export_source_analysis", { artifact: saved.artifact, format: "pdf" });
  assert.equal(parseTool(unsupported).error.code, "unsupported_export_format");
});

test("the default signer fails closed without a fake production signature", async () => {
  const server = createServer({
    bridge: fakeBridge(),
    clock: () => FIXED_TIME,
    idFactory: deterministicIdFactory(),
  });
  const result = await server.callTool("summarize_source", {
    url: "https://example.test/source",
    content: "Alpha fact.",
    summary: "Alpha fact.",
    key_points: ["Alpha fact."],
  });
  assert.equal(parseTool(result).error.code, "publisher_signer_unavailable");
});

test("stdio is newline-delimited JSON-RPC and stderr contains no request content", async () => {
  const requests = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "summarize_source",
        arguments: {
          url: "https://private.example.test/secret-path",
          content: "PRIVATE_SYNTHETIC_SOURCE_CONTENT",
          source_title: "PRIVATE_SYNTHETIC_TITLE",
          summary: "Private synthetic summary.",
          key_points: ["Private synthetic point."],
        },
      },
    },
  ];
  const child = spawn(process.execPath, [SCRIPT_PATH], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  for (const request of requests) child.stdin.write(`${JSON.stringify(request)}\n`);
  child.stdin.end();
  const exitCode = await new Promise((resolveExit, rejectExit) => {
    child.once("error", rejectExit);
    child.once("close", resolveExit);
  });
  assert.equal(exitCode, 0);
  const responses = stdout.trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(responses.length, 2);
  assert.equal(responses[0].result.protocolVersion, "2025-11-25");
  assert.equal(responses[1].result.isError, true);
  assert.equal(stderr, "");
  for (const secret of ["private.example.test", "PRIVATE_SYNTHETIC_SOURCE_CONTENT", "PRIVATE_SYNTHETIC_TITLE"]) {
    assert.equal(stderr.includes(secret), false);
  }
});

test("the source server has no network client or egress call", () => {
  const source = readFileSync(SCRIPT_PATH, "utf8");
  assert.doesNotMatch(source, /from ["']node:(?:http|https|net|dns)(?:["'])/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /new\s+WebSocket\s*\(/);
});
