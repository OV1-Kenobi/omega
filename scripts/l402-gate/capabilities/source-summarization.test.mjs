// Offline tests for the source-summarization capability adapter
// (capabilities/source-summarization.mjs). Deterministic, offline: a local
// in-memory credential-store signer (BIP-340) stands in for the remote
// artifact-signer seam; no named pipe, no network, no egress.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createCredentialStoreSigner, createInMemoryStorage, provisionSignerIdentity } from "../signer.mjs";
import {
  CAPABILITY,
  TOOLS,
  VERSION,
  computeArtifactDigest,
  createSourceSummarizationExecutor,
  sha256Hex,
} from "./source-summarization.mjs";

const SCRIPT_PATH = new URL("./source-summarization.mjs", import.meta.url);
const FIXED_CLOCK = () => new Date("2026-08-17T12:00:00.000Z");

async function makeExecutor({ clock = FIXED_CLOCK } = {}) {
  const storage = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage });
  const signer = createCredentialStoreSigner({ storage, clock });
  return { executor: createSourceSummarizationExecutor({ signer, clock }), signer, npub };
}

const SUMMARIZE_ARGS = {
  url: "https://private.example.test/paddock-source",
  content: "PRIVATE_PADDOCK_SOURCE_CONTENT alpha fact.",
  source_title: "PRIVATE_PADDOCK_TITLE",
  summary: "Synthetic paddock summary.",
  key_points: ["Synthetic paddock point."],
};

test("the adapter exposes exactly the public allowlist tool contract", () => {
  assert.deepEqual(
    TOOLS.map((tool) => tool.name),
    ["summarize_source", "ask_source", "export_source_analysis"],
  );
  assert.equal(CAPABILITY, "source-summarization");
  assert.equal(VERSION, "0.1.0");
  for (const tool of TOOLS) {
    assert.ok(tool.inputSchema, `${tool.name} carries an input schema`);
  }
});

test("summarize_source produces a signed artifact from caller-held content only", async () => {
  const { executor, npub } = await makeExecutor();
  const result = await executor.callTool("summarize_source", SUMMARIZE_ARGS);
  assert.equal(result.isError, undefined);
  const artifact = JSON.parse(result.content[0].text);
  assert.equal(artifact.kind, "source-analysis");
  assert.equal(artifact.source_url, SUMMARIZE_ARGS.url);
  assert.equal(sha256Hex(SUMMARIZE_ARGS.content), artifact.content_digest);
  assert.equal(artifact.summary, SUMMARIZE_ARGS.summary);
  assert.deepEqual(artifact.key_points, SUMMARIZE_ARGS.key_points);
  assert.equal(artifact.integrity.content_digest_sha256, artifact.content_digest);
  assert.equal(artifact.integrity.artifact_digest_sha256, computeArtifactDigest(artifact));
  assert.match(artifact.integrity.publisher_signature, /^[0-9a-f]{128}$/);
  assert.equal(artifact.integrity.publisher_npub, npub);
  // The adapter never invents output: the model summary is the artifact summary.
  assert.equal(JSON.stringify(result).includes("invented by the model"), false);
});

test("summarize_source refuses foreign digests, non-HTTP URLs, and empty content", async () => {
  const { executor } = await makeExecutor();
  const wrongDigest = await executor.callTool("summarize_source", {
    ...SUMMARIZE_ARGS,
    content_digest_override: "f".repeat(64),
  });
  assert.equal(wrongDigest.isError, true);
  assert.equal(JSON.parse(wrongDigest.content[0].text).error.code, "integrity_mismatch");

  const badScheme = await executor.callTool("summarize_source", { ...SUMMARIZE_ARGS, url: "ftp://example.test/x" });
  assert.equal(JSON.parse(badScheme.content[0].text).error.code, "unsupported_scheme");

  const empty = await executor.callTool("summarize_source", { ...SUMMARIZE_ARGS, content: "   " });
  assert.equal(JSON.parse(empty.content[0].text).error.code, "no_textual_content");

  const missingModel = await executor.callTool("summarize_source", {
    url: SUMMARIZE_ARGS.url,
    content: SUMMARIZE_ARGS.content,
  });
  assert.equal(JSON.parse(missingModel.content[0].text).error.code, "model_output_required");
});

test("ask_source validates passages and signature; a foreign artifact is refused", async () => {
  const { executor, npub } = await makeExecutor();
  const summary = await executor.callTool("summarize_source", SUMMARIZE_ARGS);
  const artifact = JSON.parse(summary.content[0].text);
  const quote = "alpha fact";
  const ask = await executor.callTool("ask_source", {
    artifact,
    question: "What alpha fact is present?",
    answer: "The alpha fact is present.",
    grounding_status: "grounded",
    grounded_passages: [{ digest: artifact.content_digest, content_quote: quote, location: "private.example.test" }],
  });
  assert.equal(ask.isError, undefined);
  const body = JSON.parse(ask.content[0].text);
  assert.equal(body.answer, "The alpha fact is present.");
  assert.equal(body.grounding_status, "grounded");
  assert.equal(body.artifact.integrity.publisher_npub, npub);
  assert.equal(body.artifact.conversation.length, 1);
  assert.equal(body.artifact.conversation[0].grounded_passages[0].content_quote, quote);

  // An unverifiable passage is refused (citation invalid).
  const badPassage = await executor.callTool("ask_source", {
    artifact,
    question: "Q",
    answer: "A",
    grounding_status: "grounded",
    grounded_passages: [{ digest: artifact.content_digest, content_quote: "not in the source at all", location: "x" }],
  });
  assert.equal(JSON.parse(badPassage.content[0].text).error.code, "citation_invalid");

  // A tampered artifact (foreign signature) is refused by the signer seam.
  const forged = { ...artifact, summary: "FORGED_SUMMARY" };
  const forgedAsk = await executor.callTool("ask_source", {
    artifact: forged,
    question: "Q",
    answer: "A",
    grounding_status: "grounded",
    grounded_passages: [{ digest: forged.content_digest, content_quote: quote, location: "x" }],
  });
  const forgedCode = JSON.parse(forgedAsk.content[0].text).error.code;
  assert.ok(["integrity_mismatch", "signature_invalid"].includes(forgedCode), `got ${forgedCode}`);
});

test("export_source_analysis accepts only caller-held artifacts and never renders source content", async () => {
  const { executor } = await makeExecutor();
  const summary = await executor.callTool("summarize_source", SUMMARIZE_ARGS);
  const artifact = JSON.parse(summary.content[0].text);

  const markdown = await executor.callTool("export_source_analysis", { artifact });
  assert.equal(markdown.isError, undefined);
  assert.equal(markdown.structuredContent.format, "markdown");
  assert.equal(markdown.structuredContent.artifact_id, artifact.id);
  const text = markdown.content[0].text;
  assert.ok(text.includes("## Summary"));
  assert.ok(text.includes(artifact.integrity.artifact_digest_sha256));
  assert.equal(text.includes("PRIVATE_PADDOCK_SOURCE_CONTENT"), false, "source content must never be rendered");

  const plainText = await executor.callTool("export_source_analysis", { artifact, format: "text" });
  assert.equal(plainText.structuredContent.format, "text");

  // record-id export targets the local library — refused (no bridge exists).
  const recordId = await executor.callTool("export_source_analysis", { record_id: "0197f000-0000-7000-8000-00000000dead" });
  assert.equal(JSON.parse(recordId.content[0].text).error.code, "tool_not_available_on_public_transport");

  // Missing artifact: bounded invalid_input.
  const noArtifact = await executor.callTool("export_source_analysis", {});
  assert.equal(JSON.parse(noArtifact.content[0].text).error.code, "invalid_input");
});

test("unknown tools and structural failures are bounded, content-free tool errors", async () => {
  const { executor } = await makeExecutor();
  const unknown = await executor.callTool("not_a_tool", {});
  assert.equal(unknown.isError, true);
  assert.equal(JSON.parse(unknown.content[0].text).error.code, "unknown_tool");
  // A tool error never echoes request content.
  const bad = await executor.callTool("summarize_source", { url: SUMMARIZE_ARGS.url, content: SUMMARIZE_ARGS.content });
  assert.equal(JSON.stringify(bad).includes("PRIVATE_PADDOCK_SOURCE_CONTENT"), false);
});

test("the adapter module has no egress, child-process, or file surface", () => {
  const source = readFileSync(SCRIPT_PATH, "utf8");
  assert.doesNotMatch(source, /node:child_process/);
  assert.doesNotMatch(source, /node:net/);
  assert.doesNotMatch(source, /node:dns/);
  assert.doesNotMatch(source, /node:fs/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /execFile|spawn|execSync/);
  assert.equal(source.includes("createCredentialStoreSigner"), false, "the adapter never opens a key store");
});