// Minimal sovereign-wallet sidecar fixture for the Rust supervisor tests.
// Speaks the framed protocol (openagents.omega.sovereign-wallet.v1) over
// stdio. The reported network comes from `--network=<name>` (per-instance
// arg, so parallel tests never race on env) with FIXTURE_NETWORK as a
// fallback. `--no-wallet-height` makes the OMEGA-DELTA-0303 wallet-height
// seam fail closed with TIP_HEIGHT_UNAVAILABLE (test-only knob). `--over-settle`
// simulates an over-settled payment (actual > prepared-for total) so the
// OMEGA-DELTA-0300 loss-rule auto-kill is observable from Rust tests.
// Updated-with-citation (0303): the honest field renames (nodeNetwork/
// nodeState/nodeConnected/nodeUnavailableReason) mirror the rail surfaces.

import fs from "node:fs";

const argNetwork = process.argv.find((arg) => arg.startsWith("--network="));
const FIXTURE_NETWORK = argNetwork ? argNetwork.slice("--network=".length) : (process.env.FIXTURE_NETWORK ?? "signet");
// OMEGA-DELTA-0303 test knob: --no-wallet-height disables the fixture's
// height answer so the typed TIP_HEIGHT_UNAVAILABLE path is observable from
// Rust tests (the C3-2 slice wires the real tip API under 0304).
const FIXTURE_NO_WALLET_HEIGHT = process.argv.includes("--no-wallet-height");
// OMEGA-DELTA-0300: over-settlement simulation for the loss rule.
const FIXTURE_OVER_SETTLE = process.argv.includes("--over-settle");

const schema = "openagents.omega.sovereign-wallet.v1";
let generation = 1;
let initializedGeneration = null;

// WP-10 (QA condition 2): the fixture writes its own PID under the data root
// so the crash->respawn test can kill the sidecar process BY PID and assert
// the supervisor respawns it (kill-by-PID discipline — never taskkill /IM).
const dataRoot = process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT ?? "";
if (dataRoot) {
  const runDir = `${dataRoot}/run`;
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(`${runDir}/fixture.pid`, String(process.pid));
}

// WP-6: deterministic L-402 proof pair (sha256(preimage) == paymentHash).
const FIXTURE_PREIMAGE = "b".repeat(64);
const FIXTURE_PAYMENT_HASH = "4ca14526b2751b640d549ce7caf8ac39438592211a0ec370064d57666a682ad6";
// OMEGA-DELTA-0300: the invoice amount is what the spend ceiling counts —
// 10u = 1,000 sats sits exactly AT the first-phase ceiling so the mandate-
// gated L-402 tests stay under it (the 100u = 10,000-sat shape would
// legitimately trip the ceiling).
const FIXTURE_INVOICE = "lntbs10u1pfixture";

function respond(id, ok, result, error) {
  process.stdout.write(
    JSON.stringify({ schema, kind: "response", id, generation, ok, result, error }) + "\n",
  );
}

const readers = [];
process.stdin.setEncoding("utf8");
let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    if (line.trim().length === 0) continue;
    let frame;
    try {
      frame = JSON.parse(line);
    } catch {
      respond("0", false, undefined, { code: "INVALID_ARGS", message: "bad json", details: "", retryable: false, remediation: "" });
      continue;
    }
    if (frame.kind !== "request") continue;
    generation = frame.generation ?? generation;
    const id = frame.id;
    // Generation fencing: only the initialize handshake may set the generation.
    if (frame.method !== "initialize" && initializedGeneration !== null && frame.generation !== initializedGeneration) {
      respond(id, false, undefined, {
        code: "STALE_GENERATION",
        message: `generation ${frame.generation} does not match active generation ${initializedGeneration}`,
        details: "",
        retryable: false,
        remediation: "",
      });
      continue;
    }
    switch (frame.method) {
      case "initialize":
        initializedGeneration = generation;
        respond(id, true, {
          schema,
          protocolVersion: 1,
          serviceVersion: "fixture",
          generation,
          capabilities: [
            "status",
            "balance",
            "make-invoice",
            "pay-invoice",
            "mcp-identity-map-get",
            "mcp-identity-map-set",
            "shutdown",
          ],
          dataRoot: process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT ?? "",
          network: FIXTURE_NETWORK,
          nodeNetwork: FIXTURE_NETWORK,
          nodeState: "connected",
          httpSurface: { bound: false, port: 0 },
        });
        break;
      case "health":
        respond(id, true, {
          ok: true,
          status: "ready",
          generation,
          dataRoot: process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT ?? "",
          walletState: "ready",
          nodeConnected: true,
          network: FIXTURE_NETWORK,
          note: "",
        });
        break;
      case "status":
        respond(id, true, {
          schema,
          protocolVersion: 1,
          serviceVersion: "fixture",
          network: FIXTURE_NETWORK,
          nodeConnected: true,
          nodeUnavailableReason: "",
          walletState: "ready",
          vaultState: "absent",
          l402GatewayState: "absent",
          httpSurface: { bound: false, port: 0 },
          dataRoot: process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT ?? "",
        });
        break;
      case "balance":
        respond(id, true, {
          confirmedSat: "12345",
          pendingInSat: "0",
          pendingOutSat: "0",
          creditAvailableSat: "0",
          creditReservedSat: "0",
        });
        break;
      case "wallet-height":
        if (FIXTURE_NO_WALLET_HEIGHT) {
          respond(id, false, undefined, {
            code: "TIP_HEIGHT_UNAVAILABLE",
            message: "the public tip API is not wired in this slice (OMEGA-DELTA-0303/0304; fixture knob)",
            details: "the C3-2 slice wires the tip API; until then the escrow gate fails closed",
            retryable: true,
            remediation: "the C3-2 slice wires the tip API; no height is ever guessed",
          });
          break;
        }
        respond(id, true, { blockHeight: 250000 });
        break;
      case "make-invoice":
        respond(id, true, {
          invoice: FIXTURE_INVOICE,
          paymentHash: FIXTURE_PAYMENT_HASH,
          amountSat: frame.params?.amtSat ?? 1,
          memo: frame.params?.memo ?? "",
          hrp: "lntbs",
        });
        break;
      case "pay-invoice": {
        // OMEGA-DELTA-0286: the real sidecar's guard is network-parameterized
        // — lnbc is refused on signet/regtest, accepted on mainnet, and a
        // mismatched HRP is refused on a mainnet-configured wallet; the
        // fixture mirrors the configured network (FIXTURE_NETWORK).
        const invoice = frame.params?.invoice ?? "";
        const isMainnetInvoice = invoice.startsWith("lnbc") && !invoice.startsWith("lnbcrt");
        if (isMainnetInvoice && FIXTURE_NETWORK !== "mainnet") {
          respond(id, false, undefined, {
            code: "MAINNET_REFUSED",
            message: "mainnet BOLT11 invoices are never paid or minted",
            details: "",
            retryable: false,
            remediation: "",
          });
          break;
        }
        if (!isMainnetInvoice && FIXTURE_NETWORK === "mainnet") {
          respond(id, false, undefined, {
            code: "INVALID_ARGS",
            message: `invoice prefix ${invoice.slice(0, 5)} does not match the configured network mainnet`,
            details: "",
            retryable: false,
            remediation: "",
          });
          break;
        }
        // OMEGA-DELTA-0300 (loss rule): the fixture reports the prepared-for
        // total outflow so the Rust-side expected-vs-actual comparison is
        // observable; --over-settle simulates over-settlement.
        respond(id, true, {
          paymentHash: FIXTURE_PAYMENT_HASH,
          status: "ENTRY_STATUS_PENDING",
          activityId: "fixture-activity-1",
          actualAmountSat: FIXTURE_OVER_SETTLE ? "999" : "1",
          expectedFeeSat: "0",
          feeKnown: true,
          expectedTotalOutflowSat: "1",
          totalOutflowKnown: true,
          warning: "",
          preimage: FIXTURE_PREIMAGE,
        });
        break;
      }
      case "mcp-identity-map-get":
        respond(id, true, { entries: {} });
        break;
      case "mcp-identity-map-set":
        respond(id, true, {
          serverId: frame.params?.serverId ?? "",
          principalPubkey: frame.params?.principalPubkey ?? null,
          updated: true,
        });
        break;
      case "shutdown":
        respond(id, true, { stopping: true });
        setTimeout(() => process.exit(0), 50);
        break;
      default:
        respond(id, false, undefined, { code: "METHOD_NOT_FOUND", message: "unknown method", details: "", retryable: false, remediation: "" });
    }
  }
});