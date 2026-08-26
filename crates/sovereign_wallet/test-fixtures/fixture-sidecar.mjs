// Minimal sovereign-wallet sidecar fixture for the Rust supervisor tests.
// Speaks the framed protocol (openagents.omega.sovereign-wallet.v1) over
// stdio. The reported network comes from `--network=<name>` (per-instance
// arg, so parallel tests never race on env) with FIXTURE_NETWORK as a
// fallback.

const argNetwork = process.argv.find((arg) => arg.startsWith("--network="));
const FIXTURE_NETWORK = argNetwork ? argNetwork.slice("--network=".length) : (process.env.FIXTURE_NETWORK ?? "signet");

const schema = "openagents.omega.sovereign-wallet.v1";
let generation = 1;
let initializedGeneration = null;

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
          capabilities: ["status", "balance"],
          dataRoot: process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT ?? "",
          network: FIXTURE_NETWORK,
          wavedNetwork: FIXTURE_NETWORK,
          wavedState: "connected",
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
          wavedConnected: true,
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
          wavedConnected: true,
          wavedUnavailableReason: "",
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
      case "shutdown":
        respond(id, true, { stopping: true });
        setTimeout(() => process.exit(0), 50);
        break;
      default:
        respond(id, false, undefined, { code: "METHOD_NOT_FOUND", message: "unknown method", details: "", retryable: false, remediation: "" });
    }
  }
});