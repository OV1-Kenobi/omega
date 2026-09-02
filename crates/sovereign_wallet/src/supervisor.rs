//! Supervise the sovereign wallet sidecar over newline-framed JSON stdio.
//!
//! Modeled on the verified `omega_effectd` supervision pattern
//! (`crates/omega_effectd/src/supervisor.rs`): generation fencing, bounded
//! line reads, request timeouts, redacted stderr forwarding, Drop-kill, and
//! the nautilus hard-bail posture (`nautilus_sidecar` refuses non-testnet;
//! this supervisor refuses anything outside its network grammar at config
//! AND at startup, and tears the child down if the initialize-reported
//! network ever mismatches the configured network — SEC-2026-050). Per
//! OMEGA-DELTA-0286 the grammar includes mainnet, reachable ONLY with the
//! explicit allow-mainnet opt-in set at the process level.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use futures::io::{AsyncBufReadExt as _, BufReader};
use futures::{AsyncWriteExt as _, StreamExt as _};
use rand::RngCore;
use serde_json::{Value, json};
use smol::process::ChildStdin;
use util::ResultExt as _;
use util::process::Child;
use util::redact::redact_command;
use zeroize::Zeroizing;

use crate::protocol::{
    ErrorCode, HealthResult, InitializeResult, PROTOCOL_SCHEMA, PROTOCOL_VERSION, ResponseFrame,
    request_frame,
};
use crate::spend_policy::SpendPolicy;

pub use crate::protocol::MAX_FRAME_BYTES;

// The grace period is consumed by the cfg(unix) branch of `stop()`; the
// Windows branch (effectd pattern) falls through to kill, so the constant is
// unused on Windows builds.
#[cfg_attr(not(unix), allow(dead_code))]
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(2);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const PAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LOOPBACK_TOKEN_BYTES: usize = 32;

/// The sidecar launch command: `node <repo>/sidecar/sovereign-wallet/dist/main.js`.
#[derive(Debug, Clone)]
pub struct SovereignWalletCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SovereignWalletSupervisorOptions {
    pub data_root: PathBuf,
    pub command: SovereignWalletCommand,
    pub network: String,
    /// Initial generation. Each successful restart increments by one.
    pub initial_generation: u64,
    pub request_timeout: Duration,
    pub node_require_minor: Option<(u32, u32)>,
}

pub struct SovereignWalletSupervisor {
    options: SovereignWalletSupervisorOptions,
    generation: AtomicU64,
    next_request_id: AtomicU64,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<smol::process::ChildStdout>>,
    /// Per-launch loopback bearer token (32 random bytes, hex); held only in
    /// supervisor memory, injected via env, zeroized on stop (SEC-2026-053).
    loopback_token: Zeroizing<String>,
    /// Negotiated network from the running child; `None` while stopped.
    negotiated_network: Option<String>,
    /// OMEGA-DELTA-0300: the spend policy (kill switch + per-surface daily
    /// budgets + loss-rule auto-kill) consulted by the client choke point
    /// (crate::client) before any funded flow is forwarded to the sidecar.
    pub(crate) spend_policy: SpendPolicy,
}

impl SovereignWalletSupervisor {
    pub fn new(options: SovereignWalletSupervisorOptions) -> Result<Self> {
        // OMEGA-DELTA-0286: the network grammar gate (nautilus pattern).
        // mainnet is refused at construction UNLESS the explicit allow-mainnet
        // opt-in is set at the process level — the supervisor spawns the
        // sidecar, so the check lives here once.
        if !crate::SUPPORTED_NETWORKS.contains(&options.network.as_str()) {
            bail!(
                "sovereign wallet network {:?} is refused; only signet/regtest/mainnet are \
                 permitted (mainnet requires the allow-mainnet opt-in — OMEGA-DELTA-0286)",
                options.network
            );
        }
        if options.network == "mainnet"
            && std::env::var(crate::ALLOW_MAINNET_ENVIRONMENT_VARIABLE).as_deref() != Ok("1")
        {
            bail!(
                "sovereign wallet network \"mainnet\" requires {}=1 (OMEGA-DELTA-0286)",
                crate::ALLOW_MAINNET_ENVIRONMENT_VARIABLE
            );
        }
        let mut token_bytes = [0u8; MAX_LOOPBACK_TOKEN_BYTES];
        rand::rng().fill_bytes(&mut token_bytes);
        let loopback_token = Zeroizing::new(hex_encode(&token_bytes));
        let generation = options.initial_generation.max(1);
        // OMEGA-DELTA-0300: the spend policy loads the persisted budget state
        // and reads the env-level kill at construction (founder-set). A
        // corrupted budget file is a construction failure (fail-closed).
        let spend_policy = SpendPolicy::new(
            &options.data_root,
            std::env::var(crate::SPEND_KILL_ENVIRONMENT_VARIABLE).as_deref() == Ok("1"),
        )
        .context("load the spend policy state (OMEGA-DELTA-0300)")?;
        Ok(Self {
            options,
            generation: AtomicU64::new(generation),
            next_request_id: AtomicU64::new(1),
            child: None,
            stdin: None,
            stdout: None,
            loopback_token,
            negotiated_network: None,
            spend_policy,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn data_root(&self) -> &Path {
        &self.options.data_root
    }

    pub fn network(&self) -> &str {
        &self.options.network
    }

    // -------------------------------------------------------------------
    // WP-7 operator surface seams: the read-only spend-policy projection
    // the dashboard renders (real state only — C7) and the operator-gated
    // kill/ceiling controls. The controls mutate the LOCAL policy store
    // (single Rust writer); every set/clear event is logged (redacted) by
    // the policy, and the clear semantics are enforced there (operator-set
    // only; loss-rule auto-kills follow the C3 halted-state rule).
    // -------------------------------------------------------------------

    /// The read-only spend-policy projection for the operator surface.
    /// `now_unix` is the current unix time in seconds (the projection
    /// normalizes stale-day counters to zero spent).
    pub fn spend_policy_snapshot(
        &self,
        now_unix: i64,
    ) -> crate::spend_policy::SpendPolicySnapshot {
        self.spend_policy.snapshot(now_unix)
    }

    /// SET the persisted spend kill (operator reason recorded, event
    /// logged redacted). Refuses to overwrite a loss-rule auto-kill (C3).
    pub fn set_operator_kill(&mut self, reason: &str) -> Result<()> {
        self.spend_policy.set_operator_kill(reason)
    }

    /// CLEAR a persisted kill the operator set. Refuses honestly for a
    /// loss-rule auto-kill (C3 halted-state rule) and when no persisted
    /// operator kill exists.
    pub fn clear_operator_kill(&mut self) -> Result<(), String> {
        self.spend_policy.clear_operator_kill()
    }

    /// Configure the per-surface daily ceiling (configuration, not a
    /// posture change — OMEGA-DELTA-0300). Zero is refused.
    pub fn set_surface_ceiling(&mut self, surface: &str, ceiling_sats: u64) -> Result<()> {
        self.spend_policy.set_surface_ceiling(surface, ceiling_sats)
    }

    /// Remove a per-surface ceiling override (falls back to the default).
    pub fn clear_surface_ceiling(&mut self, surface: &str) -> Result<()> {
        self.spend_policy.clear_surface_ceiling(surface)
    }

    pub async fn start(&mut self) -> Result<InitializeResult> {
        if self.child.is_some() {
            bail!("sovereign wallet sidecar is already running");
        }
        self.spawn_child().await?;
        let generation = self.generation();
        let result = self
            .request(
                "initialize",
                Some(json!({ "generation": generation })),
                generation,
            )
            .await?;
        let result: InitializeResult =
            serde_json::from_value(result).context("decode sovereign wallet initialize result")?;
        if result.schema != PROTOCOL_SCHEMA {
            self.stop().await.ok();
            bail!("sidecar initialize used an invalid schema");
        }
        if result.protocol_version != PROTOCOL_VERSION {
            self.stop().await.ok();
            bail!("sidecar protocol version is incompatible (want {PROTOCOL_VERSION}, got {})", result.protocol_version);
        }
        // SEC-2026-050 (revised by OMEGA-DELTA-0286): the initialize-reported
        // network (waved's ACTUAL runtime network from the sidecar's probe)
        // MUST equal the configured network. `mainnet` is refused UNLESS
        // configured mainnet AND the allow-mainnet opt-in is present — the
        // opt-in is re-checked here at startup, never trusting the env alone.
        let reported = result.waved_network.as_deref().unwrap_or(&result.network);
        let allow_mainnet =
            std::env::var(crate::ALLOW_MAINNET_ENVIRONMENT_VARIABLE).as_deref() == Ok("1");
        if reported == "mainnet" && !(self.options.network == "mainnet" && allow_mainnet) {
            self.stop().await.ok();
            bail!(
                "MAINNET_REFUSED: sidecar reported waved on mainnet; child torn down \
                 (SEC-2026-050; OMEGA-DELTA-0286)"
            );
        }
        if reported != self.options.network {
            self.stop().await.ok();
            bail!(
                "sidecar reported network {reported:?}, expected {:?}; child torn down \
                 (SEC-2026-050)",
                self.options.network
            );
        }
        self.negotiated_network = Some(reported.to_string());
        Ok(result)
    }

    pub async fn ensure_started(&mut self) -> Result<()> {
        if self.child.is_none() {
            self.start().await?;
        }
        Ok(())
    }

pub async fn health(&mut self) -> Result<HealthResult, crate::client::SovereignWalletError> {
        let result = self.request("health", None, self.generation()).await?;
        Ok(serde_json::from_value(result).context("decode health result")?)
    }

    pub async fn restart(&mut self) -> Result<InitializeResult> {
        self.stop().await?;
        let next = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.generation.store(next, Ordering::SeqCst);
        self.start().await
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.negotiated_network = None;
        if let Some(mut child) = self.child.take() {
            self.stdin.take();
            self.stdout.take();
            #[cfg(unix)]
            {
                let signal_result = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
                if signal_result != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error).context("terminate sovereign wallet sidecar");
                    }
                }
            }

            #[cfg(unix)]
            let exited = smol::future::or(async { child.status().await.map(|_| true) }, async {
                runtime_delay(SHUTDOWN_GRACE_PERIOD).await;
                Ok(false)
            })
            .await
            .context("wait for sovereign wallet sidecar shutdown")?;

            #[cfg(not(unix))]
            let exited = false;

            if !exited {
                child.kill().context("kill unresponsive sovereign wallet sidecar")?;
                child.status().await.context("reap killed sovereign wallet sidecar")?;
            }
        }
        Ok(())
    }

    async fn spawn_child(&mut self) -> Result<()> {
        std::fs::create_dir_all(&self.options.data_root)
            .with_context(|| format!("create data root {}", self.options.data_root.display()))?;

        let mut command = std::process::Command::new(&self.options.command.program);
        command.args(&self.options.command.args);
        // Secrets are injected via env, never args (design §1.3).
        command.env("OMEGA_SOVEREIGN_WALLET_DATA_ROOT", &self.options.data_root);
        command.env("OMEGA_SOVEREIGN_WALLET_NETWORK", &self.options.network);
        command.env("OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN", self.loopback_token.as_str());
        command.env("OMEGA_SOVEREIGN_WALLET_GENERATION", self.generation().to_string());
        if let Some(waved_bin) = std::env::var_os("OMEGA_SOVEREIGN_WALLET_WAVED_BIN") {
            command.env("OMEGA_SOVEREIGN_WALLET_WAVED_BIN", waved_bin);
        }

        let mut child = Child::spawn(command, Stdio::piped(), Stdio::piped(), Stdio::piped())
            .with_context(|| {
                format!(
                    "spawn sovereign wallet sidecar {}",
                    redact_command(&format!("{:?}", self.options.command))
                )
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("sovereign wallet sidecar stdin missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("sovereign wallet sidecar stdout missing"))?;
        if let Some(stderr) = child.stderr.take() {
            smol::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Some(line) = lines.next().await {
                    match line {
                        // SEC-2026-046: stderr is forwarded redacted so a
                        // stray mnemonic/password/preimage never reaches the log.
                        Ok(line) => eprintln!("sovereign-wallet: {}", redact_command(&line)),
                        Err(error) => {
                            eprintln!("sovereign-wallet stderr read failed: {error}");
                            break;
                        }
                    }
                }
            })
            .detach();
        }

        self.stdin = Some(stdin);
        self.stdout = Some(BufReader::new(stdout));
        self.child = Some(child);
        Ok(())
    }

    pub(crate) async fn request(
        &mut self,
        method: &str,
        params: Option<Value>,
        generation: u64,
    ) -> Result<Value, crate::client::SovereignWalletError> {
        let timeout = if method == "pay-invoice" {
            PAY_REQUEST_TIMEOUT
        } else if method == "health" {
            HEALTH_TIMEOUT
        } else {
            self.options.request_timeout
        };
        self.request_with_timeout(method, params, generation, timeout).await
    }

    pub(crate) async fn request_with_timeout(
        &mut self,
        method: &str,
        params: Option<Value>,
        generation: u64,
        timeout: Duration,
    ) -> Result<Value, crate::client::SovereignWalletError> {
        use crate::client::SovereignWalletError;

        let id = self
            .next_request_id
            .fetch_add(1, Ordering::SeqCst)
            .to_string();
        let frame = request_frame(id.clone(), generation, method, params);
        let line = serde_json::to_string(&frame).map_err(anyhow::Error::from)?;
        if line.len() > MAX_FRAME_BYTES {
            return Err(SovereignWalletError::Anyhow(anyhow!(
                "sovereign wallet request frame exceeds {MAX_FRAME_BYTES} bytes"
            )));
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("sovereign wallet sidecar not started"))?;
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(anyhow::Error::from)?;
        stdin.flush().await.map_err(anyhow::Error::from)?;

        let response_result = smol::future::or(
            async {
                loop {
                    let line = read_bounded_line(
                        self.stdout
                            .as_mut()
                            .ok_or_else(|| anyhow!("sovereign wallet stdout missing"))?,
                        MAX_FRAME_BYTES,
                    )
                    .await?
                    .ok_or_else(|| anyhow!("sovereign wallet sidecar closed stdout"))?;
                    let frame: Value = serde_json::from_str(&line)
                        .context("decode sovereign wallet protocol frame")?;
                    match frame.get("kind").and_then(Value::as_str) {
                        Some("event") => continue,
                        Some("response") => {}
                        _ => bail!("sovereign wallet emitted an invalid frame kind"),
                    }
                    let response: ResponseFrame = serde_json::from_value(frame)
                        .context("decode sovereign wallet response frame")?;
                    if response.schema != PROTOCOL_SCHEMA {
                        bail!("sovereign wallet response used an invalid schema");
                    }
                    if response.id != id {
                        continue;
                    }
                    if response.generation != generation {
                        bail!(
                            "sovereign wallet response used stale generation {}; expected {generation}",
                            response.generation
                        );
                    }
                    return Ok::<ResponseFrame, anyhow::Error>(response);
                }
            },
            async {
                runtime_delay(timeout).await;
                Err(anyhow!("sovereign wallet request timed out after {timeout:?}"))
            },
        )
        .await;

        let response = match response_result {
            Ok(response) => response,
            Err(error) => {
                if let Err(stop_error) = self.stop().await {
                    return Err(SovereignWalletError::Anyhow(error.context(format!(
                        "sovereign wallet request failed; child teardown also failed: {stop_error:#}"
                    ))));
                }
                return Err(SovereignWalletError::Anyhow(error));
            }
        };

        if !response.ok {
            let error = response.error.unwrap_or(crate::protocol::ErrorEnvelope {
                code: ErrorCode::Internal,
                message: "request failed without error body".to_string(),
                details: String::new(),
                retryable: true,
                remediation: String::new(),
            });
            if error.code == ErrorCode::MainnetRefused {
                return Err(SovereignWalletError::MainnetRefused);
            }
            if error.code == ErrorCode::StaleGeneration {
                return Err(SovereignWalletError::StaleGeneration);
            }
            return Err(SovereignWalletError::Protocol {
                code: error.code,
                message: error.message,
                retryable: error.retryable,
                remediation: error.remediation,
            });
        }
        response
            .result
            .ok_or_else(|| SovereignWalletError::Anyhow(anyhow!("ok response missing result")))
    }
}

impl Drop for SovereignWalletSupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().log_err();
        }
        // The loopback token is a Zeroizing<String>: zeroed on drop.
    }
}

/// Resolve the sidecar launch command: `<node> <repo>/sidecar/sovereign-wallet/dist/main.js`.
pub fn resolve_sidecar_command(node_binary: &Path) -> SovereignWalletCommand {
    // The crate lives at <repo>/crates/sovereign_wallet; the repo root is two
    // parents up. env!("CARGO_MANIFEST_DIR") is canonical on Windows.
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    SovereignWalletCommand {
        program: node_binary.to_path_buf(),
        args: vec![
            repository_root
                .join("sidecar/sovereign-wallet/dist/main.js")
                .display()
                .to_string(),
        ],
    }
}

/// Resolve the node binary through the same machinery Omega uses for
/// long-lived Node processes (design §1.3: NodeRuntime + NodeBinaryOptions).
pub async fn resolve_node_binary(
    node_runtime: &node_runtime::NodeRuntime,
) -> Result<PathBuf> {
    node_runtime.binary_path().await.context("resolve node binary for the sovereign wallet sidecar")
}

/// Test/dev helper: node from NODE env or PATH (effectd fixture pattern).
pub fn fixture_node() -> PathBuf {
    std::env::var_os("NODE")
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .or_else(|| {
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|dir| dir.join(if cfg!(windows) { "node.exe" } else { "node" }))
                    .find(|candidate| candidate.is_file())
            })
        })
        .unwrap_or_else(|| PathBuf::from("node"))
}

pub fn default_options(
    data_root: PathBuf,
    command: SovereignWalletCommand,
    network: &str,
) -> Result<SovereignWalletSupervisorOptions> {
    Ok(SovereignWalletSupervisorOptions {
        data_root,
        command,
        network: network.to_string(),
        initial_generation: 1,
        request_timeout: DEFAULT_REQUEST_TIMEOUT,
        node_require_minor: None,
    })
}

#[allow(clippy::disallowed_methods)]
async fn read_bounded_line(
    reader: &mut BufReader<smol::process::ChildStdout>,
    max_bytes: usize,
) -> Result<Option<String>> {
    let mut frame = Vec::new();
    loop {
        let (consumed, found_newline) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if frame.is_empty() {
                    return Ok(None);
                }
                bail!("sovereign wallet closed stdout with an incomplete frame");
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            let payload_length = if available.get(consumed.saturating_sub(1)) == Some(&b'\n') {
                consumed - 1
            } else {
                consumed
            };
            if frame.len() + payload_length > max_bytes {
                bail!("sovereign wallet response frame exceeds {max_bytes} bytes");
            }
            frame.extend_from_slice(&available[..payload_length]);
            (consumed, payload_length < consumed)
        };
        reader.consume_unpin(consumed);
        if found_newline {
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return String::from_utf8(frame)
                .context("sovereign wallet response frame was not UTF-8")
                .map(Some);
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[allow(clippy::disallowed_methods)]
async fn runtime_delay(duration: Duration) {
    // The supervisor is used without a GPUI application context by tests, so
    // the plain smol timer is the portable choice (effectd supervisor pattern).
    smol::Timer::after(duration).await;
}

/// Test helper: point at a fixture sidecar script (like omega_effectd's fixture_command).
pub fn fixture_command(fixture: &Path) -> SovereignWalletCommand {
    SovereignWalletCommand {
        program: fixture_node(),
        args: vec![fixture.display().to_string()],
    }
}

/// Test helper: fixture command with a per-instance network arg, so parallel
/// tests never race on a shared environment variable for the fixture's report.
pub fn fixture_command_with_network(fixture: &Path, network: &str) -> SovereignWalletCommand {
    let mut command = fixture_command(fixture);
    command.args.push(format!("--network={network}"));
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OMEGA-DELTA-0286 (updated-with-citation): the refusal remains for the
    /// UN-OPTED-IN case — `mainnet` construction is refused without
    /// OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET=1, and signet construction stays
    /// accepted. The gated-mainnet construction path is covered by
    /// `supervisor_accepts_opted_in_mainnet_at_config` in tests.rs.
    #[test]
    fn supervisor_refuses_non_signet_networks_at_config() {
        crate::test_support::assert_allow_mainnet_opt_in_absent(|| {
            let options = default_options(
                PathBuf::from(std::env::temp_dir()),
                SovereignWalletCommand {
                    program: PathBuf::from("node"),
                    args: Vec::new(),
                },
                "mainnet",
            )
            .unwrap();
            let error = SovereignWalletSupervisor::new(options)
                .err()
                .expect("construction with mainnet must fail");
            assert!(error.to_string().contains("mainnet"), "{error}");
            let options = default_options(
                PathBuf::from(std::env::temp_dir()),
                SovereignWalletCommand {
                    program: PathBuf::from("node"),
                    args: Vec::new(),
                },
                "signet",
            )
            .unwrap();
            assert!(SovereignWalletSupervisor::new(options).is_ok());
        });
    }

    #[test]
    fn loopback_token_is_32_hex_bytes() {
        let options = default_options(
            PathBuf::from(std::env::temp_dir()),
            SovereignWalletCommand {
                program: PathBuf::from("node"),
                args: Vec::new(),
            },
            "signet",
        )
        .unwrap();
        let supervisor = SovereignWalletSupervisor::new(options).unwrap();
        assert_eq!(supervisor.loopback_token.len(), 64);
        assert!(supervisor
            .loopback_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
    }
}
