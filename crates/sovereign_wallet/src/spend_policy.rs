//! OMEGA-DELTA-0300 (founder Decision 4, 2026-08-31): the spend kill switch
//! + per-surface daily budgets, installed at the sovereign-wallet supervisor
//! client choke point (client.rs `make_invoice`/`pay_invoice` consult the
//! policy BEFORE forwarding).
//!
//! Mechanism:
//! - **Kill switch** — `OMEGA_SPEND_KILL=1` (the environment-level kill, read
//!   at supervisor construction) blocks EVERY funded flow (mint AND pay — the
//!   C2 all-value-touching semantics recorded in the 0300 registry row; a
//!   halted surface creates no new invoices either). The loss rule
//!   (SEC-2026-098) auto-sets the same kill fail-closed and PERSISTS it, so a
//!   restart cannot silently un-halt the surface.
//! - **Per-surface daily ceiling** — 1,000 sats/day first phase (labeled
//!   reversible assumption, Decision 4); surface `wallet-l402` covers the
//!   wallet choke point (L-402 client pay, escrow fee composition mint+pay,
//!   mandate-gated payments). Ceiling accounting counts real mints + payments
//!   (the design's "invoice mints + payments"); the escrow `amount_sats`
//!   bookkeeping never counts (simulated limbo — no broadcast).
//! - **Persistence** — `spend-budget.json` at `<data_root>/run/` (the
//!   SEC-2026-045 owner-only root the sidecar already uses; the Rust module
//!   is the single writer — the sidecar is not involved). Atomic
//!   write-then-rename; UTC-day rollover resets the counters.
//! - **Founder-only re-enable** — no agent or surface self-clears the kill;
//!   the founder unsets the env / flips the WP-7 operator control
//!   (SEC-2026-104: procedural, recorded in the registry row).
//! - **Loss rule (C3 / SEC-2026-098)** — expected-vs-actual settle
//!   comparison at `pay_invoice`: the sidecar reports the prepared-for total
//!   outflow (invoice amount + expected fee) and the actual outflow; a
//!   payment settling for MORE than the prepared total auto-sets the kill
//!   fail-closed, reports the named halted state, and opens the Debug &
//!   Incident route before anything resumes (Decision 4).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::client::SovereignWalletError;

/// OMEGA-DELTA-0300: the environment-level spend kill env name (bound by the
/// 0300 delta check; founder-set; recorded in the WP-3 evidence). lib.rs
/// re-exports this as `crate::SPEND_KILL_ENVIRONMENT_VARIABLE`.
pub const SPEND_KILL_ENVIRONMENT_VARIABLE: &str = "OMEGA_SPEND_KILL";
/// The funded surface served by this choke point (design §5.1 surface list:
/// `wallet-l402`, `escrow`, `nautilus`, `lnmarkets`).
pub const SURFACE_WALLET_L402: &str = "wallet-l402";
/// First-phase per-surface daily ceiling in sats (Decision 4) — a labeled
/// REVERSIBLE ASSUMPTION; the value is configuration, not a constant baked
/// into a check (the 0300 registry row records the assumption).
pub const DAILY_CEILING_SATS: u64 = 1_000;
/// The persisted policy state file, under the locked data root's `run/` dir.
pub const SPEND_BUDGET_FILE_NAME: &str = "spend-budget.json";
const SPEND_BUDGET_SCHEMA: &str = "omega.spend-budget.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SurfaceBudget {
    /// UTC calendar day (YYYY-MM-DD) the counter belongs to; a different day
    /// rolls the counter over (UTC-day rollover).
    utc_day: String,
    spent_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SpendBudgetState {
    schema: String,
    /// Persisted kill: set by the loss rule (fail-closed auto-kill). The env
    /// kill lives on `SpendPolicy.env_killed` (process-level, founder-set).
    killed: bool,
    /// Named reason for the persisted kill (e.g. the loss-rule trigger).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kill_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    killed_at_unix: Option<i64>,
    /// Per-surface counters.
    surfaces: BTreeMap<String, SurfaceBudget>,
}

impl Default for SpendBudgetState {
    fn default() -> Self {
        Self {
            schema: SPEND_BUDGET_SCHEMA.to_string(),
            killed: false,
            kill_reason: None,
            killed_at_unix: None,
            surfaces: BTreeMap::new(),
        }
    }
}

/// The spend policy owned by the supervisor: kill (env + persisted) and the
/// per-surface daily ceiling, with atomic persistence.
#[derive(Debug)]
pub struct SpendPolicy {
    budget_path: PathBuf,
    /// The env-level kill read at construction (founder-set hard control).
    env_killed: bool,
    state: SpendBudgetState,
}

impl SpendPolicy {
    /// Load (or initialize) the policy at `<data_root>/run/spend-budget.json`.
    /// `env_killed` is the process-level `OMEGA_SPEND_KILL=1` read by the
    /// supervisor at construction. A missing file is a fresh state; a
    /// corrupted file is a construction failure (fail-closed).
    pub fn new(data_root: &Path, env_killed: bool) -> Result<Self> {
        let budget_path = data_root.join("run").join(SPEND_BUDGET_FILE_NAME);
        let state = match fs::read(&budget_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "spend-budget.json at {} is corrupted; refusing to start (OMEGA-DELTA-0300)",
                    budget_path.display()
                )
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => SpendBudgetState::default(),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot read {}", budget_path.display()));
            }
        };
        Ok(Self {
            budget_path,
            env_killed,
            state,
        })
    }

    /// True when any kill source is active: the env-level kill (founder-set)
    /// or the persisted kill (loss-rule auto-set). When killed, EVERY funded
    /// flow refuses before touching the sidecar (C2 all-value-touching:
    /// mint AND pay).
    pub fn killed(&self) -> bool {
        self.env_killed || self.state.killed
    }

    /// The named halted state reported to callers when killed.
    pub fn halt_message(&self) -> String {
        match &self.state.kill_reason {
            Some(reason) => format!(
                "SPEND_HALTED: {reason}; the sovereign wallet surface is halted fail-closed; \
                 the Debug & Incident route is opened before anything resumes; only the founder \
                 re-enables (OMEGA-DELTA-0300)"
            ),
            None => format!(
                "SPEND_HALTED: the spend kill is set (OMEGA_SPEND_KILL or the persisted \
                 loss-rule kill); every funded flow refuses until the founder re-enables \
                 (OMEGA-DELTA-0300)"
            ),
        }
    }

    /// The persisted budget state (test seam — read-only projection).
    #[cfg(test)]
    pub(crate) fn budget_state(&self) -> &SpendBudgetState {
        &self.state
    }

    /// Kill + ceiling gate for a mint or pay on `surface` — consulted BEFORE
    /// forwarding to the sidecar. `amount_sats` is the invoice amount (mint:
    /// the requested amount; pay: the BOLT11 amount parsed from the invoice).
    pub fn check_spend(&self, surface: &str, amount_sats: u64, now_unix: i64) -> Result<(), SovereignWalletError> {
        if self.killed() {
            return Err(SovereignWalletError::SpendHalted(self.halt_message()));
        }
        let day = utc_day(now_unix);
        let spent = self
            .state
            .surfaces
            .get(surface)
            .filter(|budget| budget.utc_day == day)
            .map(|budget| budget.spent_sats)
            .unwrap_or(0);
        if spent.saturating_add(amount_sats) > DAILY_CEILING_SATS {
            return Err(SovereignWalletError::SpendPolicyRefused(format!(
                "the daily spend ceiling for surface {surface} would be exceeded: \
                 {spent} + {amount_sats} > {DAILY_CEILING_SATS} sats (first-phase reversible \
                 assumption, OMEGA-DELTA-0300)"
            )));
        }
        Ok(())
    }

    /// Record a REAL mint or pay on `surface` after the sidecar confirmed it,
    /// persisting atomically (write-then-rename) with UTC-day rollover.
    pub fn record_spend(&mut self, surface: &str, amount_sats: u64, now_unix: i64) -> Result<()> {
        let day = utc_day(now_unix);
        let budget = self
            .state
            .surfaces
            .entry(surface.to_string())
            .or_insert_with(|| SurfaceBudget {
                utc_day: day.clone(),
                spent_sats: 0,
            });
        if budget.utc_day != day {
            // UTC-day rollover: the counter belongs to a new day.
            budget.utc_day = day;
            budget.spent_sats = 0;
        }
        budget.spent_sats = budget.spent_sats.saturating_add(amount_sats);
        self.persist()
    }

    /// C3 / SEC-2026-098: auto-set the kill fail-closed (loss rule) and
    /// PERSIST it so a restart cannot silently un-halt the surface. Only the
    /// founder re-enables (env unset / WP-7 operator control); nothing here
    /// self-clears.
    pub fn auto_kill_loss_rule(&mut self, reason: &str, now_unix: i64) -> Result<()> {
        self.state.killed = true;
        self.state.kill_reason = Some(reason.to_string());
        self.state.killed_at_unix = Some(now_unix);
        self.persist()
    }

    /// Atomic write-then-rename: write the temp file, then rename over the
    /// live file (the owner-only run dir is already secured, SEC-2026-045).
    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.budget_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(&self.state)
            .context("serialize spend-budget state (OMEGA-DELTA-0300)")?;
        let tmp = self.budget_path.with_extension("json.tmp");
        fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, &self.budget_path)
            .with_context(|| format!("rename {} over {}", tmp.display(), self.budget_path.display()))?;
        Ok(())
    }
}

/// UTC calendar day (YYYY-MM-DD) for a unix timestamp — the rollover key.
/// Howard Hinnant's civil-from-days algorithm (public domain), implemented
/// here so the policy needs no date dependency.
pub fn utc_day(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

/// Parse the BOLT11 amount (hrp digits + optional m/u/n/p multiplier) into
/// sats for ceiling accounting. `None` when the amount is absent (pay-any
/// invoice) or unparseable — pay-any invoices are not part of the designed
/// funded flows; the kill remains the hard control (recorded in WP-3
/// evidence).
///
/// BOLT-11 hrp grammar: `ln` + currency (`bc`/`bcrt`/`tbs`/`tb`) + optional
/// amount (digits + ONE optional multiplier letter) + `1` + data. The '1'
/// inside the amount digits is NOT the separator (e.g. `lnbc10u1…`), so the
/// separator is located after the amount, never via a bare `find('1')`.
pub fn bolt11_amount_sats(invoice: &str) -> Option<u64> {
    let lower = invoice.trim().to_ascii_lowercase();
    let rest = lower.strip_prefix("ln")?;
    // Longest currency first: "bcrt" starts with "bc", "tbs" starts with "tb".
    let after_currency = if let Some(rest) = rest.strip_prefix("bcrt") {
        rest
    } else if let Some(rest) = rest.strip_prefix("tbs") {
        rest
    } else if let Some(rest) = rest.strip_prefix("bc") {
        rest
    } else if let Some(rest) = rest.strip_prefix("tb") {
        rest
    } else {
        return None;
    };
    let digits: String = after_currency
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    let multiplier = after_currency.chars().nth(digits.len());
    let amount_width = digits.len() + usize::from(multiplier.is_some());
    // The separator '1' must follow the amount (digits + optional multiplier).
    if !after_currency[amount_width..].starts_with('1') {
        return None;
    }
    let base: u64 = digits.parse().ok()?;
    match multiplier {
        None => base.checked_mul(100_000_000),
        Some('m') => base.checked_mul(100_000),
        Some('u') => base.checked_mul(100),
        // n = 0.1 sat, p = 0.0001 sat: round UP so the ceiling never
        // under-counts a fractional-sat invoice.
        Some('n') => Some(base.div_ceil(10)),
        Some('p') => Some(base.div_ceil(10_000)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const NOW: i64 = 1_704_067_200; // 2024-01-01T00:00:00Z

    fn policy(env_killed: bool) -> (SpendPolicy, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        (SpendPolicy::new(dir.path(), env_killed).expect("policy"), dir)
    }

    #[test]
    fn utc_day_matches_known_anchors() {
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(1_704_067_200), "2024-01-01");
        assert_eq!(utc_day(1_704_067_199), "2023-12-31");
        assert_eq!(utc_day(1_704_067_200 + 86_400), "2024-01-02");
    }

    #[test]
    fn bolt11_amounts_parse_to_sats() {
        assert_eq!(bolt11_amount_sats("lnbc10u1p0example"), Some(1_000));
        assert_eq!(bolt11_amount_sats("lntbs100u1pfixture"), Some(10_000));
        assert_eq!(bolt11_amount_sats("lnbc2500m1xyz"), Some(250_000_000));
        assert_eq!(bolt11_amount_sats("lnbcrt10n1xyz"), Some(1)); // ceil(10/10)
        assert_eq!(bolt11_amount_sats("lnbc1xyz"), None); // pay-any (no amount)
        assert_eq!(bolt11_amount_sats("not-an-invoice"), None);
        assert_eq!(bolt11_amount_sats(""), None);
    }

    #[test]
    fn the_kill_blocks_mint_and_pay_but_not_an_unkilled_policy() {
        // C2 semantics (SEC-2026-100): ALL-VALUE-TOUCHING — when killed, mint
        // AND pay are both refused (a halted surface creates no new invoices
        // either). check_spend is the single gate for both directions.
        let (killed, _dir) = policy(true);
        let err = killed.check_spend(SURFACE_WALLET_L402, 1, NOW).expect_err("killed");
        assert!(matches!(err, SovereignWalletError::SpendHalted(_)), "{err:?}");
        assert!(err.to_string().contains("SPEND_HALTED"), "{err}");

        let (live, _dir) = policy(false);
        assert!(live.check_spend(SURFACE_WALLET_L402, 1, NOW).is_ok());
    }

    #[test]
    fn the_daily_ceiling_refuses_over_limit_and_rolls_over_on_utc_day_change() {
        let (mut policy, _dir) = policy(false);
        // 999 sats recorded -> a 2-sat pay crosses the 1,000 ceiling.
        policy.record_spend(SURFACE_WALLET_L402, 999, NOW).expect("record");
        assert!(policy.check_spend(SURFACE_WALLET_L402, 2, NOW).is_err());
        assert!(policy.check_spend(SURFACE_WALLET_L402, 1, NOW).is_ok());
        policy.record_spend(SURFACE_WALLET_L402, 1, NOW).expect("record");
        assert!(policy.check_spend(SURFACE_WALLET_L402, 1, NOW).is_err());
        // UTC-day rollover resets the counter (next day, same surface).
        let next_day = NOW + 86_400;
        assert!(policy.check_spend(SURFACE_WALLET_L402, 1_000, next_day).is_ok());
        policy.record_spend(SURFACE_WALLET_L402, 1_000, next_day).expect("record");
        assert!(policy.check_spend(SURFACE_WALLET_L402, 1, next_day).is_err());
    }

    #[test]
    fn persistence_is_atomic_and_survives_reload() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("run").join(SPEND_BUDGET_FILE_NAME);
        {
            let mut policy = SpendPolicy::new(dir.path(), false).expect("policy");
            policy.record_spend(SURFACE_WALLET_L402, 123, NOW).expect("record");
            policy.auto_kill_loss_rule("loss-rule: over-settlement (test)", NOW).expect("kill");
            assert!(path.exists(), "the budget file must be written");
            // No stray temp file may remain after the atomic rename.
            assert!(!path.with_extension("json.tmp").exists());
        }
        // Reload: the kill and the counter survive (a restart cannot
        // silently un-halt the surface).
        let reloaded = SpendPolicy::new(dir.path(), false).expect("reload");
        assert!(reloaded.killed());
        assert_eq!(reloaded.budget_state().kill_reason.as_deref(), Some("loss-rule: over-settlement (test)"));
        assert!(reloaded.check_spend(SURFACE_WALLET_L402, 1, NOW).is_err());
    }

    #[test]
    fn a_corrupted_budget_file_is_a_fail_closed_construction_error() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("run").join(SPEND_BUDGET_FILE_NAME);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, b"{not json").expect("write");
        let err = SpendPolicy::new(dir.path(), false).expect_err("corrupted file must refuse");
        assert!(err.to_string().contains("spend-budget.json"), "{err}");
    }
}