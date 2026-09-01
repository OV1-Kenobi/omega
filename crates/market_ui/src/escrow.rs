//! OMEGA-DELTA-0285 (Phase 3b minimal arbitration demo): the HTLC 2-of-3
//! escrow lifecycle — "Schrödinger's Transaction" limbo.
//!
//! The escrow holds the principal unsettled to customer, agent, and
//! platform-arbitrator alike for a bounded block window (operator-
//! configurable per session — OMEGA-DELTA-0293). No party — least of
//! all the platform — has custody during limbo; the only custody event is the
//! flat arbitration fee collected on a human decision. The state machine is
//! the demo's authority structure:
//!
//! ```text
//! Created -> AwaitingDelivery -> ReceiptSubmitted -> VerifiedPass -> Released -> Closed
//!                                                 \-> VerifiedFail -> ArbitrationRequested -> Released/Refunded -> Closed
//! AwaitingDelivery/ReceiptSubmitted/VerifiedFail --(timeout, observed_height >= timeout_at_height)--> Refunded
//! ```
//!
//! Custody rules enforced here (evidence/03b SEC-2026-084..088):
//! - the HTLC lock is EXTERNAL: `EscrowCreated`/`ArbitrationRequested` are
//!   zero-posting intents and the `mkt-swp-escrow` venue balance never moves
//!   for unsettled principal — no platform custody is ever posted;
//! - settlements (`ArbitrationReleased`/`ArbitrationRefunded`) are balanced
//!   participant-to-participant postings with the flat fee rerouted to the
//!   arbitrator exactly per the mandate;
//! - `VerifiedPass` fires only on a RE-DERIVED digest supplied by the caller
//!   (the stored `receipt_digest` is a claim, never proof — slice B computes
//!   the re-derivation from the actual receipt);
//! - the pay-first invariant: `request_arbitration` requires the
//!   `fee_payment_digest` of an already-paid fee AND refuses unless the
//!   ledger holds the committed `Fee` entry carrying that digest bound to
//!   this escrow (OMEGA-DELTA-0288 — enforced at the state machine, not
//!   only at the composition);
//! - timeout refunds gate on `observed_height >= timeout_at_height` — blocks
//!   observed through the sanctioned tip seam, never wall-clock alone.
//!
//! The demo HTLC is simulated/external and is labeled as such wherever it is
//! user-visible: nothing here broadcasts an on-chain transaction and nothing
//! here claims settlement authority — Bitcoin/Lightning remain the only
//! settlement authorities (amendment 02b §3).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

use trading_ledger::{
    escrow_timeout_at_height, LedgerAccount, LedgerEntryDraft, LedgerEntryKind, LedgerPosting,
    LedgerQuery, LedgerStore,
};
use trading_mandate::{
    AssetId, MandateDecision, MandateStore, TradingInstruction, TradingNetwork,
    MKT_SWP_ESCROW_VENUE,
};

/// Escrow session persistence schema (digest-only fields).
pub const ESCROW_SESSION_SCHEMA: &str = "omega.market.escrow-session.v1";
/// Ledger metadata schema carried by every escrow entry (WP-3b fixture shape).
/// OMEGA-DELTA-0292: one source of truth with the ledger-side guard marker.
pub const ESCROW_LEDGER_SCHEMA: &str = trading_ledger::ESCROW_LEDGER_METADATA_SCHEMA;
/// The single strategy id an escrow mandate authorizes (WP-3b fixture shape).
pub const ESCROW_STRATEGY: &str = "escrow_create";
/// Escrow sessions live beside the market sessions under the data dir.
pub const ESCROW_STORE_DIRECTORY: &str = "market_sessions";

/// Fee-free settlement marker: the automated `VerifiedPass` release reroutes
/// nothing (the founder's rule — automated receipts resolve free).
pub const AUTOMATED_RELEASE_FEE_SATS: u64 = 0;

/// OMEGA-DELTA-0293 (Decision 6): the escrow timeout window is an
/// operator-configurable session value at escrow open — any value in
/// `trading_mandate::MIN_ESCROW_TIMEOUT_BLOCKS..=MAX_ESCROW_TIMEOUT_BLOCKS`
/// (36..=432 blocks, network-agnostic) is accepted; when the operator does
/// not specify one, this default (144 blocks, ~24h at the observed mainnet
/// block cadence) applies.
pub const DEFAULT_ESCROW_TIMEOUT_BLOCKS: u32 = 144;

/// OMEGA-DELTA-0294 (Decision 5): the operator-created escrow
/// mandate/session arbitration-fee default for real-sats testing is 100
/// sats (supersedes the pending 1,000-sat default). The mandate field
/// `arbitration_fee_flat_sats` remains configurable — an explicit mandate
/// or session value overrides this default.
pub const DEFAULT_ARBITRATION_FEE_FLAT_SATS: u64 = 100;

/// OMEGA-DELTA-0289 (SEC-2026-093 closure): the fixed `reason_code` set for
/// the timeout refund door — no caller free text. The human door keeps its
/// identifier-validated caller reason (out of 0289's scope).
pub const TIMEOUT_REFUND_REASON_CODES: [&str; 1] = ["htlc_timeout"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowState {
    Created,
    AwaitingDelivery,
    ReceiptSubmitted,
    VerifiedPass,
    VerifiedFail,
    ArbitrationRequested,
    Released,
    Refunded,
    Closed,
}

/// A 2-of-3 escrow session. Every field is public-safe: digests, hex keys,
/// counts — the HTLC preimage never enters this struct (SEC-2026-088).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EscrowSession {
    pub schema: String,
    pub escrow_id: String,
    pub network: TradingNetwork,
    /// The customer (requester role in settlement postings).
    pub principal_pubkey: String,
    /// The agent (provider role in settlement postings).
    pub counterparty_pubkey: String,
    /// The platform-arbitrator (OpenAgents/Satnam) — fee beneficiary only.
    pub arbitrator_pubkey: String,
    pub amount_sats: u64,
    /// sha256 of the preimage commitment — the preimage itself stays in the
    /// external HTLC holder and never enters Omega (SEC-2026-088).
    pub hash_lock_digest: String,
    pub timeout_blocks: u32,
    pub timeout_at_height: u64,
    pub arbitration_fee_flat_sats: u64,
    pub state: EscrowState,
    /// The submitted receipt digest — a CLAIM to be re-derived, never proof.
    pub receipt_digest: Option<String>,
    /// OMEGA-DELTA-0291: the provider receipt event id whose signature was
    /// verified against the current claim (OMEGA-DELTA-0290). Together with
    /// `receipt_digest` it forms the linkage the automated
    /// `ArbitrationReleased` entry carries INSIDE the hash chain. Additive
    /// nullable on the session schema — no version bump (older persisted
    /// sessions decode with `None`).
    #[serde(default)]
    pub receipt_event_id: Option<String>,
    /// Payment proof digest of the pre-paid arbitration fee (pay-first).
    pub fee_payment_digest: Option<String>,
}

/// Parameters for opening an escrow (everything but the observed tip).
/// OMEGA-DELTA-0293/0294: `timeout_blocks` and `arbitration_fee_flat_sats`
/// are operator-configurable session values — `None` applies the defaults
/// (`DEFAULT_ESCROW_TIMEOUT_BLOCKS` = 144, `DEFAULT_ARBITRATION_FEE_FLAT_SATS`
/// = 100) at the session creation site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowOpenParams {
    pub escrow_id: String,
    pub principal_pubkey: String,
    pub counterparty_pubkey: String,
    pub arbitrator_pubkey: String,
    pub amount_sats: u64,
    pub hash_lock_digest: String,
    pub timeout_blocks: Option<u32>,
    pub arbitration_fee_flat_sats: Option<u64>,
}

fn is_64_lower_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn validate_pubkey(label: &str, value: &str) -> Result<()> {
    if !is_64_lower_hex(value) {
        bail!("escrow {label} must be 64-char lowercase hex");
    }
    Ok(())
}

fn validate_digest(label: &str, value: &str) -> Result<()> {
    if !is_64_lower_hex(value) {
        bail!("escrow {label} must be a 64-char lowercase hex digest");
    }
    Ok(())
}

fn validate_identifier_value(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("escrow {label} must be a non-empty alphanumeric identifier");
    }
    Ok(())
}

impl EscrowSession {
    /// Open an escrow: mandate-gate the principal's spend, then append the
    /// zero-posting `EscrowCreated` intent (SEC-2026-084). `observed_height`
    /// is the tip read by the caller through the sanctioned seam (slice C
    /// wires the LND `GetInfo` call; never wall-clock).
    pub fn open(
        ledger: &LedgerStore,
        mandates: &MandateStore,
        params: EscrowOpenParams,
        network: TradingNetwork,
        observed_height: u32,
        now_ms: i64,
    ) -> Result<Self> {
        validate_identifier_value("escrow id", &params.escrow_id)?;
        validate_pubkey("principal pubkey", &params.principal_pubkey)?;
        validate_pubkey("counterparty pubkey", &params.counterparty_pubkey)?;
        validate_pubkey("arbitrator pubkey", &params.arbitrator_pubkey)?;
        validate_digest("hash lock digest", &params.hash_lock_digest)?;
        if params.amount_sats == 0 {
            bail!("escrow amount must be positive");
        }
        // OMEGA-DELTA-0293/0294: the operator-configurable session values
        // resolve at the creation site — an explicit value is honored, the
        // defaults apply when unspecified.
        let timeout_blocks = params.timeout_blocks.unwrap_or(DEFAULT_ESCROW_TIMEOUT_BLOCKS);
        let arbitration_fee_flat_sats = params
            .arbitration_fee_flat_sats
            .unwrap_or(DEFAULT_ARBITRATION_FEE_FLAT_SATS);
        if arbitration_fee_flat_sats == 0 {
            bail!("escrow arbitration fee must be positive");
        }
        if !(trading_mandate::MIN_ESCROW_TIMEOUT_BLOCKS
            ..=trading_mandate::MAX_ESCROW_TIMEOUT_BLOCKS)
            .contains(&timeout_blocks)
        {
            // OMEGA-DELTA-0293: network-agnostic wording — blocks, not
            // "signet blocks".
            bail!(
                "escrow timeout must be {}..={} blocks",
                trading_mandate::MIN_ESCROW_TIMEOUT_BLOCKS,
                trading_mandate::MAX_ESCROW_TIMEOUT_BLOCKS
            );
        }
        let timeout_at_height = escrow_timeout_at_height(observed_height, timeout_blocks)
            .context("escrow timeout height")?;

        // The escrow opening is the spend decision: the principal-only
        // mkt-swp-escrow mandate must authorize it (SEC-2026-043 + the
        // max_escrow_sats cap from WP-3b's authorize extension).
        let instruction = TradingInstruction {
            venue: MKT_SWP_ESCROW_VENUE.to_string(),
            network,
            strategy_id: ESCROW_STRATEGY.to_string(),
            collateral_asset: AssetId::sats(),
            venue_balance_after: params.amount_sats,
            position_notional_usd: 0,
            leverage: 1,
            daily_realized_loss: 0,
            orders_last_hour: 0,
            liquidation_buffer_bps: 0,
        };
        match mandates.authorize(&instruction, Some(&params.principal_pubkey), now_ms)? {
            MandateDecision::Authorized { .. } => {}
            MandateDecision::Refused { reason, .. } => {
                bail!("escrow mandate refused: {reason:?}")
            }
        }

        let mut draft = LedgerEntryDraft::new(
            format!("escrow:{}:created", params.escrow_id),
            now_ms,
            ESCROW_STRATEGY,
            LedgerEntryKind::EscrowCreated,
        );
        draft.metadata = json!({
            "schema": ESCROW_LEDGER_SCHEMA,
            "escrow_id": params.escrow_id,
            "principal_pubkey": params.principal_pubkey,
            "counterparty_pubkey": params.counterparty_pubkey,
            "arbitrator_pubkey": params.arbitrator_pubkey,
            "amount_sats": params.amount_sats,
            "hash_lock_digest": params.hash_lock_digest,
            "timeout_blocks": timeout_blocks,
            "timeout_at_height": timeout_at_height,
            "mode": "htlc_2of3",
        });
        ledger
            .append(draft)
            .context("append EscrowCreated intent")?;

        let session = Self {
            schema: ESCROW_SESSION_SCHEMA.to_string(),
            escrow_id: params.escrow_id,
            network,
            principal_pubkey: params.principal_pubkey,
            counterparty_pubkey: params.counterparty_pubkey,
            arbitrator_pubkey: params.arbitrator_pubkey,
            amount_sats: params.amount_sats,
            hash_lock_digest: params.hash_lock_digest,
            timeout_blocks,
            timeout_at_height,
            arbitration_fee_flat_sats,
            state: EscrowState::Created,
            receipt_digest: None,
            receipt_event_id: None,
            fee_payment_digest: None,
        };
        Ok(session)
    }

    fn require_state(&self, allowed: &[EscrowState], action: &str) -> Result<()> {
        if self.state == EscrowState::Closed {
            bail!("escrow {} refused: the escrow is closed", action);
        }
        if !allowed.contains(&self.state) {
            bail!(
                "escrow {} refused from state {:?} (allowed: {:?})",
                action,
                self.state,
                allowed
            );
        }
        Ok(())
    }

    /// The job is accepted and delivery is awaited. No value moves.
    pub fn await_delivery(&mut self) -> Result<()> {
        self.require_state(&[EscrowState::Created], "await_delivery")?;
        self.state = EscrowState::AwaitingDelivery;
        Ok(())
    }

    /// The agent claims a delivery by submitting a receipt digest — a claim
    /// only. The digest is re-derived by the caller before `VerifiedPass`
    /// (slice B wires the lbr-closeout canonical re-derivation).
    pub fn submit_receipt(&mut self, receipt_digest: impl Into<String>) -> Result<()> {
        self.require_state(&[EscrowState::AwaitingDelivery], "submit_receipt")?;
        let digest = receipt_digest.into();
        validate_digest("receipt digest", &digest)?;
        self.receipt_digest = Some(digest);
        // OMEGA-DELTA-0291: a new claim invalidates any prior event linkage —
        // the pair is (re)bound only when a provider-signed event verifies.
        self.receipt_event_id = None;
        self.state = EscrowState::ReceiptSubmitted;
        Ok(())
    }

    /// Record a verification outcome from a RE-DERIVED digest. The stored
    /// `receipt_digest` is never used as proof — the recomputed value is the
    /// only input (SEC-2026-077 analog for the demo's receipt gate).
    pub fn record_verification(&mut self, recomputed_digest: &str) -> Result<EscrowState> {
        self.require_state(&[EscrowState::ReceiptSubmitted], "record_verification")?;
        validate_digest("recomputed receipt digest", recomputed_digest)?;
        let submitted = self
            .receipt_digest
            .clone()
            .context("submitted receipt digest missing")?;
        if recomputed_digest == submitted {
            self.state = EscrowState::VerifiedPass;
        } else {
            self.state = EscrowState::VerifiedFail;
        }
        Ok(self.state)
    }

    /// Record a FAILED verification that never reached the digest comparison
    /// (OMEGA-DELTA-0290: the provider-signature gate refused the event).
    /// The claim did not verify, so the session leaves `ReceiptSubmitted`
    /// for the `VerifiedFail` limbo — never `VerifiedPass`.
    fn refuse_verification(&mut self) -> Result<EscrowState> {
        self.require_state(&[EscrowState::ReceiptSubmitted], "record_verification")?;
        self.state = EscrowState::VerifiedFail;
        Ok(self.state)
    }

    /// Request human arbitration. Pay-first (SEC-2026-085): the escalator
    /// must already have paid the flat fee — `fee_payment_digest` references
    /// the balanced `Fee` entry slice B appends. Admitted from
    /// AwaitingDelivery (delivery overdue) or VerifiedFail (delivery failed).
    pub fn request_arbitration(
        &mut self,
        ledger: &LedgerStore,
        requested_by_pubkey: &str,
        fee_payment_digest: impl Into<String>,
        now_ms: i64,
    ) -> Result<()> {
        self.require_state(
            &[EscrowState::AwaitingDelivery, EscrowState::VerifiedFail],
            "request_arbitration",
        )?;
        validate_pubkey("requester pubkey", requested_by_pubkey)?;
        let digest = fee_payment_digest.into();
        validate_digest("fee payment digest", &digest)?;
        // OMEGA-DELTA-0288 (SEC-2026-092 closure): pay-first is enforced at
        // the state machine, not only at the composition. Refuse unless the
        // ledger already contains a COMMITTED `Fee` entry whose
        // `fee_payment_digest` equals this digest AND whose `escrow_id`
        // binds it to THIS escrow. A well-formed fabricated digest admits
        // nothing, and a `Fee` entry paid for a different escrow can never
        // gate this one (the forged-binding negative test).
        let fee_entry_committed = ledger
            .entries(&LedgerQuery::default())
            .context("read the ledger for the arbitration fee gate")?
            .into_iter()
            .any(|entry| {
                matches!(entry.kind, LedgerEntryKind::Fee)
                    && entry.metadata.get("fee_payment_digest").and_then(|value| value.as_str())
                        == Some(digest.as_str())
                    && entry.metadata.get("escrow_id").and_then(|value| value.as_str())
                        == Some(self.escrow_id.as_str())
            });
        if !fee_entry_committed {
            bail!(
                "escrow arbitration refused: no committed Fee entry carries \
                 fee_payment_digest {digest} bound to escrow {} (pay-first is \
                 enforced at the state machine, OMEGA-DELTA-0288)",
                self.escrow_id
            );
        }
        // The demo's single fee entry (slice B) is referenced by digest; the
        // human queue is unreachable without it.
        self.fee_payment_digest = Some(digest);
        let mut draft = LedgerEntryDraft::new(
            format!("escrow:{}:arbitration-requested", self.escrow_id),
            now_ms,
            ESCROW_STRATEGY,
            LedgerEntryKind::ArbitrationRequested,
        );
        draft.metadata = json!({
            "schema": ESCROW_LEDGER_SCHEMA,
            "escrow_id": self.escrow_id,
            "requested_by_pubkey": requested_by_pubkey,
            "fee_payment_digest": self.fee_payment_digest,
            "fee_amount_sats": self.arbitration_fee_flat_sats,
            "requested_at_ms": now_ms,
        });
        ledger
            .append(draft)
            .context("append ArbitrationRequested")?;
        self.state = EscrowState::ArbitrationRequested;
        Ok(())
    }

    fn settlement_postings(&self, to_provider: u64, fee_rerouted_sats: u64) -> Vec<LedgerPosting> {
        let amount = self.amount_sats as i64;
        let fee = fee_rerouted_sats as i64;
        let to_provider = to_provider as i64;
        debug_assert_eq!(amount, to_provider + fee, "settlement must balance");
        let mut postings = vec![
            LedgerPosting::sats(
                LedgerAccount::MarketParticipant {
                    role: "requester".into(),
                    participant: self.principal_pubkey.clone(),
                },
                -amount,
            ),
            LedgerPosting::sats(
                LedgerAccount::MarketParticipant {
                    role: "provider".into(),
                    participant: self.counterparty_pubkey.clone(),
                },
                to_provider,
            ),
        ];
        if fee > 0 {
            postings.push(LedgerPosting::sats(
                LedgerAccount::MarketParticipant {
                    role: "provider".into(),
                    participant: self.arbitrator_pubkey.clone(),
                },
                fee,
            ));
        }
        postings
    }

    /// Release the escrow to the agent. Two doors:
    /// - automated (from `VerifiedPass`): the customer's sign-off IS the
    ///   second signature; the fee reroute must be zero (automated receipts
    ///   resolve free);
    /// - human (from `ArbitrationRequested`): the arbitrator decided; the
    ///   flat fee reroutes to the arbitrator exactly per the mandate.
    pub fn release(
        &mut self,
        ledger: &LedgerStore,
        decided_by_pubkey: &str,
        now_ms: i64,
    ) -> Result<()> {
        // OMEGA-DELTA-0289 (SEC-2026-093 closure): the deciding party is
        // BOUND per door — the automated door is the principal's sign-off,
        // the human door is the arbitrator's decision.
        let (fee_rerouted_sats, reason, required_decider) = match self.state {
            EscrowState::VerifiedPass => (
                AUTOMATED_RELEASE_FEE_SATS,
                "automated_pass",
                &self.principal_pubkey,
            ),
            EscrowState::ArbitrationRequested => (
                self.arbitration_fee_flat_sats,
                "human_decision",
                &self.arbitrator_pubkey,
            ),
            other => bail!("escrow release refused from state {other:?}"),
        };
        validate_pubkey("decider pubkey", decided_by_pubkey)?;
        if decided_by_pubkey != required_decider.as_str() {
            bail!(
                "escrow release refused: {reason} decisions must be decided by \
                 the door's bound party (automated door -> principal, human \
                 door -> arbitrator; OMEGA-DELTA-0289)"
            );
        }
        // OMEGA-DELTA-0291 (SEC-2026-096 closure): the automated release
        // carries its receipt linkage from the VERIFIED provider event —
        // both fields land inside the hash chain on the `ArbitrationReleased`
        // entry. A `VerifiedPass` state without the verified linkage is
        // refused (fail-closed — the linkage is the release's evidence).
        let receipt_linkage = if self.state == EscrowState::VerifiedPass {
            let receipt_digest = self.receipt_digest.clone().context(
                "automated release requires the submitted receipt digest \
                 (OMEGA-DELTA-0291)",
            )?;
            let receipt_event_id = self.receipt_event_id.clone().context(
                "automated release requires the verified provider receipt event \
                 id (OMEGA-DELTA-0291: the linkage is the hash-chained evidence \
                 that the release resolves a verified provider-signed receipt)",
            )?;
            Some((receipt_digest, receipt_event_id))
        } else {
            None
        };
        let to_provider = self
            .amount_sats
            .checked_sub(fee_rerouted_sats)
            .context("settlement amount underflow")?;
        let mut draft = LedgerEntryDraft::new(
            format!("escrow:{}:released", self.escrow_id),
            now_ms,
            ESCROW_STRATEGY,
            LedgerEntryKind::ArbitrationReleased,
        );
        draft.postings = self.settlement_postings(to_provider, fee_rerouted_sats);
        draft.metadata = json!({
            "schema": ESCROW_LEDGER_SCHEMA,
            "escrow_id": self.escrow_id,
            "decision": "released",
            "decided_by_pubkey": decided_by_pubkey,
            "fee_rerouted_sats": fee_rerouted_sats,
            "reason_code": reason,
        });
        if let Some((receipt_digest, receipt_event_id)) = receipt_linkage {
            draft.metadata["receipt_digest"] = json!(receipt_digest);
            draft.metadata["receipt_event_id"] = json!(receipt_event_id);
        }
        ledger.append(draft).context("append ArbitrationReleased")?;
        self.state = EscrowState::Released;
        Ok(())
    }

    /// Refund the escrow to the customer. Two doors:
    /// - human (from `ArbitrationRequested`): the arbitrator decided; the
    ///   flat fee reroutes out of the refund;
    /// - timeout (from any pre-settlement limbo state): only once the
    ///   observed tip reaches `timeout_at_height` — blocks observed through
    ///   the sanctioned seam, never wall-clock (SEC-2026-086). No fee: no
    ///   human was engaged.
    pub fn refund(
        &mut self,
        ledger: &LedgerStore,
        decided_by_pubkey: &str,
        reason_code: &str,
        observed_height: Option<u32>,
        now_ms: i64,
    ) -> Result<()> {
        let (fee_rerouted_sats, reason, required_decider, timeout_door) = match self.state {
            EscrowState::ArbitrationRequested => (
                self.arbitration_fee_flat_sats,
                "human_decision",
                &self.arbitrator_pubkey,
                false,
            ),
            EscrowState::AwaitingDelivery
            | EscrowState::ReceiptSubmitted
            | EscrowState::VerifiedFail => {
                let observed = observed_height.context(
                    "timeout refund requires the observed signet tip height (never wall-clock)",
                )?;
                if u64::from(observed) < self.timeout_at_height {
                    bail!(
                        "escrow refund refused: HTLC window open (observed {observed} < timeout_at_height {})",
                        self.timeout_at_height
                    );
                }
                // OMEGA-DELTA-0289 (SEC-2026-093 closure): the timeout door's
                // `reason_code` comes from a fixed set — no caller free text.
                if !TIMEOUT_REFUND_REASON_CODES.contains(&reason_code) {
                    bail!(
                        "escrow timeout refund refused: reason_code must be one \
                         of {TIMEOUT_REFUND_REASON_CODES:?} (no caller free \
                         text; OMEGA-DELTA-0289)"
                    );
                }
                (0, "htlc_timeout", &self.principal_pubkey, true)
            }
            other => bail!("escrow refund refused from state {other:?}"),
        };
        let _ = reason;
        validate_identifier_value("refund reason", reason_code)?;
        validate_pubkey("decider pubkey", decided_by_pubkey)?;
        // OMEGA-DELTA-0289 (SEC-2026-093 closure): `decided_by_pubkey` is
        // BOUND per door — the human door is the arbitrator's decision, the
        // timeout door is the principal's expiry claim.
        if decided_by_pubkey != required_decider.as_str() {
            bail!(
                "escrow refund refused: {} decisions must be decided by the \
                 door's bound party (human door -> arbitrator, timeout door -> \
                 principal; OMEGA-DELTA-0289)",
                if timeout_door { "timeout" } else { "human" }
            );
        }
        let to_principal = self
            .amount_sats
            .checked_sub(fee_rerouted_sats)
            .context("refund amount underflow")?;
        // Refund shape (WP-3b fixture): the principal leaves the agent back
        // to the customer, fee rerouted out of the refund.
        let mut postings = vec![
            LedgerPosting::sats(
                LedgerAccount::MarketParticipant {
                    role: "provider".into(),
                    participant: self.counterparty_pubkey.clone(),
                },
                -(self.amount_sats as i64),
            ),
            LedgerPosting::sats(
                LedgerAccount::MarketParticipant {
                    role: "requester".into(),
                    participant: self.principal_pubkey.clone(),
                },
                to_principal as i64,
            ),
        ];
        if fee_rerouted_sats > 0 {
            postings.push(LedgerPosting::sats(
                LedgerAccount::MarketParticipant {
                    role: "provider".into(),
                    participant: self.arbitrator_pubkey.clone(),
                },
                fee_rerouted_sats as i64,
            ));
        }
        let mut draft = LedgerEntryDraft::new(
            format!("escrow:{}:refunded", self.escrow_id),
            now_ms,
            ESCROW_STRATEGY,
            LedgerEntryKind::ArbitrationRefunded,
        );
        draft.postings = postings;
        draft.metadata = json!({
            "schema": ESCROW_LEDGER_SCHEMA,
            "escrow_id": self.escrow_id,
            "decision": "refunded",
            "decided_by_pubkey": decided_by_pubkey,
            "fee_rerouted_sats": fee_rerouted_sats,
            "reason_code": reason_code,
        });
        ledger.append(draft).context("append ArbitrationRefunded")?;
        self.state = EscrowState::Refunded;
        Ok(())
    }

    /// Terminal bookkeeping after Released/Refunded. No ledger entry.
    pub fn close(&mut self) -> Result<()> {
        self.require_state(&[EscrowState::Released, EscrowState::Refunded], "close")?;
        self.state = EscrowState::Closed;
        Ok(())
    }

    /// Persist the session beside the market sessions (digest-only fields).
    pub fn persist(&self, directory: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(directory).context("create escrow store directory")?;
        let path = directory.join(format!("escrow-{}.json", self.escrow_id));
        let document = serde_json::to_string_pretty(self).context("serialize escrow session")?;
        std::fs::write(&path, document).context("write escrow session")?;
        Ok(path)
    }

    /// Load a persisted session, refusing unknown schemas.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).context("read escrow session")?;
        let value: serde_json::Value = serde_json::from_str(&raw).context("parse escrow session")?;
        if value.get("schema").and_then(serde_json::Value::as_str) != Some(ESCROW_SESSION_SCHEMA) {
            bail!("escrow session store has an unknown schema");
        }
        let session: Self = serde_json::from_value(value).context("decode escrow session")?;
        Ok(session)
    }
}

// ---------------------------------------------------------------------------
// Slice B — the receipt digest gate + the pay-first fee flow
// ---------------------------------------------------------------------------

/// The demo's receipt gate environment variable: real signet invoice minting
/// for arbitration fees stays OFF until this is explicitly set (honestly
/// labeled — no real funds move by default).
pub const ARBITRATION_LIVE_FEES_ENVIRONMENT_VARIABLE: &str = "OMEGA_ARBITRATION_LIVE_FEES";

/// The public-safe receipt event the digest gate re-derives from — the same
/// wire shape the platform receipts publish (the `lbr-closeout` lifecycle
/// event projection). Everything is a ref or hex id; no payment material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptEventProjection {
    pub id: String,
    pub pubkey: String,
    pub kind: u32,
    pub created_at: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl ReceiptEventProjection {
    fn validate(&self) -> Result<()> {
        validate_pubkey("receipt event id", &self.id)?;
        validate_pubkey("receipt author pubkey", &self.pubkey)?;
        if self.kind == 0 {
            bail!("receipt event kind must be positive");
        }
        if self.created_at < 0 {
            bail!("receipt event timestamp must not be negative");
        }
        if self.sig.len() != 128 || !self.sig.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("receipt event signature must be 128-char hex");
        }
        Ok(())
    }
}

/// Deterministic canonical projection of the receipt event (the demo's
/// `lbr-closeout` adaptation): fixed alphabetical key order via
/// `serde_json::Value`'s BTreeMap ordering, compact serialization, digest
/// over the exact bytes. A reader re-derives the digest and confirms it
/// matches the submitted claim — the claim is never the proof.
pub fn canonical_receipt_digest(event: &ReceiptEventProjection) -> Result<String> {
    event.validate()?;
    let value = json!({
        "content": event.content,
        "created_at": event.created_at,
        "id": event.id,
        "kind": event.kind,
        "pubkey": event.pubkey,
        "sig": event.sig,
        "tags": event.tags,
    });
    Ok(format!("{:x}", Sha256::digest(value.to_string().as_bytes())))
}

/// OMEGA-DELTA-0290 (SEC-2026-095 closure): the projection-to-wire adapter
/// for the receipt-verifier family (`immortal_client::domain::Event` — the
/// seam the receipt ledger projects from). Fails closed when the projection
/// carries a value the wire kind range cannot represent.
fn provider_wire_event(event: &ReceiptEventProjection) -> Result<immortal_client::domain::Event> {
    Ok(immortal_client::domain::Event {
        id: event.id.clone(),
        pubkey: event.pubkey.clone(),
        created_at: u64::try_from(event.created_at)
            .map_err(|_| anyhow::anyhow!("receipt event timestamp exceeds the wire range"))?,
        kind: u16::try_from(event.kind)
            .map_err(|_| anyhow::anyhow!("receipt event kind exceeds the wire kind range"))?,
        tags: event
            .tags
            .iter()
            .map(|tag| immortal_client::domain::Tag(tag.clone()))
            .collect(),
        content: event.content.clone(),
        sig: event.sig.clone(),
    })
}

/// The receipt gate: verify the provider event signature (0290), then
/// re-derive the digest from the ACTUAL receipt event and drive the
/// session's verification transition with it. Returns the reached state
/// (`VerifiedPass` releases free; `VerifiedFail` stays in limbo).
pub fn verify_receipt_claim(
    session: &mut EscrowSession,
    event: &ReceiptEventProjection,
) -> Result<EscrowState> {
    event.validate()?;
    // OMEGA-DELTA-0290 (SEC-2026-095 closure): the provider signature is
    // verified BEFORE the digest transition. Two refusal modes, both
    // fail-closed:
    // - an event signed by a non-provider pubkey is REFUSED outright (hard
    //   error; the session is untouched, the claim never drives a pass);
    // - a validly-shaped event whose signature does not verify is a FAILED
    //   verification — the session leaves the submission limbo for
    //   `VerifiedFail`, never `VerifiedPass`.
    // The check reuses the receipt-verifier family: the canonical event id
    // is re-derived from the NIP-01 serialization and the BIP-340 Schnorr
    // signature is verified against the event pubkey. The digest
    // re-derivation stays as the projection step afterwards.
    if event.pubkey != session.counterparty_pubkey {
        bail!(
            "receipt event refused: the signer is not the escrow provider \
             (OMEGA-DELTA-0290)"
        );
    }
    let wire_event = provider_wire_event(event)?;
    if wire_event.validate_crypto().is_err() {
        return session.refuse_verification();
    }
    let recomputed = canonical_receipt_digest(event)?;
    let state = session.record_verification(&recomputed)?;
    if state == EscrowState::VerifiedPass {
        // OMEGA-DELTA-0291: bind the verified event id so the automated
        // release can carry the digest+event linkage inside the hash chain.
        session.receipt_event_id = Some(event.id.clone());
    }
    Ok(state)
}

/// sha256 over the payment proof — the digest is what persists; the preimage
/// itself never enters the ledger, the session, or any log (SEC-2026-088).
pub fn fee_payment_digest(payment_proof: &str) -> Result<String> {
    if payment_proof.is_empty() {
        bail!("arbitration fee payment proof must not be empty");
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(payment_proof.as_bytes())
    ))
}

/// Append the balanced pre-paid arbitration `Fee` entry: the escalator pays
/// the platform-arbitrator, participant-to-participant (SEC-2026-085) — the
/// platform's only custody event, collected on escalation, never pooled.
/// Returns the `fee_payment_digest` the `ArbitrationRequested` entry
/// references (pay-first invariant).
pub fn record_fee_payment(
    ledger: &LedgerStore,
    session: &EscrowSession,
    payer_pubkey: &str,
    payment_proof: &str,
    now_ms: i64,
) -> Result<String> {
    validate_pubkey("fee payer pubkey", payer_pubkey)?;
    let digest = fee_payment_digest(payment_proof)?;
    let fee = session.arbitration_fee_flat_sats as i64;
    let mut draft = LedgerEntryDraft::new(
        format!("escrow:{}:arbitration-fee", session.escrow_id),
        now_ms,
        ESCROW_STRATEGY,
        LedgerEntryKind::Fee,
    );
    draft.postings = vec![
        LedgerPosting::sats(
            LedgerAccount::MarketParticipant {
                role: "requester".into(),
                participant: payer_pubkey.to_string(),
            },
            -fee,
        ),
        LedgerPosting::sats(
            LedgerAccount::MarketParticipant {
                role: "provider".into(),
                participant: session.arbitrator_pubkey.clone(),
            },
            fee,
        ),
    ];
    draft.metadata = json!({
        "schema": ESCROW_LEDGER_SCHEMA,
        "escrow_id": session.escrow_id,
        "purpose": "arbitration_fee",
        "fee_payment_digest": digest,
        "fee_amount_sats": session.arbitration_fee_flat_sats,
        "paid_by_pubkey": payer_pubkey,
    });
    ledger.append(draft).context("append arbitration Fee entry")?;
    Ok(digest)
}

/// Honest gate: real signet invoice minting for arbitration fees is disabled
/// unless the demo operator opts in explicitly. Called BEFORE any sidecar
/// contact, so the default posture cannot touch funds.
pub fn ensure_live_fees_allowed(allow_live_mint: bool) -> Result<()> {
    if !allow_live_mint {
        bail!(
            "arbitration fee minting is gated for the demo (no real signet invoice); \
             set {ARBITRATION_LIVE_FEES_ENVIRONMENT_VARIABLE}=1 to opt in"
        );
    }
    Ok(())
}

/// Convenience reader for the demo opt-in.
pub fn arbitration_live_fees_enabled() -> bool {
    std::env::var(ARBITRATION_LIVE_FEES_ENVIRONMENT_VARIABLE).as_deref() == Ok("1")
}

// ---------------------------------------------------------------------------
// Slice C — live-tip timeout observation (the sanctioned seam)
// ---------------------------------------------------------------------------

/// Pure gate the async wrapper uses (unit-testable): the HTLC window is open
/// until the observed tip reaches `timeout_at_height` — blocks, never
/// wall-clock (SEC-2026-086/087).
pub fn timeout_window_open(session: &EscrowSession, observed_height: u32) -> bool {
    u64::from(observed_height) < session.timeout_at_height
}

/// Read the observed signet tip through the sanctioned seam — the sidecar's
/// `wallet-height` probe of the waved getinfo surface (the WP-3b decision:
/// ONE tip source). Any probe failure propagates: the escrow timeout gate
/// fails closed and never falls back to wall-clock (SEC-2026-087).
pub async fn observe_wallet_height(
    supervisor: &mut sovereign_wallet::SovereignWalletSupervisor,
) -> Result<u32> {
    let result = supervisor
        .wallet_height()
        .await
        .map_err(|error| anyhow::anyhow!("observed tip unavailable — escrow timeout fails closed: {error}"))?;
    Ok(result.block_height)
}

/// Open an escrow against the live tip: the height is observed through the
/// sanctioned seam, never assumed.
pub async fn open_with_live_tip(
    ledger: &LedgerStore,
    mandates: &MandateStore,
    params: EscrowOpenParams,
    network: TradingNetwork,
    supervisor: &mut sovereign_wallet::SovereignWalletSupervisor,
    now_ms: i64,
) -> Result<EscrowSession> {
    let observed_height = observe_wallet_height(supervisor).await?;
    EscrowSession::open(ledger, mandates, params, network, observed_height, now_ms)
}

/// Timeout check + refund through the live tip. Returns `Ok(false)` while
/// the window is open (nothing settled), `Ok(true)` once the HTLC expiry was
/// observed at/after `timeout_at_height` and projected as `ArbitrationRefunded`.
pub async fn refund_on_timeout_with_live_tip(
    ledger: &LedgerStore,
    session: &mut EscrowSession,
    supervisor: &mut sovereign_wallet::SovereignWalletSupervisor,
    decided_by_pubkey: &str,
    now_ms: i64,
) -> Result<bool> {
    let observed_height = observe_wallet_height(supervisor).await?;
    if timeout_window_open(session, observed_height) {
        return Ok(false);
    }
    session.refund(
        ledger,
        decided_by_pubkey,
        "htlc_timeout",
        Some(observed_height),
        now_ms,
    )?;
    Ok(true)
}

/// The full pay-first escalation, wired end-to-end: mandate-gate the fee on
/// the sovereign-wallet venue, mint + pay the flat-fee invoice through the
/// sidecar, append the balanced `Fee` entry, then admit the human queue by
/// appending `ArbitrationRequested`. The invoice mint is GATED: without the
/// explicit opt-in this refuses before any sidecar contact (the demo proves
/// the wiring, not a real payment).
#[allow(dead_code)] // wired into the dashboard escalation seam (WP-5b)
pub async fn pay_arbitration_fee_and_request_arbitration(
    supervisor: &mut sovereign_wallet::SovereignWalletSupervisor,
    ledger: &LedgerStore,
    mandates: &MandateStore,
    session: &mut EscrowSession,
    escalator_pubkey: &str,
    idempotency_key: &str,
    allow_live_mint: bool,
    now_ms: i64,
) -> Result<()> {
    ensure_live_fees_allowed(allow_live_mint)?;
    let fee_sats = session.arbitration_fee_flat_sats;
    // The fee is a wallet payment: the sovereign-wallet venue's principal
    // mandate gates it (SEC-2026-043), separately from the escrow mandate.
    // OMEGA-DELTA-0286: the mandate instruction carries the SESSION's
    // network, so a mainnet escrow fee is gated by a
    // (sovereign-wallet, mainnet, principal) mandate; signet behavior is
    // unchanged.
    match sovereign_wallet::authorize_sovereign_spend(
        mandates,
        fee_sats,
        session.network,
        Some(escalator_pubkey),
        now_ms,
    )? {
        MandateDecision::Authorized { .. } => {}
        MandateDecision::Refused { reason, .. } => {
            bail!("arbitration fee payment refused by the wallet mandate: {reason:?}")
        }
    }
    let invoice = supervisor
        .make_invoice(fee_sats, "arbitration fee", idempotency_key)
        .await
        .map_err(|error| anyhow::anyhow!("arbitration fee invoice mint failed: {error}"))?;
    let paid = supervisor
        .pay_invoice(&invoice.invoice, idempotency_key)
        .await
        .map_err(|error| anyhow::anyhow!("arbitration fee payment failed: {error}"))?;
    let proof = paid
        .preimage
        .filter(|preimage| !preimage.is_empty())
        .context("arbitration fee payment returned no preimage proof")?;
    let digest = record_fee_payment(ledger, session, escalator_pubkey, &proof, now_ms)?;
    session.request_arbitration(ledger, escalator_pubkey, digest, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use immortal_client::market::MarketSigner;
    use serde_json::Value;

    const CUSTOMER: &str = "1100000000000000000000000000000000000000000000000000000000000000";
    const AGENT: &str = "2200000000000000000000000000000000000000000000000000000000000000";
    const ARBITRATOR: &str = "3300000000000000000000000000000000000000000000000000000000000000";
    const STRANGER: &str = "4400000000000000000000000000000000000000000000000000000000000000";
    const ESCROW_ID: &str = "escrow-demo-0001";
    const HASH_LOCK_DIGEST: &str = "ab00000000000000000000000000000000000000000000000000000000000000";
    const OBSERVED_HEIGHT: u32 = 250_000;
    const TIMEOUT_BLOCKS: u32 = 144;
    const TIMEOUT_AT: u64 = 250_144;
    const AMOUNT: u64 = 50_000;
    // OMEGA-DELTA-0294: the 1,000-sat test fee default is superseded by the
    // founder's 100-sat decision (Decision 5); the production default is
    // DEFAULT_ARBITRATION_FEE_FLAT_SATS (100), applied at the session
    // creation site when the operator does not configure a fee.
    const FEE: u64 = DEFAULT_ARBITRATION_FEE_FLAT_SATS;
    const RECEIPT_EVENT_KIND: u16 = 39_603;
    const RECEIPT_EVENT_TIME: u64 = 1_770_000_000;
    const NOW: i64 = 1_000;

    fn receipt_digest(seed: &str) -> String {
        // Deterministic synthetic digest stand-in (slice B re-derives the
        // real lbr-closeout canonical digest from the actual receipt).
        let mut hex = String::new();
        while hex.len() < 64 {
            hex.push_str(&format!("{:02x}", seed.bytes().next().unwrap_or(0)));
        }
        hex.truncate(64);
        hex
    }

    fn escrow_mandate(store: &MandateStore) {
        let candidate = trading_mandate::TradingMandate {
            venue: MKT_SWP_ESCROW_VENUE.to_string(),
            network: TradingNetwork::Signet,
            principal_pubkey: Some(CUSTOMER.to_string()),
            collateral_asset: AssetId::sats(),
            objective: "Minimal arbitration demo escrow".to_string(),
            max_venue_balance: AMOUNT,
            max_position_usd: 1,
            max_leverage: 1,
            daily_loss_stop: 1,
            max_orders_per_hour: 1,
            min_liquidation_buffer_bps: 0,
            allowed_strategies: [ESCROW_STRATEGY.to_string()].into_iter().collect(),
            review_cadence: trading_mandate::ReviewCadence::Interval { seconds: 3_600 },
            expires_at_ms: 1_000_000,
            allow_escrow: Some(true),
            max_escrow_sats: Some(AMOUNT),
            escrow_timeout_blocks: Some(TIMEOUT_BLOCKS),
            arbitration_fee_flat_sats: Some(FEE),
        };
        let proposal = store.propose(candidate).expect("proposal");
        store
            .apply_ui_approved(proposal, NOW)
            .expect("ui-approved escrow mandate");
    }

    fn params() -> EscrowOpenParams {
        EscrowOpenParams {
            escrow_id: ESCROW_ID.to_string(),
            principal_pubkey: CUSTOMER.to_string(),
            counterparty_pubkey: AGENT.to_string(),
            arbitrator_pubkey: ARBITRATOR.to_string(),
            amount_sats: AMOUNT,
            hash_lock_digest: HASH_LOCK_DIGEST.to_string(),
            // OMEGA-DELTA-0293/0294: the session values are operator-
            // configurable; the fixture sets them explicitly (the default
            // paths get their own tests).
            timeout_blocks: Some(TIMEOUT_BLOCKS),
            arbitration_fee_flat_sats: Some(FEE),
        }
    }

    // ----- OMEGA-DELTA-0290: real provider-signed receipt events -----

    /// A real BIP-340 test signer standing in for the provider.
    fn provider_key() -> MarketSigner {
        MarketSigner::from_secret_bytes([7; 32]).expect("provider test key")
    }

    fn stranger_key() -> MarketSigner {
        MarketSigner::from_secret_bytes([9; 32]).expect("stranger test key")
    }

    /// Project a signed wire event into the public-safe demo projection.
    fn projection_of(event: &immortal_client::domain::Event) -> ReceiptEventProjection {
        ReceiptEventProjection {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            kind: u32::from(event.kind),
            created_at: i64::try_from(event.created_at).expect("timestamp fits i64"),
            tags: event.tags.iter().map(|tag| tag.0.clone()).collect(),
            content: event.content.clone(),
            sig: event.sig.clone(),
        }
    }

    fn signed_provider_event(signer: &MarketSigner, content: &str) -> ReceiptEventProjection {
        projection_of(&signer.sign(
            RECEIPT_EVENT_TIME,
            RECEIPT_EVENT_KIND,
            Vec::new(),
            content.to_string(),
        ))
    }

    /// An opened session whose counterparty (provider) is the given pubkey —
    /// used by the signature-gate tests so the signer IS the provider.
    fn opened_with_provider(
        provider_pubkey: &str,
    ) -> (LedgerStore, MandateStore, EscrowSession) {
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        escrow_mandate(&mandates);
        let mut open_params = params();
        open_params.counterparty_pubkey = provider_pubkey.to_string();
        let session = EscrowSession::open(
            &ledger,
            &mandates,
            open_params,
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW,
        )
        .expect("escrow opened");
        (ledger, mandates, session)
    }

    fn opened() -> (LedgerStore, MandateStore, EscrowSession) {
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        escrow_mandate(&mandates);
        let session = EscrowSession::open(
            &ledger,
            &mandates,
            params(),
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW,
        )
        .expect("escrow opened");
        (ledger, mandates, session)
    }

    fn metadata_keys(ledger: &LedgerStore, event_id: &str) -> Vec<String> {
        ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries")
            .into_iter()
            .find(|entry| entry.event_id == event_id)
            .expect("entry")
            .metadata
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn open_is_mandate_gated_and_records_the_zero_posting_intent() {
        let (ledger, _mandates, session) = opened();
        assert_eq!(session.state, EscrowState::Created);
        assert_eq!(session.timeout_at_height, TIMEOUT_AT);
        let created = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries");
        assert_eq!(created.len(), 1);
        assert!(matches!(
            created[0].kind,
            LedgerEntryKind::EscrowCreated
        ));
        assert!(created[0].postings.is_empty());
        assert_eq!(created[0].metadata["mode"], "htlc_2of3");
        // No custody claim: the escrow venue balance never moves for the
        // unsettled principal (SEC-2026-084).
        assert_eq!(
            ledger
                .venue_balance(MKT_SWP_ESCROW_VENUE)
                .expect("balance"),
            0
        );
        ledger.verify().expect("hash chain covers the intent");
    }

    #[test]
    fn open_is_refused_without_a_principal_keyed_mandate() {
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        let error = EscrowSession::open(
            &ledger,
            &mandates,
            params(),
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW,
        )
        .expect_err("open without a mandate");
        assert!(error.to_string().contains("refused"));
        assert!(
            ledger
                .entries(&trading_ledger::LedgerQuery::default())
                .expect("entries")
                .is_empty()
        );
    }

    #[test]
    fn open_refuses_bad_inputs() {
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        escrow_mandate(&mandates);

        let mut bad = params();
        bad.principal_pubkey = STRANGER.to_string();
        assert!(
            EscrowSession::open(&ledger, &mandates, bad, TradingNetwork::Signet, OBSERVED_HEIGHT, NOW)
                .is_err(),
            "a different principal is not authorized"
        );

        let mut bad = params();
        bad.amount_sats = AMOUNT + 1;
        assert!(
            EscrowSession::open(&ledger, &mandates, bad, TradingNetwork::Signet, OBSERVED_HEIGHT, NOW)
                .is_err(),
            "over-cap escrow refused"
        );

        let mut bad = params();
        bad.hash_lock_digest = "nothex".to_string();
        assert!(EscrowSession::open(&ledger, &mandates, bad, TradingNetwork::Signet, OBSERVED_HEIGHT, NOW).is_err());

        let mut bad = params();
        bad.timeout_blocks = Some(35);
        assert!(EscrowSession::open(&ledger, &mandates, bad, TradingNetwork::Signet, OBSERVED_HEIGHT, NOW).is_err());
    }

    #[test]
    fn happy_path_releases_free_on_the_automated_pass() {
        // OMEGA-DELTA-0290/0291 (updated-with-citation): the automated
        // release requires the verified provider receipt linkage, so the
        // honest path runs through the provider-signature gate.
        let signer = provider_key();
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");
        let projection = signed_provider_event(&signer, "delivery receipt v1");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        let state = verify_receipt_claim(&mut session, &projection).expect("verification");
        assert_eq!(state, EscrowState::VerifiedPass);
        // Automated release: the customer's sign-off is the second signature;
        // the fee reroute is zero.
        session.release(&ledger, CUSTOMER, NOW + 1).expect("release");
        assert_eq!(session.state, EscrowState::Released);
        session.close().expect("close");
        assert_eq!(session.state, EscrowState::Closed);

        let entries = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries");
        assert_eq!(entries.len(), 2);
        let released = &entries[1];
        assert!(matches!(
            released.kind,
            LedgerEntryKind::ArbitrationReleased
        ));
        assert_eq!(released.postings.iter().map(|p| p.amount).sum::<i64>(), 0);
        assert_eq!(released.postings.len(), 2, "no arbitrator posting on a free release");
        assert_eq!(released.metadata["fee_rerouted_sats"], 0);
        assert_eq!(released.metadata["reason_code"], "automated_pass");
        // OMEGA-DELTA-0291: the linkage rides inside the hash chain.
        assert_eq!(
            released.metadata["receipt_event_id"],
            Value::String(projection.id.clone()),
            "the released entry carries the verified event id"
        );
        assert!(
            released.metadata.get("receipt_digest").is_some(),
            "the released entry carries the verified receipt digest"
        );
        assert_eq!(
            ledger
                .venue_balance(MKT_SWP_ESCROW_VENUE)
                .expect("balance"),
            0
        );
        ledger.verify().expect("verify");
    }

    #[test]
    fn verification_requires_a_matching_rederived_digest() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        session
            .submit_receipt(receipt_digest("delivery"))
            .expect("submit");
        // A tampered/re-derived digest that does not match the submitted
        // claim lands in VerifiedFail — never in VerifiedPass.
        let state = session
            .record_verification(&receipt_digest("tampered"))
            .expect("verification");
        assert_eq!(state, EscrowState::VerifiedFail);
        // The failed verification keeps the escrow in limbo: nothing settled.
        assert_eq!(
            ledger
                .entries(&trading_ledger::LedgerQuery::default())
                .expect("entries")
                .len(),
            1
        );
    }

    #[test]
    fn escalation_is_pay_first_and_the_human_release_reroutes_the_fee() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        session
            .submit_receipt(receipt_digest("bad-delivery"))
            .expect("submit");
        session
            .record_verification(&receipt_digest("mismatch"))
            .expect("verification");

        // Pay-first (SEC-2026-085): no valid fee payment digest, no human
        // queue. request_arbitration sets the digest from its argument, so
        // the invariant is probed by calling with an invalid proof.
        let error = {
            let mut s = session.clone();
            s.request_arbitration(&ledger, CUSTOMER, "not-a-digest", NOW + 1)
        };
        assert!(error.is_err(), "invalid fee proof refused");

        // OMEGA-DELTA-0288 (updated-with-citation): the state machine now
        // ledger-verifies the digest — the fee must be COMMITTED first, and
        // the request must reference the committed entry's digest.
        let fee_digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("committed fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, fee_digest.clone(), NOW + 1)
            .expect("pay-first arbitration request");
        assert_eq!(session.state, EscrowState::ArbitrationRequested);
        assert_eq!(session.fee_payment_digest.as_deref(), Some(fee_digest.as_str()));

        session.release(&ledger, ARBITRATOR, NOW + 2).expect("human release");
        let released = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries")
            .into_iter()
            .find(|entry| entry.event_id == format!("escrow:{ESCROW_ID}:released"))
            .expect("released entry");
        assert_eq!(released.postings.len(), 3, "fee reroute present");
        assert_eq!(released.postings.iter().map(|p| p.amount).sum::<i64>(), 0);
        let arbitrator_fee = released
            .postings
            .iter()
            .find(|p| {
                matches!(&p.account,
                    LedgerAccount::MarketParticipant { role, participant }
                        if role == "provider" && participant == ARBITRATOR)
            })
            .expect("arbitrator posting");
        assert_eq!(arbitrator_fee.amount, FEE as i64);
        assert_eq!(released.metadata["reason_code"], "human_decision");
        ledger.verify().expect("verify");
    }

    #[test]
    fn arbitration_requested_entry_is_zero_value_and_pay_first() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        // OMEGA-DELTA-0288 (updated-with-citation): the request must
        // reference a COMMITTED Fee entry's digest.
        let fee_digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("committed fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, fee_digest.clone(), NOW + 1)
            .expect("request from AwaitingDelivery");
        let requested = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries")
            .into_iter()
            .find(|entry| {
                matches!(entry.kind, LedgerEntryKind::ArbitrationRequested)
            })
            .expect("requested entry");
        assert!(requested.postings.is_empty());
        assert_eq!(requested.metadata["fee_payment_digest"], Value::String(fee_digest));
        assert_eq!(requested.metadata["fee_amount_sats"], FEE);
    }

    #[test]
    fn timeout_refund_is_gated_on_the_observed_height_and_carries_no_fee() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");

        // Before the window closes: refused, and nothing settled.
        let mut limbo = session.clone();
        limbo
            .refund(&ledger, CUSTOMER, "htlc_timeout", Some(OBSERVED_HEIGHT), NOW + 1)
            .expect_err("refund before timeout_at_height");
        assert_eq!(
            ledger
                .entries(&trading_ledger::LedgerQuery::default())
                .expect("entries")
                .len(),
            1
        );

        // At the timeout height (observed >= timeout_at_height): allowed,
        // fee-free, principal back to the customer.
        session
            .refund(&ledger, CUSTOMER, "htlc_timeout", Some(OBSERVED_HEIGHT), NOW + 1)
            .expect_err("still gated: observed 250000 < 250144");
        session
            .refund(&ledger, CUSTOMER, "htlc_timeout", Some(TIMEOUT_AT as u32), NOW + 1)
            .expect("refund at the timeout height");
        assert_eq!(session.state, EscrowState::Refunded);
        let refunded = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries")
            .into_iter()
            .find(|entry| entry.event_id == format!("escrow:{ESCROW_ID}:refunded"))
            .expect("refunded entry");
        assert_eq!(refunded.postings.len(), 2, "no fee on a timeout refund");
        assert_eq!(refunded.postings.iter().map(|p| p.amount).sum::<i64>(), 0);
        assert_eq!(refunded.metadata["fee_rerouted_sats"], 0);
        assert_eq!(refunded.metadata["reason_code"], "htlc_timeout");
        ledger.verify().expect("verify");
    }

    #[test]
    fn human_refund_reroutes_the_fee_out_of_the_refund() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        // OMEGA-DELTA-0288 (updated-with-citation): the request must
        // reference a COMMITTED Fee entry's digest.
        let fee_digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("committed fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, fee_digest, NOW + 1)
            .expect("arbitration");
        session
            .refund(&ledger, ARBITRATOR, "human_decision", None, NOW + 2)
            .expect("human refund");
        let refunded = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries")
            .into_iter()
            .find(|entry| entry.event_id == format!("escrow:{ESCROW_ID}:refunded"))
            .expect("refunded entry");
        assert_eq!(refunded.postings.len(), 3);
        assert_eq!(refunded.postings.iter().map(|p| p.amount).sum::<i64>(), 0);
        assert_eq!(refunded.metadata["fee_rerouted_sats"], FEE);
        assert_eq!(session.state, EscrowState::Refunded);
        ledger.verify().expect("verify");
    }

    #[test]
    fn illegal_transitions_are_refused() {
        // OMEGA-DELTA-0290/0291 (updated-with-citation): the honest advance
        // to VerifiedPass runs through the provider-signature gate so the
        // automated release can carry the verified linkage.
        let signer = provider_key();
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());

        // release/verify/submit from Created are all illegal.
        assert!(session.release(&ledger, CUSTOMER, NOW).is_err());
        assert!(session.record_verification(&receipt_digest("x")).is_err());
        assert!(session.submit_receipt(receipt_digest("x")).is_err());
        // request_arbitration from Created is illegal (nothing was attempted).
        assert!(
            session
                .request_arbitration(&ledger, CUSTOMER, receipt_digest("fee"), NOW)
                .is_err()
        );
        // close from Created is illegal.
        assert!(session.close().is_err());

        // Advance to a terminal state and confirm everything is sealed.
        session.await_delivery().expect("await");
        let projection = signed_provider_event(&signer, "delivery receipt v1");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        verify_receipt_claim(&mut session, &projection).expect("verify");
        session.release(&ledger, CUSTOMER, NOW + 1).expect("release");
        assert!(session.release(&ledger, CUSTOMER, NOW + 2).is_err(), "double release");
        assert!(
            session
                .refund(&ledger, CUSTOMER, "htlc_timeout", Some(TIMEOUT_AT as u32), NOW + 2)
                .is_err()
        );
        assert!(session.await_delivery().is_err());
        session.close().expect("close");
        assert!(session.close().is_err());
        assert!(session.release(&ledger, CUSTOMER, NOW + 3).is_err());
        assert!(session.await_delivery().is_err());
    }

    #[test]
    fn escrow_metadata_is_digest_only() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        // OMEGA-DELTA-0288 (updated-with-citation): the request must
        // reference a COMMITTED Fee entry's digest.
        let fee_digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("committed fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, fee_digest, NOW + 1)
            .expect("arbitration");
        for event_id in [
            format!("escrow:{ESCROW_ID}:created"),
            format!("escrow:{ESCROW_ID}:arbitration-requested"),
        ] {
            let keys = metadata_keys(&ledger, &event_id);
            assert!(
                keys.iter().all(|key| !key.to_ascii_lowercase().contains("preimage")),
                "digest-only metadata violated for {event_id}: {keys:?}"
            );
        }
    }

    #[test]
    fn session_persistence_round_trips_and_refuses_unknown_schemas() {
        let (_ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let directory = std::env::temp_dir().join(format!(
            "omega-escrow-test-{}",
            std::process::id()
        ));
        let path = session.persist(&directory).expect("persist");
        let loaded = EscrowSession::load(&path).expect("load");
        assert_eq!(loaded, session);
        assert_eq!(loaded.state, EscrowState::AwaitingDelivery);

        let mut unknown = loaded.clone();
        unknown.schema = "omega.market.escrow-session.v0".to_string();
        let bad_path = directory.join("escrow-unknown.json");
        std::fs::write(
            &bad_path,
            serde_json::to_string_pretty(&unknown).expect("serialize"),
        )
        .expect("write");
        assert!(EscrowSession::load(&bad_path).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }

    // ----- Slice B: receipt digest gate + pay-first fee flow -----

    fn receipt_event(content: &str) -> ReceiptEventProjection {
        ReceiptEventProjection {
            id: format!("{:0>64}", "aa"),
            pubkey: AGENT.to_string(),
            kind: 39603,
            created_at: 1_770_000_000,
            tags: vec![vec!["e".to_string(), format!("{:0>64}", "bb")]],
            content: content.to_string(),
            sig: format!("{:0>128}", "cc"),
        }
    }

    #[test]
    fn receipt_digest_is_deterministic_and_refuses_tampered_events() {
        let event = receipt_event("delivery receipt v1");
        let first = canonical_receipt_digest(&event).expect("digest");
        let second = canonical_receipt_digest(&event).expect("digest");
        assert_eq!(first, second, "same event bytes -> same digest");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let mut tampered = event.clone();
        tampered.content = "delivery receipt v2".to_string();
        let tampered_digest = canonical_receipt_digest(&tampered).expect("digest");
        assert_ne!(first, tampered_digest, "changed bytes -> changed digest");

        let mut bad = event;
        bad.id = "not-hex".to_string();
        assert!(canonical_receipt_digest(&bad).is_err());
    }

    #[test]
    fn verify_receipt_claim_drives_the_transition_from_the_real_projection() {
        // OMEGA-DELTA-0290 (updated-with-citation): the fixture now signs
        // with the real provider key — the honest path requires a valid
        // provider signature, and the digest still binds.
        let signer = provider_key();
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");

        let projection = signed_provider_event(&signer, "delivery receipt v1");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");

        // The honest re-derivation passes the gate.
        let state = verify_receipt_claim(&mut session, &projection).expect("verify");
        assert_eq!(state, EscrowState::VerifiedPass);
        session.release(&ledger, CUSTOMER, NOW + 1).expect("release");
        assert_eq!(session.state, EscrowState::Released);

        // A different (re-signed, tampered-content) event fails the digest
        // binding and stays in limbo.
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        let forged = signed_provider_event(&signer, "forged delivery");
        let state = verify_receipt_claim(&mut session, &forged).expect("verify");
        assert_eq!(state, EscrowState::VerifiedFail);
        assert_eq!(session.state, EscrowState::VerifiedFail);
    }

    #[test]
    fn verify_receipt_claim_refuses_a_wrong_signature_into_verified_fail_limbo() {
        // OMEGA-DELTA-0290 negative test 1: a validly-shaped event whose
        // signature does not verify is a FAILED verification — the session
        // lands in the VerifiedFail limbo, never VerifiedPass.
        let signer = provider_key();
        let (_ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");
        let mut projection = signed_provider_event(&signer, "delivery receipt v1");
        projection.sig = format!("{:0>128}", "ff");
        assert_eq!(projection.sig.len(), 128, "still well-formed shape");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        let state = verify_receipt_claim(&mut session, &projection)
            .expect("a failed verification is reported, not an error");
        assert_eq!(state, EscrowState::VerifiedFail);
        assert_eq!(session.state, EscrowState::VerifiedFail);
        assert_ne!(state, EscrowState::VerifiedPass, "never passes");
    }

    #[test]
    fn verify_receipt_claim_refuses_a_non_provider_signer() {
        // OMEGA-DELTA-0290 negative test 2: an event with a VALID signature
        // from a NON-provider pubkey is refused outright; the session is
        // untouched (still in the submission limbo).
        let provider = provider_key();
        let stranger = stranger_key();
        assert_ne!(provider.pubkey(), stranger.pubkey());
        let (_ledger, _mandates, mut session) = opened_with_provider(provider.pubkey());
        session.await_delivery().expect("await");
        let projection = signed_provider_event(&stranger, "forged provider receipt");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        let error = verify_receipt_claim(&mut session, &projection)
            .expect_err("a non-provider signer is refused");
        assert!(error.to_string().contains("not the escrow provider"));
        assert_eq!(
            session.state,
            EscrowState::ReceiptSubmitted,
            "the session is untouched by the refusal"
        );
    }

    #[test]
    fn verify_receipt_claim_passes_an_honest_signed_event_and_binds_the_digest() {
        // OMEGA-DELTA-0290 negative test 3 (honest control): a provider-
        // signed event passes and the digest binding holds.
        let signer = provider_key();
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");
        let projection = signed_provider_event(&signer, "delivery receipt v1");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed.clone()).expect("submit");
        let state = verify_receipt_claim(&mut session, &projection).expect("verify");
        assert_eq!(state, EscrowState::VerifiedPass);
        // Digest binding: the session's claim equals the canonical
        // projection digest, and the verified event id is bound for 0291.
        assert_eq!(session.receipt_digest.as_deref(), Some(claimed.as_str()));
        assert_eq!(
            session.receipt_event_id.as_deref(),
            Some(projection.id.as_str())
        );
        session.release(&ledger, CUSTOMER, NOW + 1).expect("release");
        assert_eq!(session.state, EscrowState::Released);
    }

    #[test]
    fn record_fee_payment_appends_a_balanced_fee_entry_and_persists_only_the_digest() {
        let (ledger, _mandates, session) = opened();
        let proof = "synthetic-payment-preimage-never-persisted";
        let digest =
            record_fee_payment(&ledger, &session, CUSTOMER, proof, NOW + 1).expect("fee entry");

        assert_eq!(digest, fee_payment_digest(proof).expect("digest"));
        let fee_entry = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries")
            .into_iter()
            .find(|entry| matches!(entry.kind, LedgerEntryKind::Fee))
            .expect("fee entry");
        assert_eq!(fee_entry.postings.iter().map(|p| p.amount).sum::<i64>(), 0);
        assert_eq!(fee_entry.postings.len(), 2);
        let arbitrator = fee_entry
            .postings
            .iter()
            .find(|p| {
                matches!(&p.account,
                    LedgerAccount::MarketParticipant { role, participant }
                        if role == "provider" && participant == ARBITRATOR)
            })
            .expect("arbitrator fee posting");
        assert_eq!(arbitrator.amount, FEE as i64);
        assert_eq!(fee_entry.metadata["fee_payment_digest"], Value::String(digest));
        // SEC-2026-088: the proof itself never persists — digest only.
        let keys: Vec<String> = fee_entry
            .metadata
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect();
        assert!(
            keys.iter().all(|key| !key.to_ascii_lowercase().contains("preimage")),
            "fee metadata must stay digest-only: {keys:?}"
        );
        ledger.verify().expect("verify");
    }

    #[test]
    fn pay_first_composition_links_the_fee_entry_to_the_arbitration_request() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, digest.clone(), NOW + 2)
            .expect("arbitration admitted after the fee");
        let entries = ledger
            .entries(&trading_ledger::LedgerQuery::default())
            .expect("entries");
        let fee = entries
            .iter()
            .find(|entry| matches!(entry.kind, LedgerEntryKind::Fee))
            .expect("fee entry");
        let requested = entries
            .iter()
            .find(|entry| matches!(entry.kind, LedgerEntryKind::ArbitrationRequested))
            .expect("requested entry");
        assert_eq!(
            fee.metadata["fee_payment_digest"],
            requested.metadata["fee_payment_digest"],
            "the request references the paid fee entry"
        );
        // Ledger order: the Fee entry (pay-first) precedes the request.
        assert!(fee.sequence < requested.sequence);
        ledger.verify().expect("verify");
    }

    #[test]
    fn live_fee_mint_is_gated_off_by_default() {
        let error = ensure_live_fees_allowed(false).expect_err("gated by default");
        assert!(error.to_string().contains("gated for the demo"));
        assert!(ensure_live_fees_allowed(true).is_ok());
        // The default env-gated reader is off in tests (variable unset).
        assert!(!arbitration_live_fees_enabled());
    }

    // ----- OMEGA-DELTA-0288: pay-first enforced at the state machine -----

    #[test]
    fn arbitration_refuses_a_well_formed_digest_without_a_committed_fee_entry() {
        // OMEGA-DELTA-0288 negative test 1: a well-formed fabricated digest
        // with NO committed Fee entry is refused at the state machine (the
        // old format-only gate would have passed it).
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let fabricated = receipt_digest("fabricated");
        validate_digest("fabricated probe", &fabricated)
            .expect("the fixture digest is well formed (the old gate would pass it)");
        let error = session
            .request_arbitration(&ledger, CUSTOMER, fabricated, NOW + 1)
            .expect_err("fabricated digest refused");
        assert!(error.to_string().contains("no committed Fee entry"));
        assert_eq!(
            session.state,
            EscrowState::AwaitingDelivery,
            "the session did not advance"
        );
        assert_eq!(
            ledger
                .entries(&trading_ledger::LedgerQuery::default())
                .expect("entries")
                .len(),
            1,
            "no ArbitrationRequested entry was appended"
        );
    }

    #[test]
    fn arbitration_refuses_a_fee_entry_bound_to_a_different_escrow() {
        // OMEGA-DELTA-0288 negative test 2 (forged binding): a real Fee
        // entry carrying the digest but bound to a DIFFERENT escrow_id is
        // refused.
        let (ledger, mandates, mut session_a) = opened();
        let mut params_b = params();
        params_b.escrow_id = "escrow-demo-0002".to_string();
        let mut session_b = EscrowSession::open(
            &ledger,
            &mandates,
            params_b,
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW,
        )
        .expect("escrow b opened");
        let digest = record_fee_payment(&ledger, &session_b, CUSTOMER, "shared-proof", NOW + 1)
            .expect("a real committed Fee entry — for escrow b");
        session_a.await_delivery().expect("await");
        let error = session_a
            .request_arbitration(&ledger, CUSTOMER, digest.clone(), NOW + 2)
            .expect_err("a Fee entry bound to a different escrow is refused");
        assert!(error.to_string().contains("no committed Fee entry"));
        assert_eq!(session_a.state, EscrowState::AwaitingDelivery);
        // The honest control: escrow b IS admitted by its own binding — the
        // refusal is about the escrow binding, not the digest itself.
        session_b.await_delivery().expect("await");
        session_b
            .request_arbitration(&ledger, CUSTOMER, digest, NOW + 2)
            .expect("escrow b is admitted by its own Fee entry");
        assert_eq!(session_b.state, EscrowState::ArbitrationRequested);
    }

    // ----- OMEGA-DELTA-0289: decided_by bound per door -----

    #[test]
    fn release_refuses_a_stranger_pubkey_on_the_human_door() {
        // OMEGA-DELTA-0289 negative test 1: a well-formed stranger key is
        // refused on the human door (format validation alone no longer
        // admits a decision).
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("committed fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, digest, NOW + 2)
            .expect("arbitration requested");
        let error = session
            .release(&ledger, STRANGER, NOW + 3)
            .expect_err("stranger pubkey refused on the human door");
        assert!(error.to_string().contains("OMEGA-DELTA-0289"));
        assert_eq!(session.state, EscrowState::ArbitrationRequested);
        assert!(
            ledger
                .entries(&trading_ledger::LedgerQuery::default())
                .expect("entries")
                .iter()
                .all(|entry| !matches!(entry.kind, LedgerEntryKind::ArbitrationReleased)),
            "nothing settled"
        );
    }

    #[test]
    fn release_refuses_the_arbitrator_on_the_automated_door() {
        // OMEGA-DELTA-0289 negative test 2: the arbitrator key is refused on
        // the automated door (the principal's sign-off is required there).
        let signer = provider_key();
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");
        let projection = signed_provider_event(&signer, "delivery receipt v1");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        verify_receipt_claim(&mut session, &projection).expect("verify");
        assert_eq!(session.state, EscrowState::VerifiedPass);
        let error = session
            .release(&ledger, ARBITRATOR, NOW + 1)
            .expect_err("arbitrator pubkey refused on the automated door");
        assert!(error.to_string().contains("OMEGA-DELTA-0289"));
        assert_eq!(session.state, EscrowState::VerifiedPass);
    }

    #[test]
    fn timeout_refund_refuses_a_caller_invented_reason_code() {
        // OMEGA-DELTA-0289 negative test 3: the timeout door's reason_code
        // comes from the fixed set — no caller free text.
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let error = session
            .refund(
                &ledger,
                CUSTOMER,
                "operator_says_so",
                Some(TIMEOUT_AT as u32),
                NOW + 1,
            )
            .expect_err("caller-invented reason code refused");
        assert!(error.to_string().contains("OMEGA-DELTA-0289"));
        assert_eq!(session.state, EscrowState::AwaitingDelivery);
    }

    #[test]
    fn refund_doors_bind_decided_by_and_the_honest_doors_pass() {
        // OMEGA-DELTA-0289 negative test 4 (the honest controls): each door
        // passes with its bound party and refuses the others.
        // Human refund door: the arbitrator decides.
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let digest = record_fee_payment(&ledger, &session, CUSTOMER, "proof-1", NOW + 1)
            .expect("committed fee entry");
        session
            .request_arbitration(&ledger, CUSTOMER, digest, NOW + 2)
            .expect("arbitration requested");
        let error = session
            .refund(&ledger, STRANGER, "human_decision", None, NOW + 3)
            .expect_err("stranger refused on the human refund door");
        assert!(error.to_string().contains("OMEGA-DELTA-0289"));
        session
            .refund(&ledger, ARBITRATOR, "human_decision", None, NOW + 3)
            .expect("honest human refund by the arbitrator");
        assert_eq!(session.state, EscrowState::Refunded);
        // Timeout door: the principal claims the expiry.
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let error = session
            .refund(&ledger, ARBITRATOR, "htlc_timeout", Some(TIMEOUT_AT as u32), NOW + 3)
            .expect_err("arbitrator refused on the timeout door");
        assert!(error.to_string().contains("OMEGA-DELTA-0289"));
        session
            .refund(&ledger, CUSTOMER, "htlc_timeout", Some(TIMEOUT_AT as u32), NOW + 4)
            .expect("honest timeout refund by the principal");
        assert_eq!(session.state, EscrowState::Refunded);
        ledger.verify().expect("hash chain holds");
    }

    // ----- OMEGA-DELTA-0291: the hash-chained receipt linkage -----

    #[test]
    fn automated_release_refuses_without_the_verified_receipt_linkage() {
        // OMEGA-DELTA-0291 negative test (session-level, fail-closed): a
        // VerifiedPass session whose verified event id is missing (e.g. a
        // tampered session-JSON projection) cannot release — the linkage is
        // required evidence, and the ledger-side validate rule backstops it.
        let signer = provider_key();
        let (ledger, _mandates, mut session) = opened_with_provider(signer.pubkey());
        session.await_delivery().expect("await");
        let projection = signed_provider_event(&signer, "delivery receipt v1");
        let claimed = canonical_receipt_digest(&projection).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        verify_receipt_claim(&mut session, &projection).expect("verify");
        session.receipt_event_id = None;
        let error = session
            .release(&ledger, CUSTOMER, NOW + 1)
            .expect_err("release without the verified linkage refused");
        assert!(error.to_string().contains("OMEGA-DELTA-0291"));
        assert_eq!(session.state, EscrowState::VerifiedPass, "nothing settled");
        assert!(
            ledger
                .entries(&trading_ledger::LedgerQuery::default())
                .expect("entries")
                .iter()
                .all(|entry| !matches!(entry.kind, LedgerEntryKind::ArbitrationReleased)),
            "no Released entry entered the hash chain"
        );
    }

    // ----- OMEGA-DELTA-0293: operator-configurable timeout window -----

    #[test]
    fn escrow_open_applies_the_default_timeout_when_unspecified() {
        // OMEGA-DELTA-0293 negative test (default control): an unspecified
        // session timeout resolves to 144 blocks at the creation site.
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        escrow_mandate(&mandates);
        let mut open_params = params();
        open_params.timeout_blocks = None;
        let session = EscrowSession::open(
            &ledger,
            &mandates,
            open_params,
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW,
        )
        .expect("opened");
        assert_eq!(session.timeout_blocks, DEFAULT_ESCROW_TIMEOUT_BLOCKS);
        assert_eq!(session.timeout_blocks, 144, "the 144 default (Decision 6)");
        assert_eq!(
            session.timeout_at_height,
            u64::from(OBSERVED_HEIGHT) + u64::from(DEFAULT_ESCROW_TIMEOUT_BLOCKS)
        );
    }

    #[test]
    fn escrow_open_refuses_out_of_range_timeout_overrides_and_names_blocks() {
        // OMEGA-DELTA-0293 negative test: out-of-range session overrides
        // (0/35/433) are refused; 36/432 are accepted; the wording is
        // network-agnostic ("blocks", never "signet blocks").
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        escrow_mandate(&mandates);
        for bad in [0_u32, 35, 433] {
            let mut open_params = params();
            open_params.timeout_blocks = Some(bad);
            let error = EscrowSession::open(
                &ledger,
                &mandates,
                open_params,
                TradingNetwork::Signet,
                OBSERVED_HEIGHT,
                NOW,
            )
            .expect_err("out-of-range session override refused");
            let message = error.to_string();
            assert!(message.contains("blocks"), "names blocks: {message}");
            assert!(
                !message.contains("signet blocks"),
                "OMEGA-DELTA-0293: network-agnostic wording: {message}"
            );
        }
        for good in [36_u32, 432] {
            let mut open_params = params();
            open_params.timeout_blocks = Some(good);
            let ledger = LedgerStore::in_memory().expect("ledger");
            let session = EscrowSession::open(
                &ledger,
                &mandates,
                open_params,
                TradingNetwork::Signet,
                OBSERVED_HEIGHT,
                NOW,
            )
            .expect("in-range session override accepted");
            assert_eq!(session.timeout_blocks, good);
        }
    }

    // ----- OMEGA-DELTA-0294: the 100-sat fee default -----

    #[test]
    fn escrow_open_applies_the_100_sat_fee_default_when_unspecified() {
        // OMEGA-DELTA-0294 negative test (default control): an unspecified
        // session fee resolves to the 100-sat default at the creation site;
        // an explicit zero fee is still refused.
        let ledger = LedgerStore::in_memory().expect("ledger");
        let mandates = MandateStore::in_memory().expect("mandates");
        escrow_mandate(&mandates);
        let mut open_params = params();
        open_params.arbitration_fee_flat_sats = None;
        let session = EscrowSession::open(
            &ledger,
            &mandates,
            open_params,
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW,
        )
        .expect("opened");
        assert_eq!(
            session.arbitration_fee_flat_sats,
            DEFAULT_ARBITRATION_FEE_FLAT_SATS
        );
        assert_eq!(
            session.arbitration_fee_flat_sats, 100,
            "the 100-sat default (Decision 5)"
        );
        let mut zero = params();
        zero.arbitration_fee_flat_sats = Some(0);
        assert!(EscrowSession::open(
            &ledger,
            &mandates,
            zero,
            TradingNetwork::Signet,
            OBSERVED_HEIGHT,
            NOW
        )
        .is_err());
    }

    // ----- Slice C: live-tip timeout observation -----

    #[test]
    fn timeout_window_gate_is_block_height_only() {
        let (_ledger, _mandates, session) = opened();
        assert!(timeout_window_open(&session, OBSERVED_HEIGHT), "window open before the timeout height");
        assert!(!timeout_window_open(&session, TIMEOUT_AT as u32), "window closed at the timeout height");
        assert!(!timeout_window_open(&session, TIMEOUT_AT as u32 + 5), "window closed after the timeout height");
    }
}
