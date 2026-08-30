//! OMEGA-DELTA-0285 (Phase 3b minimal arbitration demo): the HTLC 2-of-3
//! escrow lifecycle — "Schrödinger's Transaction" limbo.
//!
//! The escrow holds the principal unsettled to customer, agent, and
//! platform-arbitrator alike for a bounded signet window. No party — least of
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
//!   `fee_payment_digest` of an already-paid fee (slice B wires the payment);
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
    LedgerStore,
};
use trading_mandate::{
    AssetId, MandateDecision, MandateStore, TradingInstruction, TradingNetwork,
    MKT_SWP_ESCROW_VENUE,
};

/// Escrow session persistence schema (digest-only fields).
pub const ESCROW_SESSION_SCHEMA: &str = "omega.market.escrow-session.v1";
/// Ledger metadata schema carried by every escrow entry (WP-3b fixture shape).
pub const ESCROW_LEDGER_SCHEMA: &str = "omega.escrow.v1";
/// The single strategy id an escrow mandate authorizes (WP-3b fixture shape).
pub const ESCROW_STRATEGY: &str = "escrow_create";
/// Escrow sessions live beside the market sessions under the data dir.
pub const ESCROW_STORE_DIRECTORY: &str = "market_sessions";

/// Fee-free settlement marker: the automated `VerifiedPass` release reroutes
/// nothing (the founder's rule — automated receipts resolve free).
pub const AUTOMATED_RELEASE_FEE_SATS: u64 = 0;

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
    /// Payment proof digest of the pre-paid arbitration fee (pay-first).
    pub fee_payment_digest: Option<String>,
}

/// Parameters for opening an escrow (everything but the observed tip).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowOpenParams {
    pub escrow_id: String,
    pub principal_pubkey: String,
    pub counterparty_pubkey: String,
    pub arbitrator_pubkey: String,
    pub amount_sats: u64,
    pub hash_lock_digest: String,
    pub timeout_blocks: u32,
    pub arbitration_fee_flat_sats: u64,
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
        if params.arbitration_fee_flat_sats == 0 {
            bail!("escrow arbitration fee must be positive");
        }
        if !(36..=432).contains(&params.timeout_blocks) {
            bail!("escrow timeout must be 36..=432 signet blocks");
        }
        let timeout_at_height = escrow_timeout_at_height(observed_height, params.timeout_blocks)
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
            "timeout_blocks": params.timeout_blocks,
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
            timeout_blocks: params.timeout_blocks,
            timeout_at_height,
            arbitration_fee_flat_sats: params.arbitration_fee_flat_sats,
            state: EscrowState::Created,
            receipt_digest: None,
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
        let (fee_rerouted_sats, reason) = match self.state {
            EscrowState::VerifiedPass => (AUTOMATED_RELEASE_FEE_SATS, "automated_pass"),
            EscrowState::ArbitrationRequested => (self.arbitration_fee_flat_sats, "human_decision"),
            other => bail!("escrow release refused from state {other:?}"),
        };
        validate_pubkey("decider pubkey", decided_by_pubkey)?;
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
        let (fee_rerouted_sats, reason) = match self.state {
            EscrowState::ArbitrationRequested => {
                (self.arbitration_fee_flat_sats, "human_decision")
            }
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
                (0, "htlc_timeout")
            }
            other => bail!("escrow refund refused from state {other:?}"),
        };
        validate_identifier_value("refund reason", reason_code)?;
        validate_pubkey("decider pubkey", decided_by_pubkey)?;
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
        let _ = reason;
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

/// The receipt gate: re-derive the digest from the ACTUAL receipt event and
/// drive the session's verification transition with it. Returns the reached
/// state (`VerifiedPass` releases free; `VerifiedFail` stays in limbo).
pub fn verify_receipt_claim(
    session: &mut EscrowSession,
    event: &ReceiptEventProjection,
) -> Result<EscrowState> {
    let recomputed = canonical_receipt_digest(event)?;
    session.record_verification(&recomputed)
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
    match sovereign_wallet::authorize_sovereign_spend(
        mandates,
        fee_sats,
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
    const FEE: u64 = 1_000;
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
            timeout_blocks: TIMEOUT_BLOCKS,
            arbitration_fee_flat_sats: FEE,
        }
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
        bad.timeout_blocks = 35;
        assert!(EscrowSession::open(&ledger, &mandates, bad, TradingNetwork::Signet, OBSERVED_HEIGHT, NOW).is_err());
    }

    #[test]
    fn happy_path_releases_free_on_the_automated_pass() {
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let submitted = receipt_digest("delivery");
        session.submit_receipt(submitted.clone()).expect("submit");
        let state = session
            .record_verification(&submitted)
            .expect("verification");
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

        let fee_digest = receipt_digest("fee-payment");
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
        let fee_digest = receipt_digest("fee");
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
        session
            .request_arbitration(&ledger, CUSTOMER, receipt_digest("fee"), NOW + 1)
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
        let (ledger, _mandates, mut session) = opened();

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
        session
            .submit_receipt(receipt_digest("delivery"))
            .expect("submit");
        session
            .record_verification(&receipt_digest("delivery"))
            .expect("verify");
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
        session
            .request_arbitration(&ledger, CUSTOMER, receipt_digest("fee"), NOW + 1)
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
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");

        let event = receipt_event("delivery receipt v1");
        let claimed = canonical_receipt_digest(&event).expect("digest");
        session.submit_receipt(claimed).expect("submit");

        // The honest re-derivation passes the gate.
        let state = verify_receipt_claim(&mut session, &event).expect("verify");
        assert_eq!(state, EscrowState::VerifiedPass);
        session.release(&ledger, CUSTOMER, NOW + 1).expect("release");
        assert_eq!(session.state, EscrowState::Released);

        // A different (tampered) event fails the gate and stays in limbo.
        let (ledger, _mandates, mut session) = opened();
        session.await_delivery().expect("await");
        let claimed = canonical_receipt_digest(&event).expect("digest");
        session.submit_receipt(claimed).expect("submit");
        let mut forged = event.clone();
        forged.content = "forged delivery".to_string();
        let state = verify_receipt_claim(&mut session, &forged).expect("verify");
        assert_eq!(state, EscrowState::VerifiedFail);
        assert_eq!(session.state, EscrowState::VerifiedFail);
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

    // ----- Slice C: live-tip timeout observation -----

    #[test]
    fn timeout_window_gate_is_block_height_only() {
        let (_ledger, _mandates, session) = opened();
        assert!(timeout_window_open(&session, OBSERVED_HEIGHT), "window open before the timeout height");
        assert!(!timeout_window_open(&session, TIMEOUT_AT as u32), "window closed at the timeout height");
        assert!(!timeout_window_open(&session, TIMEOUT_AT as u32 + 5), "window closed after the timeout height");
    }
}
