//! NIP-AC authority projection (WP-12; OMEGA-DELTA-0302; WP-11 design note
//! §2-§5, §6, §7, §10-§13).
//!
//! The projection CONSTRUCTS, SIGNS, and (when a delivery sink accepts)
//! EMITS signed Nostr events in the satnam-v0.2 NIP-AC schema at four
//! moments where the LOCAL authority layer has already decided. It is a
//! portable-proof layer, never a second authority: the LedgerStore and the
//! MandateStore remain the only ledger and the only spend-authorization
//! gate (founder decision 3A), and every emission site sits AFTER the local
//! decision (founder decision 2A kind policy; OMEGA-DELTA-0302's four-part
//! check enforces the ordering, the flag default, the read-only structure,
//! and the kind policy).
//!
//! # The four emission sites (design note §2-§5)
//!
//! 1. **Envelope (39242) at mandate approval** — emitted WITH the widening
//!    door's approval, never instead of it. The site is
//!    [`emit_envelope_for_approved_mandate`], fed by
//!    [`observe_approved_mandate`]: a read-only observation of the store's
//!    own approval revision (the store's append-only history records the
//!    approval digest of the proposal its single widening door applied).
//!    The projection is a read-only observer: it takes `&MandateStore`
//!    only, calls only read methods, and never alters the widening door
//!    (OMEGA-DELTA-0245 freezes the store's public-method set and the
//!    widening-door caller allowlist; this module adds no store method and
//!    calls no door).
//! 2. **Spend authorization (39243) after the supervisor choke point** —
//!    emitted only after `authorize_sovereign_spend` returned
//!    `MandateDecision::Authorized` AND the payment proceeded.
//!    [`spend_authorization_after_decision`] accepts the gate's decision BY
//!    REFERENCE and refuses to build the event input from a `Refused`
//!    decision, so a 39243 can never exist for a spend the local authority
//!    refused (threat-model §13.1). Wired at the L-402 redemption
//!    (`l402::pay_l402_challenge`) and the escrow arbitration-fee
//!    composition (`market_ui` `pay_arbitration_fee_and_request_arbitration`).
//! 3. **Settlement receipt (39244) per settled engagement** — the L-402
//!    paid redemption (preimage proof returned) or the escrow fee actually
//!    paid (the balanced `Fee` ledger entry's `fee_payment_digest`).
//!    [`settlement_after_settled_pay`] refuses to build the event input
//!    without a real settled amount and a 64-hex digest completion proof —
//!    no invented values (honesty law; SEC-2026-088 digest-only).
//! 4. **Revocation (1985) at mandate revocation** — a NIP-32 label event
//!    carrying the "revoked" label, emitted after the store's revocation
//!    path (`MandateStore::revoke`, the store owns revocation) recorded the
//!    `Revocation` revision. [`observe_revoked_mandate`] reads that
//!    revision; [`emit_revocation_for_revoked_mandate`] emits the notice.
//!    The local authority changed FIRST; the event is the portable notice.
//!
//! # Inbound boundary (threat-model §13.2 — binding)
//!
//! Received NIP-AC events are DISPLAY-ONLY in Omega. No code path in this
//! module (or anywhere in the projection) treats an inbound NIP-AC event as
//! local authority: nothing parsed from the wire grants, widens,
//! authorizes, settles, or revokes anything. Replay of a captured 39243
//! grants nothing locally. Any future inbound feature is separately
//! founder-gated.
//!
//! # Kind policy (founder decision 2A — binding)
//!
//! The projection emits ONLY 39242 (envelope), 39243 (spend authorization),
//! 39244 (settlement receipt), and 1985 (revocation label). The MKT-SWP
//! 39610/39603 family stays RESERVED for escrow arbitration settlement; the
//! agent-credit economy speaks NIP-AC. The single signing choke point
//! ([`NipacProjection::emit_signed_event`]) re-checks
//! [`enforce_kind_policy`] before signing, so no caller can emit any other
//! kind through the projection (negative-tested for 39603/39610).
//!
//! # Escrow-receipt bidirectional mapping note (design note §6 — shipped)
//!
//! 1. A satnam reader encountering an Omega 39603 escrow receipt: it is NOT
//!    a 39244 settlement receipt; it references an MKT-SWP escrow session
//!    (`escrow:<id>` event-id grammar), carries the arbitrator as fee
//!    beneficiary, and its verification is the 0290 signature gate. A 39244
//!    receipt never adjudicates anything.
//! 2. An Omega reader encountering a satnam 39244: it is a credit-
//!    settlement receipt for an envelope; it maps to no Omega escrow
//!    session; its `envelope_id` matches the Omega §2 envelope only if the
//!    mandate is Omega-originated.
//! 3. The bridge: both receipt families reference the same underlying
//!    mandate/envelope id when the engagement is Omega-mandated, so
//!    correlation is BY ENVELOPE/MANDATE ID, never by kind equivalence.
//!    Omega also emits no NIP-AC 39240/39241 (intent/offer): an Omega
//!    envelope is self-originated — satnam readers should not wait for
//!    intent/offer events that will never come (`offer_id` carries the
//!    local proposal identity, the store-recorded approval digest).
//!
//! # Field-mapping decisions recorded at implementation (design §2-§5)
//!
//! - **Mandate identity (`d` tag / `envelope_id`)**: the MandateStore
//!   assigns no id; the stable store-recorded identity of an approved
//!   mandate is the `approval_digest` on its approval revision
//!   (`MandateRevision.approval_digest`, the `proposal_digest` sha256 hex
//!   the single widening door recorded). The envelope id is
//!   `omega-mandate-<approval_digest>` ([`envelope_id_for`]) — stable
//!   (append-only history), unique per applied proposal, re-derivable
//!   locally. `offer_id` carries the raw digest.
//! - **Approver/governor identity**: the governor signs with the
//!   projection's identity seam — the sidecar-sovereign identity (the
//!   BIP-39/NIP-06 vault identity, OMEGA-DELTA-0284, profile id
//!   `satnam.v2.nip06.v1`, derivation path `m/44'/1237'/0'/0/0`). Today the
//!   mandate principal and the operator identity are the same derived
//!   identity (the New-Auth flow keys the mandate to the vault identity's
//!   pubkey); the mapping note states this so a satnam reader knows
//!   governor == agent on Omega-emitted envelopes until a separate operator
//!   identity exists (founder-visible, revisitable at activation).
//! - **`purpose` (39243)**: digest-based per the P10 content-free rule —
//!   `sovereign-wallet:<lane>:<payment-hash>` where lane is
//!   `l402-redemption` / `escrow-arbitration-fee` / `wallet-payment` and
//!   the payment hash is the invoice's sha256 payment hash (already a
//!   digest). No free text, no content-bearing data; a missing payment
//!   hash fails the emission honestly rather than composing free text.
//! - **L-402 settled amount (39244)**: the supervisor client's `PayResult`
//!   actual settled outflow (`actual_amount_sat`, the loss-rule's actual
//!   side); when the sidecar did not report a parseable settled amount the
//!   emission FAILS honestly — the quoted amount is never substituted.
//!   The completion proof is the payment hash (sha256(preimage) per the
//!   gateway's redemption verification; the preimage itself never appears
//!   — SEC-2026-088 inheritance).
//! - **`task_completion_score` / `reputation_delta` / `sig4sats_proof`**:
//!   omitted from Omega-emitted receipts (no Omega scoring semantics;
//!   Sig4Sats deferred Phase 3b) — setting them would invent data. The
//!   `score` TAG is likewise omitted. `has_performance_bond: false` per
//!   the design's honest default.
//! - **`allowed_mints`**: omitted (empty = all allowed in satnam's schema;
//!   Omega settles over Lightning, not Cashu mints, in this phase).
//! - **`recipient` (39243)**: omitted rather than invented — the payee
//!   endpoint is not known to the wired callers.
//! - **`scope_constraints_hash`**: sha256 over the mandate's scope tuple
//!   with the canonical serialization
//!   `venue ␟ network-label ␟ sorted-strategies ␟ principal-or-empty`
//!   joined by U+001F (unit separator); network label is
//!   `signet`/`testnet`/`mainnet` (serde snake_case form); see
//!   [`scope_constraints_hash`].
//! - **Denomination**: sats everywhere (design §7; P9) — `max_sats`,
//!   `amount_sats`, `total_sats_spent` are sats; `expires_at` converts the
//!   mandate's Unix milliseconds to Unix seconds (the conversion is
//!   recorded here per the mapping note).
//!
//! # Flag plan (design §11) and failure posture
//!
//! `OMEGA_NIPAC_PROJECTION=1` enables emission; the default is OFF in every
//! environment and nothing self-enables (the founder flips it at
//! activation). When OFF the module is inert: no event construction, no
//! signing, no delivery attempt. When ON but the identity seam or the relay
//! delivery sink is unavailable, emissions fail closed into the honest
//! [`NipacEmissionOutcome::Failed`] state (retryable where re-attempting is
//! meaningful) and the LOCAL authority is unaffected in every case: every
//! emission returns an outcome the caller logs, never an error that can
//! alter the payment/settlement result.
//!
//! # Relay target (configuration only)
//!
//! The relay target is configuration (`OMEGA_NIPAC_RELAY_URL`), never
//! committed credentials; the URL itself is [REQUIRES VERIFICATION]
//! founder-held at activation. WP-12 wires no transport: the production
//! sink ([`UnconfiguredRelaySink`]) refuses delivery with a named reason,
//! so a flag-ON run without activation wiring reports an honest retryable
//! failure after local construction — nothing leaves the machine.

use std::sync::Arc;

use immortal_client::domain::{Event, Tag};
use immortal_client::market::MarketSigner;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use trading_mandate::{MandateDecision, MandateRevisionKind, MandateStore, TradingMandate, TradingNetwork};

/// The NIP-AC projection flag (design §11; the WP-11 flag plan; the WP-7
/// operator surface renders this exact name's state). Default OFF; the
/// enabled value is exactly "1".
pub const NIPAC_PROJECTION_ENVIRONMENT_VARIABLE: &str = "OMEGA_NIPAC_PROJECTION";
/// The relay target configuration variable (configuration only — never
/// credentials; the URL is [REQUIRES VERIFICATION] founder-held at
/// activation). Unset in every environment until activation.
pub const NIPAC_RELAY_URL_ENVIRONMENT_VARIABLE: &str = "OMEGA_NIPAC_RELAY_URL";
/// The only enabled value of [`NIPAC_PROJECTION_ENVIRONMENT_VARIABLE`].
pub const NIPAC_ENABLED_VALUE: &str = "1";

/// Kind 39242 — credit envelope (mandate approval).
pub const KIND_ENVELOPE: u16 = 39_242;
/// Kind 39243 — spend authorization (after the local gate authorizes).
pub const KIND_SPEND_AUTHORIZATION: u16 = 39_243;
/// Kind 39244 — settlement receipt (per settled engagement).
pub const KIND_SETTLEMENT_RECEIPT: u16 = 39_244;
/// Kind 1985 — NIP-32 revocation label.
pub const KIND_REVOCATION: u16 = 1_985;

/// The closed kind set the projection may emit (the 2A kind policy).
pub const NIPAC_EMITTABLE_KINDS: [u16; 4] = [
    KIND_ENVELOPE,
    KIND_SPEND_AUTHORIZATION,
    KIND_SETTLEMENT_RECEIPT,
    KIND_REVOCATION,
];

/// Prefix of the envelope id (`d` tag / `envelope_id` references): the
/// mandate's store-recorded approval digest.
pub const ENVELOPE_ID_PREFIX: &str = "omega-mandate-";
/// NIP-32 label namespace for the revocation label.
pub const LABEL_NAMESPACE: &str = "omega-nipac-envelope";
/// The revocation label value (satnam treats a 1985 label event carrying
/// "revoked" as the revocation signal).
pub const REVOCATION_LABEL: &str = "revoked";
/// The only rail in this phase (Cashu is not an Omega rail).
pub const RAIL_LIGHTNING: &str = "lightning";

/// The purpose lanes (design §3): call-site category, digest-composed.
pub const LANE_L402_REDEMPTION: &str = "l402-redemption";
pub const LANE_ESCROW_ARBITRATION_FEE: &str = "escrow-arbitration-fee";
pub const LANE_WALLET_PAYMENT: &str = "wallet-payment";

/// The closed NIP-AC kind set as a type: every emitter reaches signing
/// through a `NipacEventKind`, so the compiler-level surface only admits
/// the four policy kinds. [`enforce_kind_policy`] is the runtime gate for
/// the `u16`-shaped path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NipacEventKind {
    Envelope,
    SpendAuthorization,
    SettlementReceipt,
    Revocation,
}

impl NipacEventKind {
    /// The Nostr kind number.
    pub fn kind(self) -> u16 {
        match self {
            Self::Envelope => KIND_ENVELOPE,
            Self::SpendAuthorization => KIND_SPEND_AUTHORIZATION,
            Self::SettlementReceipt => KIND_SETTLEMENT_RECEIPT,
            Self::Revocation => KIND_REVOCATION,
        }
    }

    /// The closed mapping from a kind number to the policy set: 39603,
    /// 39610, and every other kind are `None` (refused).
    pub fn from_kind(kind: u16) -> Option<Self> {
        match kind {
            KIND_ENVELOPE => Some(Self::Envelope),
            KIND_SPEND_AUTHORIZATION => Some(Self::SpendAuthorization),
            KIND_SETTLEMENT_RECEIPT => Some(Self::SettlementReceipt),
            KIND_REVOCATION => Some(Self::Revocation),
            _ => None,
        }
    }
}

/// The 2A kind policy, enforced at the projection's single signing choke
/// point: ONLY 39242/39243/39244/1985 pass; 39603/39610 (the MKT-SWP
/// escrow reservation) and everything else are refused with a named reason.
pub fn enforce_kind_policy(kind: u16) -> Result<NipacEventKind, String> {
    NipacEventKind::from_kind(kind).ok_or_else(|| {
        format!(
            "kind {kind} is refused by the NIP-AC projection kind policy \
             (only {NIPAC_EMITTABLE_KINDS:?} are emittable; the MKT-SWP \
             39610/39603 family stays reserved for escrow arbitration \
             settlement — founder decision 2A)"
        )
    })
}

/// The outcome of one emission attempt. Never an error that can alter the
/// local authority result: callers log it and move on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NipacEmissionOutcome {
    /// The event was constructed, kind-policy-checked, signed, canonical-id
    /// validated, and accepted by the delivery sink.
    Emitted { kind: u16, event_id: String },
    /// The flag is OFF (the default): the module is inert — no event was
    /// constructed, signed, or delivered.
    Disabled,
    /// The flag is ON but the emission failed. `retryable` marks whether a
    /// later attempt is meaningful (relay/identity availability) versus a
    /// permanent input problem (a refused decision, a missing digest).
    Failed { reason: String, retryable: bool },
}

impl NipacEmissionOutcome {
    /// True only when the event exists and was accepted for delivery.
    pub fn is_emitted(&self) -> bool {
        matches!(self, Self::Emitted { .. })
    }
}

/// The signing seam. The production identity at activation is the
/// sidecar-sovereign BIP-39/NIP-06 identity (OMEGA-DELTA-0284; profile id
/// `satnam.v2.nip06.v1`): its secret lives in the sidecar vault / the
/// omega_identity import path and is bridged in as 32 secret bytes — never
/// logged, never committed. Tests inject a deterministic key.
pub trait NipacEventSigner {
    /// The signer's Nostr pubkey hex (64-hex) — the governor identity.
    fn pubkey_hex(&self) -> &str;
    /// Sign one event (BIP-340 schnorr over the canonical id).
    fn sign_event(
        &self,
        created_at: u64,
        kind: u16,
        tags: Vec<Tag>,
        content: String,
    ) -> Result<Event, String>;
}

/// The immortal_client signing family behind the seam: BIP-340 schnorr via
/// `MarketSigner`, with canonical-id re-derivation validation after every
/// signature (the signed event's id must re-derive from its exact NIP-01
/// preimage and its schnorr signature must verify — fail-closed on either).
#[derive(Clone)]
pub struct ImmortalNipacSigner {
    signer: MarketSigner,
    pubkey_hex: String,
}

impl ImmortalNipacSigner {
    /// Build from 32 secret bytes (the bridged sidecar-identity material).
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        let signer = MarketSigner::from_secret_bytes(bytes)?;
        Ok(Self {
            pubkey_hex: signer.pubkey().to_owned(),
            signer,
        })
    }
}

impl NipacEventSigner for ImmortalNipacSigner {
    fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    fn sign_event(
        &self,
        created_at: u64,
        kind: u16,
        tags: Vec<Tag>,
        content: String,
    ) -> Result<Event, String> {
        let event = self
            .signer
            .sign(created_at, kind, tags, content);
        // Canonical-id re-derivation validation (fail-closed): structure +
        // id re-derivation + BIP-340 verification must all pass.
        event
            .validate_structure()
            .and_then(|()| event.validate_crypto())
            .map_err(|error| format!("the signed NIP-AC event failed validation: {error}"))?;
        Ok(event)
    }
}

/// The delivery sink seam. WP-12 wires no relay transport: production gets
/// [`UnconfiguredRelaySink`] until activation (the founder-held relay URL
/// plus credentials never touch this tree).
pub trait NipacDeliverySink {
    fn deliver(&self, event: &Event) -> Result<(), String>;
}

/// The production sink until activation: refuses every delivery with the
/// named configuration reason (honest retryable failure — nothing leaves
/// the machine). The relay configuration state is reported by
/// [`NipacProjection::relay_configured`] from the projection's own
/// snapshot; the sink itself stays configuration-free by construction.
pub struct UnconfiguredRelaySink;

impl NipacDeliverySink for UnconfiguredRelaySink {
    fn deliver(&self, _event: &Event) -> Result<(), String> {
        Err(format!(
            "relay delivery is not configured ({} unset; the relay target is \
             founder-held at activation) — the projection is not activated",
            NIPAC_RELAY_URL_ENVIRONMENT_VARIABLE
        ))
    }
}

/// A recording sink for tests (and any local operator-facing capture):
/// accepts every validated event.
#[derive(Default)]
pub struct RecordingSink {
    pub delivered: std::sync::Mutex<Vec<Event>>,
}

impl NipacDeliverySink for RecordingSink {
    fn deliver(&self, event: &Event) -> Result<(), String> {
        self.delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
        Ok(())
    }
}

/// Read-only observation of an approved mandate: the store's own record of
/// the approval its single widening door applied. Only constructible from
/// the store's history CONTAINING that approval — the after-decision proof
/// for the envelope site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedMandateObservation {
    /// The store-recorded approval digest of the applied proposal (the
    /// mandate's stable identity; the envelope `d` derivation input).
    pub approval_digest: String,
    /// The approval revision number.
    pub revision: u64,
    /// When the approval was recorded (Unix ms).
    pub approved_at_ms: i64,
    /// The approved mandate (cloned from the revision row — owned data;
    /// the store is never held).
    pub mandate: TradingMandate,
}

/// Read-only observation of a revoked mandate: the store's `Revocation`
/// revision. Only constructible from history CONTAINING that revocation —
/// the after-decision proof for the 1985 site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokedMandateObservation {
    /// The revocation revision number.
    pub revision: u64,
    /// When the revocation was recorded (Unix ms).
    pub revoked_at_ms: i64,
    /// The revoked scope: venue + network (the store's revocation path is
    /// venue-wide for the pair; principal-keyed revocation is not wired in
    /// the store — OQ-WP5-3).
    pub venue: String,
    pub network: TradingNetwork,
}

/// The envelope identifier for a mandate: `omega-mandate-<approval_digest>`
/// — stable (the store's append-only history), unique per applied proposal.
pub fn envelope_id_for(approval_digest: &str) -> String {
    format!("{ENVELOPE_ID_PREFIX}{approval_digest}")
}

/// The scope-tuple digest (design §2): sha256 over the canonical
/// serialization `venue ␟ network-label ␟ sorted-strategies ␟
/// principal-or-empty` with U+001F separators. The strategy set is sorted
/// so the digest is order-stable; a `None` principal serializes as the
/// empty string (the venue-wide shape; the sovereign-wallet venue is
/// principal-only in practice — SEC-2026-043).
pub fn scope_constraints_hash(mandate: &TradingMandate) -> String {
    let network_label = match mandate.network {
        TradingNetwork::Signet => "signet",
        TradingNetwork::Testnet => "testnet",
        TradingNetwork::Mainnet => "mainnet",
    };
    let mut strategies: Vec<&str> = mandate.allowed_strategies.iter().map(String::as_str).collect();
    strategies.sort_unstable();
    let canonical = [
        mandate.venue.as_str(),
        network_label,
        strategies.join("\u{1f}").as_str(),
        mandate.principal_pubkey.as_deref().unwrap_or(""),
    ]
    .join("\u{1f}");
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

/// Unix seconds now (the event `created_at` clock).
pub fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Read-only observation: the latest approval (Creation/Widening with a
/// recorded approval digest) for the (venue, network, principal) scope.
/// Reads `MandateStore::history()` only — no mutation path exists on the
/// borrowed store.
pub fn observe_approved_mandate(
    store: &MandateStore,
    venue: &str,
    network: TradingNetwork,
    principal: Option<&str>,
) -> Result<Option<ApprovedMandateObservation>, String> {
    let revisions = store
        .history()
        .map_err(|error| format!("the mandate store history is unreadable: {error}"))?;
    Ok(revisions
        .iter()
        .filter(|revision| revision_matches_scope(revision, venue, network, principal))
        .filter(|revision| {
            matches!(
                revision.kind,
                MandateRevisionKind::Creation | MandateRevisionKind::Widening
            )
        })
        .filter_map(|revision| {
            revision
                .approval_digest
                .as_ref()
                .map(|digest| (revision, digest))
        })
        .last()
        .map(|(revision, digest)| ApprovedMandateObservation {
            approval_digest: digest.clone(),
            revision: revision.revision,
            approved_at_ms: revision.changed_at_ms,
            mandate: revision
                .mandate
                .clone()
                .expect("an approval revision always records its mandate"),
        }))
}

/// The envelope id of the latest approved mandate for the scope (the
/// convenience the spend/settlement sites use to reference the envelope).
pub fn observe_last_approved_envelope_id(
    store: &MandateStore,
    venue: &str,
    network: TradingNetwork,
    principal: Option<&str>,
) -> Result<Option<String>, String> {
    Ok(observe_approved_mandate(store, venue, network, principal)?
        .map(|observation| envelope_id_for(&observation.approval_digest)))
}

/// Read-only observation: the latest `Revocation` revision for the
/// (venue, network) pair — the store's own record that the mandate is
/// revoked. Reads `MandateStore::history()` only.
pub fn observe_revoked_mandate(
    store: &MandateStore,
    venue: &str,
    network: TradingNetwork,
) -> Result<Option<RevokedMandateObservation>, String> {
    let revisions = store
        .history()
        .map_err(|error| format!("the mandate store history is unreadable: {error}"))?;
    Ok(revisions
        .iter()
        .filter(|revision| revision.kind == MandateRevisionKind::Revocation)
        .filter(|revision| {
            revision.venue.as_deref() == Some(venue) && revision.network == Some(network)
        })
        .last()
        .map(|revision| RevokedMandateObservation {
            revision: revision.revision,
            revoked_at_ms: revision.changed_at_ms,
            venue: revision.venue.clone().unwrap_or_else(|| venue.to_owned()),
            network: revision.network.unwrap_or(network),
        }))
}

fn revision_matches_scope(
    revision: &trading_mandate::MandateRevision,
    venue: &str,
    network: TradingNetwork,
    principal: Option<&str>,
) -> bool {
    revision.venue.as_deref() == Some(venue)
        && revision.network == Some(network)
        && revision.principal_pubkey.as_deref() == principal
}

/// The after-decision input for the 39243 site. Constructed ONLY through
/// [`spend_authorization_after_decision`], which requires the gate's
/// `Authorized` decision — a `Refused` decision can never produce this
/// input, so a 39243 can never exist for a refused spend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedSpend {
    /// The envelope this spend draws down (`omega-mandate-<digest>`).
    pub envelope_id: String,
    /// The spending agent's Nostr pubkey hex (the mandate principal).
    pub agent_pubkey: String,
    /// The authorized amount in sats (≤ the envelope cap — enforced by the
    /// local gate before this input exists).
    pub amount_sats: u64,
    /// Digest-based purpose (`sovereign-wallet:<lane>:<payment-hash>`;
    /// P10 content-free).
    pub purpose: String,
    /// The payee endpoint when known; omitted rather than invented.
    pub recipient: Option<String>,
}

/// Build the 39243 input from the gate's decision. `decision` is the exact
/// `MandateDecision` the local authority produced: only `Authorized`
/// proceeds; `Refused` fails with a named permanent error (the projection
/// must never paper over a local refusal).
pub fn spend_authorization_after_decision(
    decision: &MandateDecision,
    envelope_id: &str,
    agent_pubkey: &str,
    amount_sats: u64,
    payment_hash_digest: Option<&str>,
    lane: &str,
) -> Result<AuthorizedSpend, String> {
    match decision {
        MandateDecision::Authorized { .. } => {}
        MandateDecision::Refused { .. } => {
            return Err(
                "the local authority refused this spend — no spend-authorization \
                 projection may exist for it (emission-after-decision)"
                    .to_owned(),
            );
        }
    }
    let payment_hash = payment_hash_digest.ok_or_else(|| {
        "the payment hash digest is unavailable — the purpose cannot be composed \
         content-free, so the emission fails honestly (no free-text purpose)"
            .to_owned()
    })?;
    Ok(AuthorizedSpend {
        envelope_id: envelope_id.to_owned(),
        agent_pubkey: agent_pubkey.to_owned(),
        amount_sats,
        purpose: format!("sovereign-wallet:{lane}:{payment_hash}"),
        // Omitted rather than invented: the wired callers do not know the
        // payee endpoint (design §3).
        recipient: None,
    })
}

/// The after-decision input for the 39244 site: a settled engagement with
/// its real settled amount and its digest completion proof. Constructed
/// ONLY through [`settlement_after_settled_pay`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettledEngagement {
    pub envelope_id: String,
    pub agent_pubkey: String,
    /// The settled sats (the L-402 actual settled outflow, or the escrow
    /// fee actually paid).
    pub total_sats_spent: u64,
    /// The digest binding the receipt to the work (the fee payment digest,
    /// or the L-402 payment hash). Digest-only — never a preimage
    /// (SEC-2026-088 inheritance).
    pub completion_proof: String,
}

/// Build the 39244 input from a settled payment. `actual_settled_sats`
/// must be the REAL settled amount (`PayResult::actual_amount_sat` for
/// L-402; the flat fee for escrow) — `None` (the sidecar did not report a
/// parseable settled amount) fails honestly; the quoted amount is never
/// substituted. `completion_proof` must be a 64-char lowercase hex digest.
pub fn settlement_after_settled_pay(
    envelope_id: &str,
    agent_pubkey: &str,
    actual_settled_sats: Option<u64>,
    completion_proof: &str,
) -> Result<SettledEngagement, String> {
    let total_sats_spent = actual_settled_sats.ok_or_else(|| {
        "the settled amount was not reported — the receipt emission fails \
         honestly rather than substituting the quoted amount"
            .to_owned()
    })?;
    if !is_64_lower_hex(completion_proof) {
        return Err(
            "the completion proof must be a 64-char lowercase hex digest \
             (digest-only; SEC-2026-088 inheritance)"
                .to_owned(),
        );
    }
    Ok(SettledEngagement {
        envelope_id: envelope_id.to_owned(),
        agent_pubkey: agent_pubkey.to_owned(),
        total_sats_spent,
        completion_proof: completion_proof.to_owned(),
    })
}

fn is_64_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The flag-gated, read-only projection. Construct with
/// [`NipacProjection::from_env`] at the emission sites; tests inject a
/// signer + recording sink. The projection holds NO store: the store
/// enters only the free-standing read-only observation functions.
pub struct NipacProjection {
    flag_enabled: bool,
    signer: Option<Arc<dyn NipacEventSigner>>,
    sink: Arc<dyn NipacDeliverySink>,
    relay_configured: bool,
}

impl NipacProjection {
    /// Read the flag plan from the environment: `OMEGA_NIPAC_PROJECTION`
    /// (enabled only by the exact value "1"; anything else — including
    /// unset — is OFF), the relay configuration state (reported in the
    /// honest failure reason; the URL value itself is never read into the
    /// projection), and the production delivery sink (unconfigured until
    /// activation). No signer is wired in production until the activation
    /// step bridges the sidecar identity — a flag-ON run reports the
    /// honest identity-unavailable failure.
    pub fn from_env() -> Self {
        let flag_enabled = std::env::var(NIPAC_PROJECTION_ENVIRONMENT_VARIABLE).as_deref()
            == Ok(NIPAC_ENABLED_VALUE);
        let relay_configured = std::env::var(NIPAC_RELAY_URL_ENVIRONMENT_VARIABLE)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        Self {
            flag_enabled,
            signer: None,
            sink: Arc::new(UnconfiguredRelaySink),
            relay_configured,
        }
    }

    /// Inject the signing seam (the activation step bridges the sidecar
    /// identity here; tests inject a deterministic key).
    pub fn with_signer(mut self, signer: Arc<dyn NipacEventSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Inject the delivery sink (tests use [`RecordingSink`]; the
    /// activation step may replace the unconfigured sink with a real
    /// relay transport behind the same seam).
    pub fn with_sink(mut self, sink: Arc<dyn NipacDeliverySink>) -> Self {
        self.sink = sink;
        self
    }

    /// The REAL flag state (the operator surface renders this honestly).
    pub fn flag_enabled(&self) -> bool {
        self.flag_enabled
    }

    /// The configured relay state (reported honestly; no connection is
    /// attempted by this module).
    pub fn relay_configured(&self) -> bool {
        self.relay_configured
    }

    /// Site 1 — the envelope (39242) for an approved mandate (design §2).
    /// `observation` is the store's own approval record: this input can
    /// only exist AFTER the widening door applied the proposal.
    pub fn emit_envelope(
        &self,
        observation: &ApprovedMandateObservation,
        now_unix: u64,
    ) -> NipacEmissionOutcome {
        // Flag OFF ⇒ inert before any identity or content work (§11); the
        // choke point re-checks.
        if !self.flag_enabled {
            return NipacEmissionOutcome::Disabled;
        }
        let Some(governor) = self.governor_pubkey() else {
            return self.identity_unavailable();
        };
        let mandate = &observation.mandate;
        let agent = match &mandate.principal_pubkey {
            Some(principal) => principal,
            // The sovereign-wallet venue is principal-only (SEC-2026-043);
            // a principal-less approval is a store anomaly — fail honestly.
            None => {
                return NipacEmissionOutcome::Failed {
                    reason: "the approved mandate carries no principal pubkey \
                             (SEC-2026-043 principal-only violation) — the \
                             envelope cannot name an agent"
                        .to_owned(),
                    retryable: false,
                };
            }
        };
        let expires_at_seconds = match mandate_seconds(&mandate.expires_at_ms) {
            Ok(seconds) => seconds,
            Err(reason) => return NipacEmissionOutcome::Failed { reason, retryable: false },
        };
        let envelope_id = envelope_id_for(&observation.approval_digest);
        let scope_hash = scope_constraints_hash(mandate);
        let content = json!({
            "offer_id": observation.approval_digest,
            "agent_pubkey": agent,
            "governor_pubkey": governor,
            "max_sats": mandate.max_venue_balance,
            "scope_constraints_hash": scope_hash,
            "expires_at": expires_at_seconds,
            // allowed_mints omitted: Omega settles over Lightning, not
            // Cashu mints, in this phase (empty = all allowed in satnam).
        })
        .to_string();
        let tags = vec![
            Tag::new(vec!["d".to_owned(), envelope_id.clone()]),
            Tag::new(vec!["p".to_owned(), agent.clone()]),
            // `e` carries the local proposal identity (the raw approval
            // digest) — the mapping note tells satnam readers this is a
            // local proposal, not a 39241 event id.
            Tag::new(vec!["e".to_owned(), observation.approval_digest.clone()]),
            Tag::new(vec![
                "max_sats".to_owned(),
                mandate.max_venue_balance.to_string(),
            ]),
            Tag::new(vec![
                "expires_at".to_owned(),
                expires_at_seconds.to_string(),
            ]),
            Tag::new(vec!["scope_hash".to_owned(), scope_hash]),
        ];
        self.emit_signed_event(
            KIND_ENVELOPE,
            tags,
            content,
            now_unix,
            &format!("envelope {envelope_id} (mandate revision {})", observation.revision),
        )
    }

    /// Site 2 — the spend authorization (39243) AFTER the local gate
    /// authorized and the payment proceeded (design §3).
    pub fn emit_spend_authorization(
        &self,
        spend: &AuthorizedSpend,
        now_unix: u64,
    ) -> NipacEmissionOutcome {
        // Flag OFF ⇒ inert before any identity or content work (§11); the
        // choke point re-checks.
        if !self.flag_enabled {
            return NipacEmissionOutcome::Disabled;
        }
        let Some(_governor) = self.governor_pubkey() else {
            return self.identity_unavailable();
        };
        let mut content = json!({
            "envelope_id": spend.envelope_id,
            "agent_pubkey": spend.agent_pubkey,
            "amount_sats": spend.amount_sats,
            "purpose": spend.purpose,
            "rail": RAIL_LIGHTNING,
        });
        if let Some(recipient) = &spend.recipient {
            content["recipient"] = json!(recipient);
        }
        let tags = vec![
            Tag::new(vec!["e".to_owned(), spend.envelope_id.clone()]),
            Tag::new(vec!["p".to_owned(), spend.agent_pubkey.clone()]),
            Tag::new(vec!["amount".to_owned(), spend.amount_sats.to_string()]),
        ];
        self.emit_signed_event(
            KIND_SPEND_AUTHORIZATION,
            tags,
            content.to_string(),
            now_unix,
            &format!("spend authorization for {}", spend.envelope_id),
        )
    }

    /// Site 3 — the settlement receipt (39244) per settled engagement
    /// (design §4). `task_completion_score`, `reputation_delta`, and
    /// `sig4sats_proof` are omitted (no Omega semantics; Sig4Sats deferred
    /// Phase 3b) — setting them would invent data.
    pub fn emit_settlement_receipt(
        &self,
        settlement: &SettledEngagement,
        now_unix: u64,
    ) -> NipacEmissionOutcome {
        // Flag OFF ⇒ inert before any identity or content work (§11); the
        // choke point re-checks.
        if !self.flag_enabled {
            return NipacEmissionOutcome::Disabled;
        }
        let Some(governor) = self.governor_pubkey() else {
            return self.identity_unavailable();
        };
        let content = json!({
            "envelope_id": settlement.envelope_id,
            "agent_pubkey": settlement.agent_pubkey,
            "governor_pubkey": governor,
            "total_sats_spent": settlement.total_sats_spent,
            "has_performance_bond": false,
            "completion_proof": settlement.completion_proof,
        })
        .to_string();
        let tags = vec![
            Tag::new(vec!["e".to_owned(), settlement.envelope_id.clone()]),
            Tag::new(vec!["p".to_owned(), settlement.agent_pubkey.clone()]),
            // `score` tag omitted per the recorded not-applicable decision.
        ];
        self.emit_signed_event(
            KIND_SETTLEMENT_RECEIPT,
            tags,
            content,
            now_unix,
            &format!("settlement receipt for {}", settlement.envelope_id),
        )
    }

    /// Site 4 — the revocation (1985) for a revoked mandate (design §5):
    /// a NIP-32 label event carrying the "revoked" label and referencing
    /// the envelope id. The local authority changed FIRST (the store's
    /// revocation revision is the observation input); the event is the
    /// portable notice.
    pub fn emit_revocation(
        &self,
        revocation: &RevokedMandateObservation,
        envelope_id: &str,
        revocation_reason: Option<&str>,
        now_unix: u64,
    ) -> NipacEmissionOutcome {
        // Flag OFF ⇒ inert before any identity or content work (§11); the
        // choke point re-checks.
        if !self.flag_enabled {
            return NipacEmissionOutcome::Disabled;
        }
        let Some(_guardian) = self.governor_pubkey() else {
            return self.identity_unavailable();
        };
        let mut content = json!({
            "envelope_id": envelope_id,
        });
        if let Some(reason) = revocation_reason {
            content["revocation_reason"] = json!(reason);
        }
        let tags = vec![
            Tag::new(vec!["e".to_owned(), envelope_id.to_owned()]),
            Tag::new(vec!["L".to_owned(), LABEL_NAMESPACE.to_owned()]),
            Tag::new(vec![
                "l".to_owned(),
                REVOCATION_LABEL.to_owned(),
                LABEL_NAMESPACE.to_owned(),
            ]),
        ];
        self.emit_signed_event(
            KIND_REVOCATION,
            tags,
            content.to_string(),
            now_unix,
            &format!(
                "revocation for {envelope_id} (store revision {})",
                revocation.revision
            ),
        )
    }

    /// Convenience site wrappers the widening-door / revocation callers
    /// use right after the local decision — observe from the store (read
    /// only), then emit. Kept beside the emitters so the ordering
    /// (observe → emit, never emit → observe) is local and auditable.
    pub fn emit_envelope_for_approved_mandate(
        &self,
        store: &MandateStore,
        venue: &str,
        network: TradingNetwork,
        principal: Option<&str>,
        now_unix: u64,
    ) -> NipacEmissionOutcome {
        let observation = match observe_approved_mandate(store, venue, network, principal) {
            Ok(Some(observation)) => observation,
            Ok(None) => {
                return NipacEmissionOutcome::Failed {
                    reason: "no approved mandate observed for the scope — the \
                             envelope site sits after the widening door, and \
                             no approval revision exists yet"
                        .to_owned(),
                    retryable: false,
                };
            }
            Err(reason) => return NipacEmissionOutcome::Failed { reason, retryable: true },
        };
        self.emit_envelope(&observation, now_unix)
    }

    pub fn emit_revocation_for_revoked_mandate(
        &self,
        store: &MandateStore,
        venue: &str,
        network: TradingNetwork,
        revocation_reason: Option<&str>,
        now_unix: u64,
    ) -> NipacEmissionOutcome {
        let envelope_id = match observe_last_approved_envelope_id(store, venue, network, None) {
            Ok(Some(envelope_id)) => envelope_id,
            Ok(None) => {
                return NipacEmissionOutcome::Failed {
                    reason: "no approved mandate observed for the revoked scope — \
                             the revocation references the envelope of the mandate \
                             the store recorded, and none exists"
                        .to_owned(),
                    retryable: false,
                };
            }
            Err(reason) => return NipacEmissionOutcome::Failed { reason, retryable: true },
        };
        let revocation = match observe_revoked_mandate(store, venue, network) {
            Ok(Some(revocation)) => revocation,
            Ok(None) => {
                return NipacEmissionOutcome::Failed {
                    reason: "no revocation revision observed — the 1985 site sits \
                             after the store's revocation path, which has not \
                             recorded one yet"
                        .to_owned(),
                    retryable: false,
                };
            }
            Err(reason) => return NipacEmissionOutcome::Failed { reason, retryable: true },
        };
        self.emit_revocation(&revocation, &envelope_id, revocation_reason, now_unix)
    }
}

/// OMEGA-DELTA-0302 — the wired-lane emission seam for one SETTLED spend:
/// the 39243 (spend authorization, keyed to the supervisor choke point's
/// decision) plus the 39244 (settlement receipt, keyed to the real settled
/// amount and the digest completion proof). Called by the two settled-
/// payment lanes ONLY AFTER the local decision AND the payment proceeded
/// (`l402::pay_l402_challenge` after the preimage proof returns;
/// `market_ui::escrow::pay_arbitration_fee_and_request_arbitration` after
/// the balanced `Fee` entry is appended). Read-only over the store; every
/// outcome is LOGGED, never propagated — the caller's payment/settlement
/// result is unaffected in every case (flag OFF ⇒ inert, honest failure ⇒
/// logged failed state, the local authority unchanged).
///
/// `decision` is the exact `MandateDecision` the local gate produced (a
/// `Refused` decision is refused here by [`spend_authorization_after_decision`]
/// — a 39243 can never exist for a refused spend). `actual_settled_sats`
/// is the REAL settled outflow (`PayResult::actual_amount_sat` parsed; an
/// unparseable/absent value fails the receipt honestly — the quoted amount
/// is never substituted). `completion_proof` is the digest binding the
/// receipt to the work (the L-402 payment hash, or the escrow
/// `fee_payment_digest`); digest-only, 64-char lowercase hex enforced.
#[allow(clippy::too_many_arguments)]
pub fn emit_settled_spend_pair(
    store: &MandateStore,
    venue: &str,
    network: TradingNetwork,
    principal: Option<&str>,
    decision: &MandateDecision,
    amount_sats: u64,
    payment_hash_digest: Option<&str>,
    lane: &str,
    actual_settled_sats: Option<u64>,
    completion_proof: &str,
) {
    let projection = NipacProjection::from_env();
    let Some(agent) = principal else {
        log::warn!(
            "nipac: an authorized settled spend carried no principal pubkey — \
             the projection emits nothing (no invented identity)"
        );
        return;
    };
    let envelope_id = match observe_last_approved_envelope_id(store, venue, network, principal) {
        Ok(Some(envelope_id)) => envelope_id,
        Ok(None) => {
            log::warn!(
                "nipac: no approved mandate observed for ({venue}, {network:?}) — \
                 the settled spend emits nothing (no invented envelope reference)"
            );
            return;
        }
        Err(error) => {
            log::warn!(
                "nipac: the mandate store history is unreadable ({error}) — \
                 the settled spend emits nothing"
            );
            return;
        }
    };
    let now_unix = now_unix_seconds();
    match spend_authorization_after_decision(
        decision,
        &envelope_id,
        agent,
        amount_sats,
        payment_hash_digest,
        lane,
    ) {
        Ok(spend) => log_outcome(projection.emit_spend_authorization(&spend, now_unix)),
        Err(reason) => log::warn!("nipac: the spend-authorization input was refused: {reason}"),
    }
    match settlement_after_settled_pay(&envelope_id, agent, actual_settled_sats, completion_proof) {
        Ok(settled) => log_outcome(projection.emit_settlement_receipt(&settled, now_unix)),
        Err(reason) => log::warn!("nipac: the settlement-receipt input was refused: {reason}"),
    }
}

/// Log one emission outcome (the wired lanes' only consumer of an outcome).
fn log_outcome(outcome: NipacEmissionOutcome) {
    match outcome {
        NipacEmissionOutcome::Emitted { kind, event_id } => {
            log::info!("nipac: emitted kind {kind} event {event_id}");
        }
        NipacEmissionOutcome::Disabled => {
            log::info!("nipac: the projection flag is OFF — nothing constructed or emitted");
        }
        NipacEmissionOutcome::Failed { reason, retryable } => {
            log::warn!("nipac: emission failed (retryable: {retryable}): {reason}");
        }
    }
}

impl NipacProjection {
    fn governor_pubkey(&self) -> Option<String> {
        self.signer
            .as_ref()
            .map(|signer| signer.pubkey_hex().to_owned())
    }

    fn identity_unavailable(&self) -> NipacEmissionOutcome {
        NipacEmissionOutcome::Failed {
            reason: "the signing identity is unavailable — the sidecar identity \
                     seam is not bridged (activation-time step); the emission \
                     fails closed and the local authority is unaffected"
                .to_owned(),
            retryable: true,
        }
    }

    /// The single signing choke point every emitter passes through: the
    /// kind policy is enforced HERE on the raw kind number before any
    /// signature exists — 39603/39610 (and every non-NIP-AC kind) are
    /// refused by name. Then sign (BIP-340 via the seam), validate the
    /// canonical id, and hand to the delivery sink.
    fn emit_signed_event(
        &self,
        kind: u16,
        tags: Vec<Tag>,
        content: String,
        created_at: u64,
        label: &str,
    ) -> NipacEmissionOutcome {
        if !self.flag_enabled {
            // Inert: no event construction, no signing, no delivery (§11).
            return NipacEmissionOutcome::Disabled;
        }
        let Some(signer) = &self.signer else {
            return self.identity_unavailable();
        };
        let kind = match enforce_kind_policy(kind) {
            Ok(kind) => kind,
            Err(reason) => {
                return NipacEmissionOutcome::Failed {
                    reason,
                    retryable: false,
                };
            }
        };
        let event = match signer.sign_event(created_at, kind.kind(), tags, content) {
            Ok(event) => event,
            Err(reason) => {
                return NipacEmissionOutcome::Failed {
                    reason,
                    retryable: true,
                };
            }
        };
        let event_id = event.id.clone();
        let event_kind = event.kind;
        match self.sink.deliver(&event) {
            Ok(()) => NipacEmissionOutcome::Emitted {
                kind: event_kind,
                event_id,
            },
            Err(reason) => {
                NipacEmissionOutcome::Failed {
                    reason: format!(
                        "the event was constructed and signed ({label}; id \
                         {event_id}) but delivery refused: {reason}"
                    ),
                    retryable: true,
                }
            }
        }
    }
}

/// Convert the mandate's Unix-millisecond expiry to Unix seconds (the
/// recorded ms → s conversion; satnam's `expires_at` is Unix seconds).
fn mandate_seconds(expires_at_ms: &i64) -> Result<u64, String> {
    if *expires_at_ms <= 0 {
        return Err(format!(
            "the mandate expiry {expires_at_ms} ms is not a representable \
             Unix timestamp — the envelope fails honestly"
        ));
    }
    Ok((*expires_at_ms as u64) / 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::with_nipac_projection_env;
    use trading_mandate::SOVEREIGN_WALLET_VENUE;

    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
    const PAYMENT_HASH: &str = "4ca14526b2751b640d549ce7caf8ac39438592211a0ec370064d57666a682ad6";

    /// The deterministic test key: [7u8; 32]. Its pubkey is COMPUTED (never
    /// assumed) — the governor assertions compare against it.
    fn test_signer() -> Arc<dyn NipacEventSigner> {
        Arc::new(
            ImmortalNipacSigner::from_secret_bytes([7u8; 32]).expect("test signer"),
        )
    }

    fn governor_pubkey() -> String {
        test_signer().pubkey_hex().to_owned()
    }

    /// The first value of the named tag on an event (the immortal_client
    /// `Event` exposes the `tag_values` iterator; the tests read the first
    /// value the way the satnam tag grammar defines single-valued tags).
    fn tag_value(event: &Event, name: &str) -> Option<String> {
        event.tag_values(name).next().map(str::to_owned)
    }

    /// A flag-ON projection with the test signer and a recording sink,
    /// constructed under the projection-env lock so the process-global env
    /// cannot race (the crate's established env-hygiene pattern): the flag
    /// snapshot is taken with the env momentarily set, then restored to
    /// absent.
    fn test_projection() -> NipacProjection {
        let projection = with_nipac_projection_env(Some("1"), None, NipacProjection::from_env);
        projection
            .with_signer(test_signer())
            .with_sink(Arc::new(RecordingSink::default()))
    }

    /// A flag-OFF projection (the env guaranteed absent at construction).
    fn flag_off_projection() -> NipacProjection {
        with_nipac_projection_env(None, None, NipacProjection::from_env)
    }

    fn candidate(max_payment_sat: u64) -> TradingMandate {
        crate::sovereign_wallet_mandate_candidate(TradingNetwork::Signet, AGENT, max_payment_sat, 1_000_000)
    }

    fn approve_mandate(store: &MandateStore, max_payment_sat: u64) -> String {
        let proposal = store.propose(candidate(max_payment_sat)).expect("proposal");
        trading_mandate::apply_ui_approved_for_test(store, proposal, 2).expect("approved");
        observe_approved_mandate(store, SOVEREIGN_WALLET_VENUE, TradingNetwork::Signet, Some(AGENT))
            .expect("history readable")
            .expect("the approval is observed")
            .approval_digest
    }

    fn authorized() -> MandateDecision {
        MandateDecision::Authorized { revision: 1 }
    }

    fn refused() -> MandateDecision {
        MandateDecision::Refused {
            reason: trading_mandate::MandateRefusal::Missing,
            required_posture: trading_mandate::RequiredRiskPosture::FlatRisk,
        }
    }

    // -------------------------------------------------------------------
    // The OMEGA-DELTA-0302 four-part check (its own named test): (a)
    // emission only after the local decision; (b) flag default OFF; (c)
    // no store mutation; (d) the kind policy.
    // -------------------------------------------------------------------

    #[test]
    fn nipac_projection_four_part_check() {
        let store = MandateStore::in_memory().expect("store");
        let projection = test_projection();

        // (a) emission-after-decision, at every site:
        // 39243: a Refused decision can never produce the input.
        assert!(
            spend_authorization_after_decision(
                &refused(),
                "omega-mandate-x",
                AGENT,
                1_000,
                Some(PAYMENT_HASH),
                LANE_L402_REDEMPTION,
            )
            .is_err(),
            "a refused decision must never produce a spend-authorization input"
        );
        // 39243 before any approval: no envelope id exists to reference.
        assert_eq!(
            observe_last_approved_envelope_id(&store, SOVEREIGN_WALLET_VENUE, TradingNetwork::Signet, Some(AGENT))
                .expect("history readable"),
            None,
            "no envelope id may exist before the approval decision"
        );
        // 39242: the envelope site with no approval revision fails honestly.
        let outcome = projection.emit_envelope_for_approved_mandate(
            &store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            Some(AGENT),
            10,
        );
        assert!(
            matches!(outcome, NipacEmissionOutcome::Failed { retryable: false, .. }),
            "the envelope site without an approval decision must fail (not emit)"
        );
        // ...and after the approval decision the site emits.
        let digest = approve_mandate(&store, 50_000);
        let outcome = projection.emit_envelope_for_approved_mandate(
            &store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            Some(AGENT),
            10,
        );
        assert!(
            outcome.is_emitted(),
            "after the approval the envelope emits: {outcome:?}"
        );
        // The authorized amount is capped by the envelope (the local gate
        // already enforced this; the projection asserts the observable).
        let envelope_id = envelope_id_for(&digest);
        let spend = spend_authorization_after_decision(
            &authorized(),
            &envelope_id,
            AGENT,
            50_000,
            Some(PAYMENT_HASH),
            LANE_L402_REDEMPTION,
        )
        .expect("the authorized decision produces the input");
        assert_eq!(spend.amount_sats, 50_000);
        let outcome = projection.emit_spend_authorization(&spend, 11);
        assert!(outcome.is_emitted(), "the authorized spend emits: {outcome:?}");

        // (b) the flag default is OFF: with the env unset, every emitter
        // reports Disabled and constructs nothing.
        let projection = flag_off_projection();
        assert!(!projection.flag_enabled(), "the flag default must be OFF");
        let spend = spend_authorization_after_decision(
            &authorized(),
            &envelope_id,
            AGENT,
            1_000,
            Some(PAYMENT_HASH),
            LANE_L402_REDEMPTION,
        )
        .expect("the decision input is independent of the flag");
        for outcome in [
            projection.emit_envelope_for_approved_mandate(
                &store,
                SOVEREIGN_WALLET_VENUE,
                TradingNetwork::Signet,
                Some(AGENT),
                10,
            ),
            projection.emit_spend_authorization(&spend, 10),
        ] {
            assert_eq!(
                outcome,
                NipacEmissionOutcome::Disabled,
                "a flag-OFF projection must be inert at every site"
            );
        }
        // The exact enabled value: "0" is OFF too.
        with_nipac_projection_env(Some("0"), None, || {
            let projection = NipacProjection::from_env();
            assert!(!projection.flag_enabled(), "OMEGA_NIPAC_PROJECTION=0 is OFF");
        });
        with_nipac_projection_env(Some("1"), None, || {
            assert!(NipacProjection::from_env().flag_enabled(), "=1 enables");
        });

        // (c) no store mutation: every emission path leaves the store's
        // revision exactly where it was.
        let projection = test_projection();
        let before = store.snapshot().expect("snapshot").revision;
        let spend = spend_authorization_after_decision(
            &authorized(),
            &envelope_id,
            AGENT,
            1_000,
            Some(PAYMENT_HASH),
            LANE_ESCROW_ARBITRATION_FEE,
        )
        .expect("input");
        let settled = settlement_after_settled_pay(
            &envelope_id,
            AGENT,
            Some(100),
            PAYMENT_HASH,
        )
        .expect("input");
        let _ = projection.emit_envelope_for_approved_mandate(
            &store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            Some(AGENT),
            10,
        );
        let _ = projection.emit_spend_authorization(&spend, 10);
        let _ = projection.emit_settlement_receipt(&settled, 10);
        let _ = projection.emit_revocation_for_revoked_mandate(
            &store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            None,
            10,
        );
        let after = store.snapshot().expect("snapshot").revision;
        assert_eq!(before, after, "the projection must not mutate the store");

        // (d) the kind policy: only the four kinds are emittable; the
        // escrow reservation (39603/39610) is refused through the
        // projection's choke point.
        assert_eq!(NIPAC_EMITTABLE_KINDS, [39_242, 39_243, 39_244, 1_985]);
        for refused_kind in [39_603u16, 39_610] {
            assert!(
                enforce_kind_policy(refused_kind).is_err(),
                "kind {refused_kind} must be refused by the projection's kind policy"
            );
        }
        for allowed in NIPAC_EMITTABLE_KINDS {
            assert!(
                enforce_kind_policy(allowed).is_ok(),
                "kind {allowed} is within the policy"
            );
        }
    }

    /// The kind-policy negative test the brief names explicitly: emitting
    /// 39603/39610 through the projection is refused (at the choke point,
    /// before any signature exists).
    #[test]
    fn kind_policy_refuses_39603_and_39610_emission_through_the_projection() {
        let projection = test_projection();
        assert!(NipacEventKind::from_kind(39_603).is_none());
        assert!(NipacEventKind::from_kind(39_610).is_none());
        for kind in [39_603u16, 39_610] {
            let outcome = projection.emit_signed_event(
                kind,
                vec![Tag::new(vec!["d".to_owned(), "x".to_owned()])],
                "{}".to_owned(),
                10,
                "negative probe",
            );
            match outcome {
                NipacEmissionOutcome::Failed { reason, retryable: false } => {
                    assert!(
                        reason.contains("kind policy"),
                        "the refusal must name the kind policy: {reason}"
                    );
                    assert!(
                        reason.contains(&format!("{kind}")),
                        "the refusal must name the refused kind: {reason}"
                    );
                }
                other => panic!("kind {kind} must be refused, got {other:?}"),
            }
        }
    }

    /// The §7 sats unit test: the emitted NIP-AC fields carry
    /// sats-magnitude values matching the local entries (P9), and the
    /// expiry converts ms → s.
    #[test]
    fn emitted_fields_carry_sats_matching_the_local_entries() {
        let store = MandateStore::in_memory().expect("store");
        let digest = approve_mandate(&store, 50_000);
        let projection = test_projection();
        let sink = Arc::new(RecordingSink::default());
        let projection = projection.with_sink(sink.clone());

        let outcome = projection.emit_envelope_for_approved_mandate(
            &store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            Some(AGENT),
            10,
        );
        assert!(outcome.is_emitted(), "{outcome:?}");
        let envelope_event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("the envelope event was delivered")
            .clone();
        let envelope: serde_json::Value = serde_json::from_str(&envelope_event.content).expect("json");
        // The mandate cap is 50_000 sats: the content field and the tag
        // both carry exactly that sats value.
        assert_eq!(envelope["max_sats"], 50_000, "envelope max_sats is sats");
        assert_eq!(
            tag_value(&envelope_event, "max_sats"),
            Some("50000".to_owned()),
            "the max_sats tag mirrors the sats value"
        );
        // ms → s: the candidate expired at 1_000_000 ms → 1_000 s of Unix time.
        assert_eq!(envelope["expires_at"], 1_000, "expires_at converts ms to seconds");
        assert_eq!(
            tag_value(&envelope_event, "expires_at"),
            Some("1000".to_owned())
        );

        // A 10_000-sat authorized spend → amount_sats 10000 (sats), tag "10000".
        let spend = spend_authorization_after_decision(
            &authorized(),
            &envelope_id_for(&digest),
            AGENT,
            10_000,
            Some(PAYMENT_HASH),
            LANE_L402_REDEMPTION,
        )
        .expect("input");
        let outcome = projection.emit_spend_authorization(&spend, 11);
        assert!(outcome.is_emitted(), "{outcome:?}");
        let spend_event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("the spend event was delivered")
            .clone();
        let spend_json: serde_json::Value =
            serde_json::from_str(&spend_event.content).expect("json");
        assert_eq!(spend_json["amount_sats"], 10_000, "amount_sats is sats");
        assert_eq!(tag_value(&spend_event, "amount"), Some("10000".to_owned()));

        // The 100-sat escrow fee (DEFAULT_ARBITRATION_FEE_FLAT_SATS) →
        // total_sats_spent 100 (sats).
        let settled = settlement_after_settled_pay(
            &envelope_id_for(&digest),
            AGENT,
            Some(100),
            PAYMENT_HASH,
        )
        .expect("input");
        let outcome = projection.emit_settlement_receipt(&settled, 12);
        assert!(outcome.is_emitted(), "{outcome:?}");
        let receipt_event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("the receipt event was delivered")
            .clone();
        let receipt: serde_json::Value = serde_json::from_str(&receipt_event.content).expect("json");
        assert_eq!(
            receipt["total_sats_spent"], 100,
            "total_sats_spent is the settled sats value"
        );
    }

    /// §2 envelope mapping: every field of the design table, asserted
    /// against the approved mandate and the signer identity.
    #[test]
    fn envelope_mapping_matches_the_design_table() {
        let store = MandateStore::in_memory().expect("store");
        let digest = approve_mandate(&store, 50_000);
        let observation = observe_approved_mandate(
            &store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            Some(AGENT),
        )
        .expect("history readable")
        .expect("observed");
        assert_eq!(observation.approval_digest, digest);
        assert_eq!(observation.mandate.max_venue_balance, 50_000);
        assert_eq!(observation.mandate.principal_pubkey.as_deref(), Some(AGENT));

        let projection = test_projection();
        let sink = Arc::new(RecordingSink::default());
        let projection = projection.with_sink(sink.clone());
        let outcome = projection.emit_envelope(&observation, 10);
        assert!(outcome.is_emitted(), "{outcome:?}");
        let event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("delivered")
            .clone();
        assert_eq!(event.kind, 39_242);
        assert_eq!(
            event.pubkey,
            governor_pubkey(),
            "governor == the signer identity"
        );
        let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
        assert_eq!(content["offer_id"], digest, "offer_id = the applied proposal's identity");
        assert_eq!(content["agent_pubkey"], AGENT);
        assert_eq!(content["governor_pubkey"], governor_pubkey());
        assert_eq!(content["max_sats"], 50_000);
        assert_eq!(content["expires_at"], 1_000, "ms → s");
        assert!(content.get("allowed_mints").is_none(), "allowed_mints omitted");
        // The scope digest is a 64-hex digest and deterministic.
        let scope_hash = content["scope_constraints_hash"].as_str().expect("hex");
        assert!(is_64_lower_hex(scope_hash));
        assert_eq!(scope_hash, scope_constraints_hash(&observation.mandate));
        // Tags per types.ts CreditEnvelopeTags.
        let envelope_id = envelope_id_for(&digest);
        assert_eq!(tag_value(&event, "d"), Some(envelope_id.clone()));
        assert_eq!(tag_value(&event, "p"), Some(AGENT.to_owned()));
        assert_eq!(tag_value(&event, "e"), Some(digest.clone()));
        assert_eq!(tag_value(&event, "max_sats"), Some("50000".to_owned()));
        assert_eq!(tag_value(&event, "expires_at"), Some("1000".to_owned()));
        assert_eq!(tag_value(&event, "scope_hash"), Some(scope_hash.to_owned()));
        // The signed event's canonical id re-derives (validated at sign time
        // too — this is the independent re-check).
        assert_eq!(event.computed_id().expect("id"), event.id);
    }

    /// §3 spend-authorization mapping: envelope reference, principal,
    /// amount, digest-composed purpose, omitted recipient, fixed rail,
    /// tags.
    #[test]
    fn spend_authorization_mapping_matches_the_design_table() {
        let spend = spend_authorization_after_decision(
            &authorized(),
            "omega-mandate-abc",
            AGENT,
            10_000,
            Some(PAYMENT_HASH),
            LANE_L402_REDEMPTION,
        )
        .expect("input");
        assert_eq!(spend.envelope_id, "omega-mandate-abc");
        assert_eq!(spend.agent_pubkey, AGENT);
        assert_eq!(spend.amount_sats, 10_000);
        assert_eq!(
            spend.purpose,
            format!("sovereign-wallet:{LANE_L402_REDEMPTION}:{PAYMENT_HASH}"),
            "purpose = call-site lane + the payment hash digest (content-free)"
        );
        assert_eq!(spend.recipient, None, "omitted rather than invented");

        let projection = test_projection();
        let sink = Arc::new(RecordingSink::default());
        let projection = projection.with_sink(sink.clone());
        let outcome = projection.emit_spend_authorization(&spend, 10);
        assert!(outcome.is_emitted(), "{outcome:?}");
        let event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("delivered")
            .clone();
        assert_eq!(event.kind, 39_243);
        let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
        assert_eq!(content["envelope_id"], "omega-mandate-abc");
        assert_eq!(content["agent_pubkey"], AGENT);
        assert_eq!(content["amount_sats"], 10_000);
        assert_eq!(content["rail"], "lightning", "the fixed rail for this phase");
        assert!(content.get("recipient").is_none(), "recipient omitted");
        assert_eq!(tag_value(&event, "e"), Some("omega-mandate-abc".to_owned()));
        assert_eq!(tag_value(&event, "p"), Some(AGENT.to_owned()));
        assert_eq!(tag_value(&event, "amount"), Some("10000".to_owned()));

        // A missing payment hash fails honestly — no free-text purpose.
        assert!(
            spend_authorization_after_decision(
                &authorized(),
                "omega-mandate-abc",
                AGENT,
                10_000,
                None,
                LANE_L402_REDEMPTION,
            )
            .is_err(),
            "the purpose cannot be composed content-free without the digest"
        );
    }

    /// §4 settlement-receipt mapping: envelope/principal/governor, the real
    /// settled amount, the honest false bond flag, the digest completion
    /// proof, the omitted score/bond fields, and the honest failures.
    #[test]
    fn settlement_receipt_mapping_matches_the_design_table() {
        // No settled amount → honest failure (never the quoted amount).
        assert!(settlement_after_settled_pay("omega-mandate-abc", AGENT, None, PAYMENT_HASH).is_err());
        // A non-digest completion proof is refused (digest-only law).
        assert!(settlement_after_settled_pay("omega-mandate-abc", AGENT, Some(100), "preimage-text").is_err());
        assert!(settlement_after_settled_pay("omega-mandate-abc", AGENT, Some(100), "ABCD").is_err());

        let settled =
            settlement_after_settled_pay("omega-mandate-abc", AGENT, Some(100), PAYMENT_HASH)
                .expect("input");
        assert_eq!(settled.total_sats_spent, 100);
        assert_eq!(settled.completion_proof, PAYMENT_HASH);

        let projection = test_projection();
        let sink = Arc::new(RecordingSink::default());
        let projection = projection.with_sink(sink.clone());
        let outcome = projection.emit_settlement_receipt(&settled, 10);
        assert!(outcome.is_emitted(), "{outcome:?}");
        let event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("delivered")
            .clone();
        assert_eq!(event.kind, 39_244);
        let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
        assert_eq!(content["envelope_id"], "omega-mandate-abc");
        assert_eq!(content["agent_pubkey"], AGENT);
        assert_eq!(content["governor_pubkey"], governor_pubkey());
        assert_eq!(content["total_sats_spent"], 100);
        assert_eq!(content["has_performance_bond"], false, "the honest default");
        assert_eq!(content["completion_proof"], PAYMENT_HASH, "digest-only");
        assert!(
            content.get("task_completion_score").is_none()
                && content.get("reputation_delta").is_none()
                && content.get("sig4sats_proof").is_none(),
            "no Omega scoring semantics exist; setting them would invent data"
        );
        assert!(
            tag_value(&event, "score").is_none(),
            "the score tag is omitted per the recorded not-applicable decision"
        );
        assert_eq!(tag_value(&event, "e"), Some("omega-mandate-abc".to_owned()));
        assert_eq!(tag_value(&event, "p"), Some(AGENT.to_owned()));
    }

    /// §5 revocation mapping: the 1985 site sits after the store's
    /// revocation path; the label carries "revoked"; the envelope
    /// reference is the mandate's envelope id; the pre-revocation call
    /// fails honestly.
    ///
    /// The store's revocation path (`MandateStore::revoke`) is venue-wide
    /// for the (venue, network) pair (OQ-WP5-3) — it records a Revocation
    /// revision only when a venue-wide mandate is active for the pair. The
    /// success path below therefore runs on the venue-wide shape (the
    /// legacy venue, mirroring trading_mandate's own revocation tests),
    /// and the sovereign-wallet reality (principal-keyed approvals only, so
    /// the venue-wide revoke is a recorded no-op) is asserted as the honest
    /// failed state — never papered over.
    #[test]
    fn revocation_mapping_matches_the_design_table() {
        let store = MandateStore::in_memory().expect("store");
        let projection = test_projection();
        let sink = Arc::new(RecordingSink::default());
        let projection = projection.with_sink(sink.clone());

        // Before any revocation revision exists, the site fails (not emit).
        let outcome = projection.emit_revocation_for_revoked_mandate(
            &store,
            trading_mandate::LEGACY_VENUE,
            TradingNetwork::Signet,
            None,
            10,
        );
        assert!(
            matches!(outcome, NipacEmissionOutcome::Failed { retryable: false, .. }),
            "no 1985 before the store records a revocation: {outcome:?}"
        );

        // The store's venue-wide revocation path (the only wired one —
        // OQ-WP5-3) records the Revocation revision; the site then emits.
        // The venue-wide approval (principal None) is the mandate the
        // venue-wide revoke removes, and the revocation notice references
        // ITS envelope id.
        let venue_wide_candidate = TradingMandate {
            venue: trading_mandate::LEGACY_VENUE.to_string(),
            network: TradingNetwork::Signet,
            principal_pubkey: None,
            collateral_asset: trading_mandate::AssetId::sats(),
            objective: "venue-wide revocation-mapping fixture".to_string(),
            max_venue_balance: 50_000,
            max_position_usd: 1,
            max_leverage: 1,
            daily_loss_stop: 50_000,
            max_orders_per_hour: 1,
            min_liquidation_buffer_bps: 0,
            allowed_strategies: [crate::SOVEREIGN_WALLET_STRATEGY.to_string()]
                .into_iter()
                .collect(),
            review_cadence: trading_mandate::ReviewCadence::Interval { seconds: 3_600 },
            expires_at_ms: 1_000_000,
            allow_escrow: None,
            max_escrow_sats: None,
            escrow_timeout_blocks: None,
            arbitration_fee_flat_sats: None,
        };
        let proposal = store.propose(venue_wide_candidate).expect("proposal");
        trading_mandate::apply_ui_approved_for_test(&store, proposal, 2).expect("approved");
        store
            .revoke(trading_mandate::LEGACY_VENUE, TradingNetwork::Signet, 20)
            .expect("revoked");
        let outcome = projection.emit_revocation_for_revoked_mandate(
            &store,
            trading_mandate::LEGACY_VENUE,
            TradingNetwork::Signet,
            Some("operator revocation"),
            21,
        );
        assert!(outcome.is_emitted(), "{outcome:?}");
        let event = sink
            .delivered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .expect("delivered")
            .clone();
        assert_eq!(event.kind, 1_985, "NIP-32 label kind");
        assert_eq!(tag_value(&event, "L"), Some(LABEL_NAMESPACE.to_owned()));
        assert_eq!(
            tag_value(&event, "l"),
            Some(REVOCATION_LABEL.to_owned()),
            "the l tag's value carries 'revoked' (NIP-32 shape)"
        );
        let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
        assert!(content["envelope_id"].as_str().expect("id").starts_with(ENVELOPE_ID_PREFIX));
        assert_eq!(content["revocation_reason"], "operator revocation");

        // The sovereign-wallet reality (OQ-WP5-3): approvals there are
        // principal-keyed, the venue-wide revoke records NO revocation
        // revision, and the site fails honestly instead of emitting a 1985
        // the local authority never recorded.
        let sovereign_store = MandateStore::in_memory().expect("store");
        approve_mandate(&sovereign_store, 50_000);
        sovereign_store
            .revoke(SOVEREIGN_WALLET_VENUE, TradingNetwork::Signet, 20)
            .expect("the venue-wide revoke call itself succeeds");
        let outcome = projection.emit_revocation_for_revoked_mandate(
            &sovereign_store,
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            None,
            21,
        );
        assert!(
            matches!(outcome, NipacEmissionOutcome::Failed { retryable: false, .. }),
            "no 1985 may exist without the store recording the revocation: {outcome:?}"
        );
    }

    /// The signer seam: BIP-340 signatures verify, the canonical id
    /// re-derives, and the governor identity is the signer's pubkey.
    #[test]
    fn the_signer_seam_signs_verifiable_canonical_events() {
        let signer = test_signer();
        let governor = signer.pubkey_hex().to_owned();
        let event = signer
            .sign_event(
                10,
                KIND_ENVELOPE,
                vec![Tag::new(vec!["d".to_owned(), "x".to_owned()])],
                "{}".to_owned(),
            )
            .expect("signed");
        event
            .validate_structure()
            .and_then(|()| event.validate_crypto())
            .expect("the signed event verifies (BIP-340 + canonical id)");
        assert_eq!(event.pubkey, governor);
        assert_eq!(event.kind, 39_242);

        // The projection without a signer fails honestly (retryable) when
        // the flag is ON — the activation-time identity bridge is missing.
        let flag_on = with_nipac_projection_env(Some("1"), None, NipacProjection::from_env);
        let spend = spend_authorization_after_decision(
            &authorized(),
            "omega-mandate-abc",
            AGENT,
            1_000,
            Some(PAYMENT_HASH),
            LANE_WALLET_PAYMENT,
        )
        .expect("input");
        let outcome = flag_on.emit_spend_authorization(&spend, 10);
        match outcome {
            NipacEmissionOutcome::Failed { reason, retryable: true } => {
                assert!(reason.contains("identity"), "{reason}");
            }
            other => panic!("identity-unavailable must fail retryable, got {other:?}"),
        }
        // With the relay sink unconfigured (production default), the
        // signed event's delivery refuses with the named reason.
        let projection = with_nipac_projection_env(Some("1"), None, || {
            NipacProjection::from_env().with_signer(test_signer())
        });
        assert!(!projection.relay_configured());
        let outcome = projection.emit_spend_authorization(&spend, 10);
        match outcome {
            NipacEmissionOutcome::Failed { reason, retryable: true } => {
                assert!(reason.contains("relay"), "{reason}");
            }
            other => panic!("unconfigured relay must fail retryable, got {other:?}"),
        }
    }

    /// The scope digest is order-stable over the strategy set and changes
    /// when the scope changes (venue/network/strategies/principal).
    #[test]
    fn the_scope_constraints_hash_is_stable_and_scope_sensitive() {
        let mut base = candidate(50_000);
        let first = scope_constraints_hash(&base);
        assert_eq!(first, scope_constraints_hash(&base), "deterministic");
        // Strategy-set order does not change the digest.
        base.allowed_strategies
            .insert(format!("{}_alt", crate::SOVEREIGN_WALLET_STRATEGY));
        let widened = scope_constraints_hash(&base);
        assert_ne!(widened, first, "a different scope digests differently");
        // A different network is a different scope.
        let mut other_network = candidate(50_000);
        other_network.network = TradingNetwork::Mainnet;
        assert_ne!(scope_constraints_hash(&other_network), first);
        // A different principal is a different scope.
        let mut other_principal = candidate(50_000);
        other_principal.principal_pubkey = Some(governor_pubkey());
        assert_ne!(scope_constraints_hash(&other_principal), first);
    }
}
