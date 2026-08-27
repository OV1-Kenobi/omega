use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, bail};
use parking_lot::Mutex;
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct as _};
use sha2::{Digest as _, Sha256};
pub use trading_ledger::AssetId;

const MAX_IDENTIFIER_LENGTH: usize = 200;
const MAX_OBJECTIVE_LENGTH: usize = 1_000;
const MIN_REVIEW_INTERVAL_SECONDS: u64 = 60;

/// The venue every mandate recorded before venue scoping implicitly governed.
pub const LEGACY_VENUE: &str = "lnmarkets";

/// The sovereign wallet venue (design §6.3.5). SEC-2026-043 (resolved by the
/// founder: principal-only for the sovereign-wallet venue) makes this venue
/// principal-only: every mandate for it MUST carry `principal_pubkey`, and
/// `authorize` never falls back to a venue-wide mandate on this venue.
pub const SOVEREIGN_WALLET_VENUE: &str = "sovereign-wallet";

/// Mandate schema version stored in SQLite `user_version`. Version 1 stores
/// held one implicit-venue revision chain; version 2 rows carry an explicit
/// (venue, network) scope. The principal-keyed scope dimension (WP-5) is an
/// additive nullable column on version 2 — the version constant is NOT bumped
/// because OMEGA-DELTA-0258 pins `MANDATE_SCHEMA_VERSION: i64 = 2` and
/// crates/omega_deltas is out of bounds for WP-5 (labeled choice; open
/// question OQ-WP5-1: bump both together in a delta-owning WP).
pub const MANDATE_SCHEMA_VERSION: i64 = 2;

/// SEC-2026-043: the sovereign-wallet venue is principal-only. The venue-wide
/// fallback never applies to it, so a principal-keyed spend requires an exact
/// principal mandate even when a venue-wide mandate exists.
pub fn is_principal_only_venue(venue: &str) -> bool {
    venue == SOVEREIGN_WALLET_VENUE
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradingNetwork {
    Signet,
    Testnet,
    Mainnet,
}

impl TradingNetwork {
    fn label(self) -> &'static str {
        match self {
            Self::Signet => "signet",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    fn parse(label: &str) -> Result<Self> {
        match label {
            "signet" => Ok(Self::Signet),
            "testnet" => Ok(Self::Testnet),
            "mainnet" => Ok(Self::Mainnet),
            other => bail!("unknown trading network {other:?}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReviewCadence {
    FundingSettlement,
    Interval { seconds: u64 },
}

impl ReviewCadence {
    fn validate(&self) -> Result<()> {
        if let Self::Interval { seconds } = self
            && *seconds < MIN_REVIEW_INTERVAL_SECONDS
        {
            bail!("mandate review interval must be at least {MIN_REVIEW_INTERVAL_SECONDS} seconds");
        }
        Ok(())
    }
}

/// One mandate governs one (venue, network) pair. `max_venue_balance` and
/// `daily_loss_stop` are denominated in `collateral_asset`; `max_position_usd`
/// and the leverage, order-rate, and liquidation-buffer limits are
/// venue-neutral.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TradingMandate {
    pub venue: String,
    pub network: TradingNetwork,
    /// Nostr public key hex (validated 64-hex) this mandate authorizes.
    /// `None` = venue-wide mandate (legacy semantics, unchanged). The
    /// sovereign-wallet venue is principal-only (SEC-2026-043): a mandate for
    /// that venue without a principal is refused by the widening door.
    pub principal_pubkey: Option<String>,
    pub collateral_asset: AssetId,
    pub objective: String,
    pub max_venue_balance: u64,
    pub max_position_usd: u64,
    pub max_leverage: u8,
    pub daily_loss_stop: u64,
    pub max_orders_per_hour: u32,
    pub min_liquidation_buffer_bps: u32,
    pub allowed_strategies: BTreeSet<String>,
    pub review_cadence: ReviewCadence,
    pub expires_at_ms: i64,
}

impl TradingMandate {
    fn is_legacy_shape(&self) -> bool {
        self.venue == LEGACY_VENUE && self.collateral_asset.is_sats() && self.principal_pubkey.is_none()
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier("venue", &self.venue)?;
        if let Some(principal) = &self.principal_pubkey
            && !is_valid_pubkey_hex(principal)
        {
            bail!("mandate principal pubkey must be 64 hex characters");
        }
        let objective = self.objective.trim();
        if objective.is_empty() {
            bail!("mandate objective must not be empty");
        }
        if objective.len() > MAX_OBJECTIVE_LENGTH {
            bail!("mandate objective must not exceed {MAX_OBJECTIVE_LENGTH} bytes");
        }
        if self.max_venue_balance == 0 {
            bail!("mandate venue balance limit must be positive");
        }
        if self.max_position_usd == 0 {
            bail!("mandate position limit must be positive");
        }
        if !(1..=100).contains(&self.max_leverage) {
            bail!("mandate leverage must be from 1 through 100");
        }
        if self.daily_loss_stop == 0 {
            bail!("mandate daily loss stop must be positive");
        }
        if self.min_liquidation_buffer_bps > 10_000 {
            bail!("mandate liquidation buffer must not exceed 10000 basis points");
        }
        if self.allowed_strategies.is_empty() {
            bail!("mandate must allow at least one strategy");
        }
        for strategy_id in &self.allowed_strategies {
            validate_identifier("strategy ID", strategy_id)?;
        }
        self.review_cadence.validate()?;
        if self.expires_at_ms <= 0 {
            bail!("mandate expiry must be a positive timestamp");
        }
        Ok(())
    }
}

// Mandates for the pre-scoping shape (LN Markets, sats collateral) keep the
// original field layout — no `venue`/`collateral_asset` fields and the
// `*_sats` limit names — so approval digests recorded by earlier releases
// still verify against byte-identical serialized candidates.
impl Serialize for TradingMandate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.is_legacy_shape() {
            let mut state = serializer.serialize_struct("TradingMandate", 11)?;
            state.serialize_field("network", &self.network)?;
            state.serialize_field("objective", &self.objective)?;
            state.serialize_field("max_venue_balance_sats", &self.max_venue_balance)?;
            state.serialize_field("max_position_usd", &self.max_position_usd)?;
            state.serialize_field("max_leverage", &self.max_leverage)?;
            state.serialize_field("daily_loss_stop_sats", &self.daily_loss_stop)?;
            state.serialize_field("max_orders_per_hour", &self.max_orders_per_hour)?;
            state.serialize_field(
                "min_liquidation_buffer_bps",
                &self.min_liquidation_buffer_bps,
            )?;
            state.serialize_field("allowed_strategies", &self.allowed_strategies)?;
            state.serialize_field("review_cadence", &self.review_cadence)?;
            state.serialize_field("expires_at_ms", &self.expires_at_ms)?;
            state.end()
        } else {
            let mut state = serializer.serialize_struct("TradingMandate", 14)?;
            state.serialize_field("venue", &self.venue)?;
            state.serialize_field("network", &self.network)?;
            // The principal scope dimension (WP-5) is included in the
            // non-legacy serialization only, so pre-scoping byte-identical
            // approval digests stay verifiable (design §6.3.6).
            state.serialize_field("principal_pubkey", &self.principal_pubkey)?;
            state.serialize_field("collateral_asset", &self.collateral_asset)?;
            state.serialize_field("objective", &self.objective)?;
            state.serialize_field("max_venue_balance", &self.max_venue_balance)?;
            state.serialize_field("max_position_usd", &self.max_position_usd)?;
            state.serialize_field("max_leverage", &self.max_leverage)?;
            state.serialize_field("daily_loss_stop", &self.daily_loss_stop)?;
            state.serialize_field("max_orders_per_hour", &self.max_orders_per_hour)?;
            state.serialize_field(
                "min_liquidation_buffer_bps",
                &self.min_liquidation_buffer_bps,
            )?;
            state.serialize_field("allowed_strategies", &self.allowed_strategies)?;
            state.serialize_field("review_cadence", &self.review_cadence)?;
            state.serialize_field("expires_at_ms", &self.expires_at_ms)?;
            state.end()
        }
    }
}

#[derive(Deserialize)]
struct TradingMandateRepr {
    // Old records governed LN Markets implicitly and denominated in sats.
    #[serde(default = "legacy_venue")]
    venue: String,
    network: TradingNetwork,
    // Pre-principal-keying rows carry no principal scope (None = venue-wide).
    #[serde(default)]
    principal_pubkey: Option<String>,
    #[serde(default = "AssetId::sats")]
    collateral_asset: AssetId,
    objective: String,
    #[serde(alias = "max_venue_balance_sats")]
    max_venue_balance: u64,
    max_position_usd: u64,
    max_leverage: u8,
    #[serde(alias = "daily_loss_stop_sats")]
    daily_loss_stop: u64,
    // Old mandates receive no hourly order authority until a person reviews them.
    #[serde(default)]
    max_orders_per_hour: u32,
    // Old mandates require maximum distance from liquidation until reviewed.
    #[serde(default = "legacy_liquidation_buffer_bps")]
    min_liquidation_buffer_bps: u32,
    allowed_strategies: BTreeSet<String>,
    review_cadence: ReviewCadence,
    expires_at_ms: i64,
}

impl From<TradingMandateRepr> for TradingMandate {
    fn from(repr: TradingMandateRepr) -> Self {
        Self {
            venue: repr.venue,
            network: repr.network,
            principal_pubkey: repr.principal_pubkey,
            collateral_asset: repr.collateral_asset,
            objective: repr.objective,
            max_venue_balance: repr.max_venue_balance,
            max_position_usd: repr.max_position_usd,
            max_leverage: repr.max_leverage,
            daily_loss_stop: repr.daily_loss_stop,
            max_orders_per_hour: repr.max_orders_per_hour,
            min_liquidation_buffer_bps: repr.min_liquidation_buffer_bps,
            allowed_strategies: repr.allowed_strategies,
            review_cadence: repr.review_cadence,
            expires_at_ms: repr.expires_at_ms,
        }
    }
}

impl<'de> Deserialize<'de> for TradingMandate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(TradingMandateRepr::deserialize(deserializer)?.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateChangeClass {
    Creation,
    Widening,
    Restriction,
    Unchanged,
}

impl MandateChangeClass {
    pub fn needs_ui_approval(self) -> bool {
        matches!(self, Self::Creation | Self::Widening)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MandateProposal {
    base_revision: u64,
    candidate: TradingMandate,
    change_class: MandateChangeClass,
    digest: String,
}

impl MandateProposal {
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    pub fn candidate(&self) -> &TradingMandate {
        &self.candidate
    }

    pub fn change_class(&self) -> MandateChangeClass {
        self.change_class
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateRevisionKind {
    Creation,
    Widening,
    Restriction,
    Revocation,
}

impl MandateRevisionKind {
    fn needs_ui_approval(self) -> bool {
        matches!(self, Self::Creation | Self::Widening)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MandateRevision {
    pub revision: u64,
    pub changed_at_ms: i64,
    pub kind: MandateRevisionKind,
    pub mandate: Option<TradingMandate>,
    pub approval_digest: Option<String>,
    // Pre-scoping rows carry no explicit scope; revocations recorded since
    // venue scoping name the (venue, network) pair they revoke. The
    // principal-keyed scope dimension (WP-5) is carried on the same row:
    // NULL = the venue-wide (None) scope.
    #[serde(default)]
    pub venue: Option<String>,
    #[serde(default)]
    pub network: Option<TradingNetwork>,
    #[serde(default)]
    pub principal_pubkey: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MandateSnapshot {
    pub revision: u64,
    pub mandates: Vec<TradingMandate>,
}

impl MandateSnapshot {
    /// The venue-wide mandate for the (venue, network) pair (pre-principal-keying
    /// semantics, unchanged). Principal-keyed mandates are selected with
    /// [`MandateSnapshot::mandate_for_principal`].
    pub fn mandate_for(&self, venue: &str, network: TradingNetwork) -> Option<&TradingMandate> {
        self.mandate_for_principal(venue, network, None)
    }

    /// Exact-scope lookup on the (venue, network, principal) triple (WP-5).
    /// `None` principal selects the venue-wide mandate for the pair.
    pub fn mandate_for_principal(
        &self,
        venue: &str,
        network: TradingNetwork,
        principal: Option<&str>,
    ) -> Option<&TradingMandate> {
        self.mandates.iter().find(|mandate| {
            mandate.venue == venue
                && mandate.network == network
                && mandate.principal_pubkey.as_deref() == principal
        })
    }
}

#[derive(Deserialize)]
struct MandateSnapshotRepr {
    revision: u64,
    // Pre-scoping snapshots recorded one optional mandate.
    #[serde(default)]
    mandate: Option<TradingMandate>,
    #[serde(default)]
    mandates: Vec<TradingMandate>,
}

impl<'de> Deserialize<'de> for MandateSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = MandateSnapshotRepr::deserialize(deserializer)?;
        let mut mandates = repr.mandates;
        if let Some(mandate) = repr.mandate
            && mandates.is_empty()
        {
            mandates.push(mandate);
        }
        Ok(Self {
            revision: repr.revision,
            mandates,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TradingInstruction {
    pub venue: String,
    pub network: TradingNetwork,
    pub strategy_id: String,
    pub collateral_asset: AssetId,
    pub venue_balance_after: u64,
    pub position_notional_usd: u64,
    pub leverage: u8,
    pub daily_realized_loss: u64,
    pub orders_last_hour: u32,
    pub liquidation_buffer_bps: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredRiskPosture {
    FlatRisk,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MandateRefusal {
    Missing,
    /// A principal was supplied but no mandate authorizes that principal for
    /// the (venue, network) pair — and the venue-wide fallback either does not
    /// exist or the venue is principal-only (SEC-2026-043).
    PrincipalNotAuthorized {
        principal: String,
    },
    Expired {
        expires_at_ms: i64,
    },
    NetworkNotAllowed,
    StrategyNotAllowed {
        strategy_id: String,
    },
    CollateralAssetMismatch {
        mandate_asset: AssetId,
        instruction_asset: AssetId,
    },
    VenueBalanceLimit {
        #[serde(default = "AssetId::sats")]
        asset: AssetId,
        #[serde(alias = "limit_sats")]
        limit: u64,
        #[serde(alias = "requested_sats")]
        requested: u64,
    },
    PositionLimit {
        limit_usd: u64,
        requested_usd: u64,
    },
    LeverageLimit {
        limit: u8,
        requested: u8,
    },
    DailyLossStop {
        #[serde(default = "AssetId::sats")]
        asset: AssetId,
        #[serde(alias = "limit_sats")]
        limit: u64,
        #[serde(alias = "loss_sats")]
        loss: u64,
    },
    HourlyOrderLimit {
        limit: u32,
        orders_last_hour: u32,
    },
    LiquidationBufferFloor {
        minimum_bps: u32,
        current_bps: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MandateDecision {
    Authorized {
        revision: u64,
    },
    Refused {
        reason: MandateRefusal,
        required_posture: RequiredRiskPosture,
    },
}

#[derive(Clone)]
pub struct MandateStore {
    connection: Arc<Mutex<Connection>>,
}

impl MandateStore {
    pub fn default_path() -> PathBuf {
        paths::data_dir().join("threads").join("trading-mandate.db")
    }

    pub fn open_default() -> Result<Self> {
        Self::open(&Self::default_path())
    }

    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("could not create trading mandate directory {parent:?}")
            })?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("could not open trading mandate store {path:?}"))?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )?;
        migrate_legacy_single_scope_store(&connection)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS trading_mandate_revisions (
                 revision INTEGER PRIMARY KEY CHECK (revision > 0),
                 changed_at_ms INTEGER NOT NULL CHECK (changed_at_ms >= 0),
                 kind TEXT NOT NULL,
                 mandate_json TEXT,
                 approval_digest TEXT,
                 venue TEXT,
                 network TEXT,
                 principal_pubkey TEXT
             ) STRICT;
             CREATE TRIGGER IF NOT EXISTS trading_mandate_no_update
             BEFORE UPDATE ON trading_mandate_revisions BEGIN
                 SELECT RAISE(ABORT, 'trading mandate history is append-only');
             END;
             CREATE TRIGGER IF NOT EXISTS trading_mandate_no_delete
             BEFORE DELETE ON trading_mandate_revisions BEGIN
                 SELECT RAISE(ABORT, 'trading mandate history is append-only');
             END;",
        )?;
        connection.pragma_update(None, "user_version", MANDATE_SCHEMA_VERSION)?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
        };
        store.verify()?;
        Ok(store)
    }

    pub fn snapshot(&self) -> Result<MandateSnapshot> {
        let revisions = load_revisions(&self.connection.lock())?;
        let replay = verify_revisions(&revisions)?;
        Ok(replay.snapshot())
    }

    pub fn history(&self) -> Result<Vec<MandateRevision>> {
        let revisions = load_revisions(&self.connection.lock())?;
        verify_revisions(&revisions)?;
        Ok(revisions)
    }

    pub fn verify(&self) -> Result<()> {
        verify_revisions(&load_revisions(&self.connection.lock())?)?;
        Ok(())
    }

    pub fn propose(&self, candidate: TradingMandate) -> Result<MandateProposal> {
        candidate.validate()?;
        let revisions = load_revisions(&self.connection.lock())?;
        let replay = verify_revisions(&revisions)?;
        make_proposal(
            replay.revision,
            replay.active.get(&scope_of(&candidate)),
            candidate,
        )
    }

    pub fn save_restriction(
        &self,
        proposal: MandateProposal,
        changed_at_ms: i64,
    ) -> Result<MandateSnapshot> {
        validate_timestamp(changed_at_ms)?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let revisions = load_revisions(&transaction)?;
        let replay = verify_revisions(&revisions)?;
        let proposal = revalidate_proposal(&proposal, &replay)?;
        match proposal.change_class {
            MandateChangeClass::Creation | MandateChangeClass::Widening => {
                bail!("creating or widening a mandate requires explicit UI approval")
            }
            MandateChangeClass::Unchanged => {
                transaction.commit()?;
                return Ok(replay.snapshot());
            }
            MandateChangeClass::Restriction => {}
        }
        let scope = scope_of(&proposal.candidate);
        append_revision(
            &transaction,
            &revisions,
            changed_at_ms,
            MandateRevisionKind::Restriction,
            Some(proposal.candidate),
            None,
            Some(scope),
        )?;
        transaction.commit()?;
        let revisions = load_revisions(&connection)?;
        Ok(verify_revisions(&revisions)?.snapshot())
    }

    /// This is the single widening door. Repository policy limits production
    /// call sites to the settings UI, which must bind the accepted prompt to
    /// this exact proposal before calling it.
    pub fn apply_ui_approved(
        &self,
        proposal: MandateProposal,
        approved_at_ms: i64,
    ) -> Result<MandateSnapshot> {
        validate_timestamp(approved_at_ms)?;
        if proposal.candidate.expires_at_ms <= approved_at_ms {
            bail!("an approved mandate must expire in the future");
        }
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let revisions = load_revisions(&transaction)?;
        let replay = verify_revisions(&revisions)?;
        let proposal = revalidate_proposal(&proposal, &replay)?;
        let kind = match proposal.change_class {
            MandateChangeClass::Creation => MandateRevisionKind::Creation,
            MandateChangeClass::Widening => MandateRevisionKind::Widening,
            MandateChangeClass::Restriction | MandateChangeClass::Unchanged => {
                bail!("UI approval is reserved for mandate creation or widening")
            }
        };
        let scope = scope_of(&proposal.candidate);
        append_revision(
            &transaction,
            &revisions,
            approved_at_ms,
            kind,
            Some(proposal.candidate),
            Some(proposal.digest),
            Some(scope),
        )?;
        transaction.commit()?;
        let revisions = load_revisions(&connection)?;
        Ok(verify_revisions(&revisions)?.snapshot())
    }

    pub fn revoke(
        &self,
        venue: &str,
        network: TradingNetwork,
        changed_at_ms: i64,
    ) -> Result<MandateSnapshot> {
        validate_timestamp(changed_at_ms)?;
        validate_identifier("venue", venue)?;
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let revisions = load_revisions(&transaction)?;
        let replay = verify_revisions(&revisions)?;
        // Revocation keeps the pre-principal-keying signature and semantics:
        // it removes the VENUE-WIDE (None) mandate for the pair. Revoking a
        // principal-keyed mandate needs a principal-aware scope and is not
        // wired in this WP (open question OQ-WP5-3).
        let scope = (venue.to_owned(), network, None);
        if !replay.active.contains_key(&scope) {
            transaction.commit()?;
            return Ok(replay.snapshot());
        }
        append_revision(
            &transaction,
            &revisions,
            changed_at_ms,
            MandateRevisionKind::Revocation,
            None,
            None,
            Some(scope),
        )?;
        transaction.commit()?;
        let revisions = load_revisions(&connection)?;
        Ok(verify_revisions(&revisions)?.snapshot())
    }

    /// Authorize an instruction. `principal` is the spending agent's Nostr
    /// pubkey hex (64-hex) when the flow is principal-keyed, `None` for
    /// non-principal flows (e.g. nautilus). Resolution order (design §6.3.3,
    /// SEC-2026-043): an exact `(venue, network, Some(principal))` mandate
    /// first; then the venue-wide `(venue, network, None)` mandate — except on
    /// principal-only venues (sovereign-wallet) where the venue-wide fallback
    /// never applies. `PrincipalNotAuthorized` fires when a principal was
    /// supplied and no mandate authorizes it.
    pub fn authorize(
        &self,
        instruction: &TradingInstruction,
        principal: Option<&str>,
        now_ms: i64,
    ) -> Result<MandateDecision> {
        validate_timestamp(now_ms)?;
        validate_identifier("venue", &instruction.venue)?;
        validate_identifier("strategy ID", &instruction.strategy_id)?;
        if let Some(principal) = principal
            && !is_valid_pubkey_hex(principal)
        {
            // A malformed principal can never match a stored mandate (mandate
            // `principal_pubkey` values are validated 64-hex), so the honest
            // refusal is PrincipalNotAuthorized for the supplied value.
            return Ok(refused(MandateRefusal::PrincipalNotAuthorized {
                principal: principal.to_string(),
            }));
        }
        let snapshot = self.snapshot()?;
        let Some(mandate) = resolve_mandate(&snapshot, &instruction.venue, instruction.network, principal)
        else {
            return Ok(match principal {
                Some(principal) => refused(MandateRefusal::PrincipalNotAuthorized {
                    principal: principal.to_string(),
                }),
                None => refused(MandateRefusal::Missing),
            });
        };
        if now_ms >= mandate.expires_at_ms {
            return Ok(refused(MandateRefusal::Expired {
                expires_at_ms: mandate.expires_at_ms,
            }));
        }
        if !mandate
            .allowed_strategies
            .contains(&instruction.strategy_id)
        {
            return Ok(refused(MandateRefusal::StrategyNotAllowed {
                strategy_id: instruction.strategy_id.clone(),
            }));
        }
        if instruction.collateral_asset != mandate.collateral_asset {
            return Ok(refused(MandateRefusal::CollateralAssetMismatch {
                mandate_asset: mandate.collateral_asset.clone(),
                instruction_asset: instruction.collateral_asset.clone(),
            }));
        }
        if instruction.venue_balance_after > mandate.max_venue_balance {
            return Ok(refused(MandateRefusal::VenueBalanceLimit {
                asset: mandate.collateral_asset.clone(),
                limit: mandate.max_venue_balance,
                requested: instruction.venue_balance_after,
            }));
        }
        if instruction.position_notional_usd > mandate.max_position_usd {
            return Ok(refused(MandateRefusal::PositionLimit {
                limit_usd: mandate.max_position_usd,
                requested_usd: instruction.position_notional_usd,
            }));
        }
        if instruction.leverage > mandate.max_leverage {
            return Ok(refused(MandateRefusal::LeverageLimit {
                limit: mandate.max_leverage,
                requested: instruction.leverage,
            }));
        }
        if instruction.daily_realized_loss >= mandate.daily_loss_stop {
            return Ok(refused(MandateRefusal::DailyLossStop {
                asset: mandate.collateral_asset.clone(),
                limit: mandate.daily_loss_stop,
                loss: instruction.daily_realized_loss,
            }));
        }
        if instruction.orders_last_hour >= mandate.max_orders_per_hour {
            return Ok(refused(MandateRefusal::HourlyOrderLimit {
                limit: mandate.max_orders_per_hour,
                orders_last_hour: instruction.orders_last_hour,
            }));
        }
        if instruction.position_notional_usd > 0
            && instruction.leverage > 1
            && instruction.liquidation_buffer_bps < mandate.min_liquidation_buffer_bps
        {
            return Ok(refused(MandateRefusal::LiquidationBufferFloor {
                minimum_bps: mandate.min_liquidation_buffer_bps,
                current_bps: instruction.liquidation_buffer_bps,
            }));
        }
        Ok(MandateDecision::Authorized {
            revision: snapshot.revision,
        })
    }
}

fn refused(reason: MandateRefusal) -> MandateDecision {
    MandateDecision::Refused {
        reason,
        required_posture: RequiredRiskPosture::FlatRisk,
    }
}

/// Test-support seam (WP-5): lets another crate's mandate-gate tests set up an
/// approved mandate without adding a production widening caller. This is the
/// same store call the settings-UI approval path performs; it exists so the
/// spend-gate tests in `sovereign_wallet` can create approved state without
/// duplicating the widening door. Production callers must keep using the
/// settings-UI approval path (OMEGA-DELTA-0245).
#[doc(hidden)]
pub fn apply_ui_approved_for_test(
    store: &MandateStore,
    proposal: MandateProposal,
    approved_at_ms: i64,
) -> Result<MandateSnapshot> {
    store.apply_ui_approved(proposal, approved_at_ms)
}

/// The mandate scope key: (venue, network, principal). `None` principal is
/// the venue-wide scope (legacy semantics, unchanged).
type MandateScope = (String, TradingNetwork, Option<String>);

fn scope_of(mandate: &TradingMandate) -> MandateScope {
    (
        mandate.venue.clone(),
        mandate.network,
        mandate.principal_pubkey.clone(),
    )
}

/// SEC-2026-043 (resolved by the founder: principal-only for the
/// sovereign-wallet venue): a mandate for that venue without a
/// `principal_pubkey` is refused by the widening door (`propose` →
/// `apply_ui_approved`), so no venue-wide sovereign-wallet mandate can ever
/// exist to fall back on.
fn venue_policy_check(candidate: &TradingMandate) -> Result<()> {
    if is_principal_only_venue(&candidate.venue) && candidate.principal_pubkey.is_none() {
        bail!(
            "the {SOVEREIGN_WALLET_VENUE} venue is principal-only; a mandate for it must carry principal_pubkey (SEC-2026-043)"
        );
    }
    Ok(())
}

/// Resolve the governing mandate for a (venue, network, principal) request
/// (design §6.3.3 + SEC-2026-043): exact principal scope first; venue-wide
/// fallback for non-principal-only venues; NO venue-wide fallback on
/// principal-only venues.
fn resolve_mandate<'a>(
    snapshot: &'a MandateSnapshot,
    venue: &str,
    network: TradingNetwork,
    principal: Option<&str>,
) -> Option<&'a TradingMandate> {
    if let Some(principal) = principal {
        if let Some(exact) = snapshot.mandate_for_principal(venue, network, Some(principal)) {
            return Some(exact);
        }
        if is_principal_only_venue(venue) {
            return None; // SEC-2026-043: the venue-wide fallback never applies here.
        }
    }
    snapshot.mandate_for_principal(venue, network, None)
}

/// Nostr public keys in this store are 64 hex characters (design §6.3.1).
fn is_valid_pubkey_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

struct MandateReplay {
    revision: u64,
    active: BTreeMap<MandateScope, TradingMandate>,
}

impl MandateReplay {
    fn snapshot(&self) -> MandateSnapshot {
        MandateSnapshot {
            revision: self.revision,
            mandates: self.active.values().cloned().collect(),
        }
    }
}

// Version 1 stores predate scoped rows; the added columns stay NULL for
// existing rows, whose scope is recovered from the mandate itself during
// replay. WP-5 adds the principal-keyed scope dimension as an additive
// nullable column on the same table (legacy rows NULL → None = venue-wide).
fn migrate_legacy_single_scope_store(connection: &Connection) -> Result<()> {
    let table_exists = connection
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'trading_mandate_revisions'")?
        .exists([])?;
    if !table_exists {
        return Ok(());
    }
    let has_scope_columns = connection
        .prepare(
            "SELECT 1 FROM pragma_table_info('trading_mandate_revisions') WHERE name = 'venue'",
        )?
        .exists([])?;
    if !has_scope_columns {
        connection.execute_batch(
            "ALTER TABLE trading_mandate_revisions ADD COLUMN venue TEXT;
             ALTER TABLE trading_mandate_revisions ADD COLUMN network TEXT;",
        )?;
    }
    let has_principal_column = connection
        .prepare(
            "SELECT 1 FROM pragma_table_info('trading_mandate_revisions') WHERE name = 'principal_pubkey'",
        )?
        .exists([])?;
    if !has_principal_column {
        connection.execute_batch(
            "ALTER TABLE trading_mandate_revisions ADD COLUMN principal_pubkey TEXT;",
        )?;
    }
    Ok(())
}

fn revalidate_proposal(
    proposal: &MandateProposal,
    replay: &MandateReplay,
) -> Result<MandateProposal> {
    if replay.revision != proposal.base_revision {
        bail!("mandate changed after the proposal was displayed; review the current limits again");
    }
    let current = make_proposal(
        replay.revision,
        replay.active.get(&scope_of(&proposal.candidate)),
        proposal.candidate.clone(),
    )?;
    if current != *proposal {
        bail!("mandate proposal no longer matches the approved limits");
    }
    Ok(current)
}

fn make_proposal(
    base_revision: u64,
    current: Option<&TradingMandate>,
    candidate: TradingMandate,
) -> Result<MandateProposal> {
    candidate.validate()?;
    venue_policy_check(&candidate)?;
    let change_class = classify_change(current, &candidate);
    let digest = proposal_digest(base_revision, &candidate)?;
    Ok(MandateProposal {
        base_revision,
        candidate,
        change_class,
        digest,
    })
}

fn classify_change(
    current: Option<&TradingMandate>,
    candidate: &TradingMandate,
) -> MandateChangeClass {
    let Some(current) = current else {
        return MandateChangeClass::Creation;
    };
    if current == candidate {
        return MandateChangeClass::Unchanged;
    }
    let cadence_widens = match (&current.review_cadence, &candidate.review_cadence) {
        (
            ReviewCadence::Interval {
                seconds: current_seconds,
            },
            ReviewCadence::Interval {
                seconds: candidate_seconds,
            },
        ) => candidate_seconds > current_seconds,
        (ReviewCadence::FundingSettlement, ReviewCadence::FundingSettlement) => false,
        _ => true,
    };
    let widens = candidate.venue != current.venue
        || candidate.network != current.network
        || candidate.collateral_asset != current.collateral_asset
        || candidate.objective != current.objective
        || candidate.max_venue_balance > current.max_venue_balance
        || candidate.max_position_usd > current.max_position_usd
        || candidate.max_leverage > current.max_leverage
        || candidate.daily_loss_stop > current.daily_loss_stop
        || candidate.max_orders_per_hour > current.max_orders_per_hour
        || candidate.min_liquidation_buffer_bps < current.min_liquidation_buffer_bps
        || !candidate
            .allowed_strategies
            .is_subset(&current.allowed_strategies)
        || cadence_widens
        || candidate.expires_at_ms > current.expires_at_ms;
    if widens {
        MandateChangeClass::Widening
    } else {
        MandateChangeClass::Restriction
    }
}

fn legacy_venue() -> String {
    LEGACY_VENUE.to_owned()
}

const fn legacy_liquidation_buffer_bps() -> u32 {
    10_000
}

fn proposal_digest(base_revision: u64, candidate: &TradingMandate) -> Result<String> {
    #[derive(Serialize)]
    struct DigestPayload<'a> {
        base_revision: u64,
        candidate: &'a TradingMandate,
    }
    let bytes = serde_json::to_vec(&DigestPayload {
        base_revision,
        candidate,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn append_revision(
    transaction: &Transaction<'_>,
    revisions: &[MandateRevision],
    changed_at_ms: i64,
    kind: MandateRevisionKind,
    mandate: Option<TradingMandate>,
    approval_digest: Option<String>,
    scope: Option<MandateScope>,
) -> Result<MandateRevision> {
    let revision = revisions.last().map_or(Ok(1_u64), |last| {
        last.revision
            .checked_add(1)
            .context("mandate revision overflowed")
    })?;
    let revision_i64 = i64::try_from(revision).context("mandate revision exceeded SQLite range")?;
    let kind_json = serde_json::to_string(&kind)?;
    let mandate_json = mandate.as_ref().map(serde_json::to_string).transpose()?;
    let (venue, network, principal_pubkey) = match &scope {
        Some((venue, network, principal_pubkey)) => {
            (Some(venue.clone()), Some(*network), principal_pubkey.clone())
        }
        None => (None, None, None),
    };
    transaction.execute(
        "INSERT INTO trading_mandate_revisions (
             revision, changed_at_ms, kind, mandate_json, approval_digest, venue, network, principal_pubkey
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            revision_i64,
            changed_at_ms,
            kind_json,
            mandate_json,
            approval_digest,
            venue,
            network.map(TradingNetwork::label),
            principal_pubkey,
        ],
    )?;
    Ok(MandateRevision {
        revision,
        changed_at_ms,
        kind,
        mandate,
        approval_digest,
        venue,
        network,
        principal_pubkey,
    })
}

fn load_revisions(connection: &Connection) -> Result<Vec<MandateRevision>> {
    let mut statement = connection.prepare(
        "SELECT revision, changed_at_ms, kind, mandate_json, approval_digest, venue, network, principal_pubkey
         FROM trading_mandate_revisions ORDER BY revision",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let mut revisions = Vec::new();
    for row in rows {
        let (
            revision,
            changed_at_ms,
            kind_json,
            mandate_json,
            approval_digest,
            venue,
            network,
            principal_pubkey,
        ) = row?;
        revisions.push(MandateRevision {
            revision: u64::try_from(revision).context("mandate revision was negative")?,
            changed_at_ms,
            kind: serde_json::from_str(&kind_json)
                .context("mandate revision kind is not valid JSON")?,
            mandate: mandate_json
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .context("mandate revision is not valid JSON")?,
            approval_digest,
            venue,
            network: network
                .as_deref()
                .map(TradingNetwork::parse)
                .transpose()
                .context("mandate revision names an unknown network")?,
            principal_pubkey,
        });
    }
    Ok(revisions)
}

fn verify_revisions(revisions: &[MandateRevision]) -> Result<MandateReplay> {
    let mut expected_revision = 1_u64;
    let mut active = BTreeMap::<MandateScope, TradingMandate>::new();
    for revision in revisions {
        if revision.revision != expected_revision {
            bail!(
                "trading mandate revision gap: expected {}, found {}",
                expected_revision,
                revision.revision
            );
        }
        validate_timestamp(revision.changed_at_ms)?;
        match (&revision.kind, &revision.mandate) {
            (MandateRevisionKind::Revocation, None) => {
                if revision.approval_digest.is_some() {
                    bail!("mandate revocation must not carry a widening approval");
                }
                let scope = match (&revision.venue, revision.network, &revision.principal_pubkey) {
                    (Some(venue), Some(network), principal) => {
                        (venue.clone(), network, principal.clone())
                    }
                    // Pre-scoping revocations named no scope; they were only
                    // valid while exactly one mandate was active.
                    _ => {
                        if active.len() != 1 {
                            bail!(
                                "a scope-less mandate revocation requires exactly one active mandate"
                            );
                        }
                        active
                            .keys()
                            .next()
                            .cloned()
                            .context("mandate replay lost its active scope")?
                    }
                };
                if active.remove(&scope).is_none() {
                    bail!("mandate history revokes an absent mandate");
                }
            }
            (kind, Some(mandate)) => {
                mandate.validate()?;
                let scope = scope_of(mandate);
                if let (Some(venue), Some(network)) = (&revision.venue, revision.network)
                    && (venue != &scope.0
                        || network != scope.1
                        || revision.principal_pubkey != scope.2)
                {
                    bail!("mandate revision scope does not match its mandate");
                }
                let proposal = make_proposal(
                    revision.revision.saturating_sub(1),
                    active.get(&scope),
                    mandate.clone(),
                )?;
                if proposal.change_class == MandateChangeClass::Unchanged {
                    bail!("mandate history contains an unchanged revision");
                }
                // Creation and Widening carry the same approval requirement;
                // accepting either label lets pre-scoping histories that moved
                // a single slot across networks keep verifying, without
                // loosening the approval boundary itself.
                if kind.needs_ui_approval() != proposal.change_class.needs_ui_approval() {
                    bail!("mandate revision kind does not match its limit change");
                }
                match proposal.change_class.needs_ui_approval() {
                    true if revision.approval_digest.as_deref() != Some(&proposal.digest) => {
                        bail!("mandate creation or widening lacks its bound UI approval")
                    }
                    false if revision.approval_digest.is_some() => {
                        bail!("mandate restriction carries an unexpected widening approval")
                    }
                    _ => {}
                }
                active.insert(scope, mandate.clone());
            }
            (_, None) => bail!("non-revocation mandate history row has no mandate"),
        }
        expected_revision = expected_revision
            .checked_add(1)
            .context("mandate revision overflowed during verification")?;
    }
    Ok(MandateReplay {
        revision: expected_revision.saturating_sub(1),
        active,
    })
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("mandate {label} must not be empty");
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        bail!("mandate {label} must not exceed {MAX_IDENTIFIER_LENGTH} bytes");
    }
    Ok(())
}

fn validate_timestamp(timestamp_ms: i64) -> Result<()> {
    if timestamp_ms < 0 {
        bail!("mandate timestamp must not be negative");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strategies(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn mandate() -> TradingMandate {
        TradingMandate {
            venue: LEGACY_VENUE.into(),
            network: TradingNetwork::Signet,
            principal_pubkey: None,
            collateral_asset: AssetId::sats(),
            objective: "Maximize ledger profit in sats".into(),
            max_venue_balance: 100_000,
            max_position_usd: 500,
            max_leverage: 3,
            daily_loss_stop: 5_000,
            max_orders_per_hour: 12,
            min_liquidation_buffer_bps: 1_500,
            allowed_strategies: strategies(&["rebalance_to_target"]),
            review_cadence: ReviewCadence::FundingSettlement,
            expires_at_ms: 10_000,
        }
    }

    fn usdc_mandate() -> TradingMandate {
        TradingMandate {
            venue: "hyperliquid".into(),
            network: TradingNetwork::Mainnet,
            principal_pubkey: None,
            collateral_asset: AssetId::usdc(),
            objective: "Carry funding in USDC".into(),
            max_venue_balance: 250_000_000,
            max_position_usd: 200,
            max_leverage: 2,
            daily_loss_stop: 10_000_000,
            max_orders_per_hour: 6,
            min_liquidation_buffer_bps: 2_000,
            allowed_strategies: strategies(&["hl_funding_carry"]),
            review_cadence: ReviewCadence::Interval { seconds: 3_600 },
            expires_at_ms: 10_000,
        }
    }

    fn approve(store: &MandateStore, candidate: TradingMandate, now: i64) -> MandateSnapshot {
        let proposal = store.propose(candidate).expect("proposal");
        assert!(proposal.change_class().needs_ui_approval());
        store
            .apply_ui_approved(proposal, now)
            .expect("approved mandate")
    }

    fn instruction() -> TradingInstruction {
        TradingInstruction {
            venue: LEGACY_VENUE.into(),
            network: TradingNetwork::Signet,
            strategy_id: "rebalance_to_target".into(),
            collateral_asset: AssetId::sats(),
            venue_balance_after: 80_000,
            position_notional_usd: 400,
            leverage: 2,
            daily_realized_loss: 1_000,
            orders_last_hour: 2,
            liquidation_buffer_bps: 2_500,
        }
    }

    #[test]
    fn legacy_mandate_json_defaults_new_limits_to_fail_closed_values() {
        let value = serde_json::json!({
            "network": "signet",
            "objective": "Legacy mandate",
            "max_venue_balance_sats": 100_000,
            "max_position_usd": 500,
            "max_leverage": 3,
            "daily_loss_stop_sats": 5_000,
            "allowed_strategies": ["rebalance_to_target"],
            "review_cadence": { "type": "funding_settlement" },
            "expires_at_ms": 10_000
        });
        let decoded: TradingMandate = serde_json::from_value(value).expect("legacy mandate");

        assert_eq!(decoded.max_orders_per_hour, 0);
        assert_eq!(decoded.min_liquidation_buffer_bps, 10_000);
        assert_eq!(decoded.venue, LEGACY_VENUE);
        assert!(decoded.collateral_asset.is_sats());
        assert_eq!(decoded.max_venue_balance, 100_000);
        assert_eq!(decoded.daily_loss_stop, 5_000);
    }

    #[test]
    fn legacy_shape_mandates_serialize_with_their_original_layout() {
        let encoded = serde_json::to_value(mandate()).expect("serialize");
        let object = encoded.as_object().expect("object");
        assert!(!object.contains_key("venue"));
        assert!(!object.contains_key("collateral_asset"));
        assert_eq!(object["max_venue_balance_sats"], 100_000);
        assert_eq!(object["daily_loss_stop_sats"], 5_000);
        assert_eq!(
            serde_json::from_value::<TradingMandate>(encoded).expect("round trip"),
            mandate()
        );

        let encoded = serde_json::to_value(usdc_mandate()).expect("serialize usdc");
        let object = encoded.as_object().expect("object");
        assert_eq!(object["venue"], "hyperliquid");
        assert_eq!(object["collateral_asset"], "usdc");
        assert_eq!(object["max_venue_balance"], 250_000_000);
        assert_eq!(object["daily_loss_stop"], 10_000_000);
        assert!(!object.contains_key("max_venue_balance_sats"));
        assert_eq!(
            serde_json::from_value::<TradingMandate>(encoded).expect("round trip"),
            usdc_mandate()
        );
    }

    #[test]
    fn testnet_is_a_durable_mandate_scope() {
        let mut mandate = usdc_mandate();
        mandate.network = TradingNetwork::Testnet;
        let store = MandateStore::in_memory().expect("store");
        let snapshot = approve(&store, mandate.clone(), 1);
        assert_eq!(
            snapshot.mandate_for("hyperliquid", TradingNetwork::Testnet),
            Some(&mandate)
        );
        assert!(
            snapshot
                .mandate_for("hyperliquid", TradingNetwork::Mainnet)
                .is_none()
        );
    }

    #[test]
    fn creation_and_every_widening_dimension_require_approval() {
        let store = MandateStore::in_memory().expect("store");
        let initial = mandate();
        let creation = store.propose(initial.clone()).expect("creation");
        assert_eq!(creation.change_class(), MandateChangeClass::Creation);
        assert!(store.save_restriction(creation, 1).is_err());
        approve(&store, initial.clone(), 1);

        let mut candidates = Vec::new();
        let mut objective = initial.clone();
        objective.objective = "A changed objective".into();
        candidates.push(objective);
        let mut venue = initial.clone();
        venue.max_venue_balance += 1;
        candidates.push(venue);
        let mut position = initial.clone();
        position.max_position_usd += 1;
        candidates.push(position);
        let mut leverage = initial.clone();
        leverage.max_leverage += 1;
        candidates.push(leverage);
        let mut loss = initial.clone();
        loss.daily_loss_stop += 1;
        candidates.push(loss);
        let mut order_count = initial.clone();
        order_count.max_orders_per_hour += 1;
        candidates.push(order_count);
        let mut liquidation_buffer = initial.clone();
        liquidation_buffer.min_liquidation_buffer_bps -= 1;
        candidates.push(liquidation_buffer);
        let mut strategies = initial.clone();
        strategies.allowed_strategies.insert("funding_carry".into());
        candidates.push(strategies);
        let mut cadence = initial.clone();
        cadence.review_cadence = ReviewCadence::Interval { seconds: 3_600 };
        candidates.push(cadence);
        let mut collateral = initial.clone();
        collateral.collateral_asset = AssetId::usdc();
        candidates.push(collateral);
        let mut expiry = initial;
        expiry.expires_at_ms += 1;
        candidates.push(expiry);

        for candidate in candidates {
            let proposal = store.propose(candidate).expect("widening proposal");
            assert_eq!(proposal.change_class(), MandateChangeClass::Widening);
            assert!(store.save_restriction(proposal, 2).is_err());
        }
    }

    #[test]
    fn a_mandate_for_a_new_venue_or_network_is_a_creation_requiring_approval() {
        let store = MandateStore::in_memory().expect("store");
        approve(&store, mandate(), 1);

        // A different (venue, network) scope does not widen the existing
        // mandate; it creates a new one, behind the same approval door.
        let mut mainnet = mandate();
        mainnet.network = TradingNetwork::Mainnet;
        let proposal = store.propose(mainnet).expect("mainnet proposal");
        assert_eq!(proposal.change_class(), MandateChangeClass::Creation);
        assert!(store.save_restriction(proposal, 2).is_err());

        let proposal = store.propose(usdc_mandate()).expect("usdc proposal");
        assert_eq!(proposal.change_class(), MandateChangeClass::Creation);
        assert!(store.save_restriction(proposal, 2).is_err());
    }

    #[test]
    fn one_mandate_governs_each_venue_and_network_pair() {
        let store = MandateStore::in_memory().expect("store");
        approve(&store, mandate(), 1);
        approve(&store, usdc_mandate(), 2);

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.mandates.len(), 2);
        assert!(
            snapshot
                .mandate_for(LEGACY_VENUE, TradingNetwork::Signet)
                .is_some()
        );
        assert!(
            snapshot
                .mandate_for("hyperliquid", TradingNetwork::Mainnet)
                .is_some()
        );
        assert!(
            snapshot
                .mandate_for("hyperliquid", TradingNetwork::Signet)
                .is_none()
        );

        // Authorization routes by the instruction's (venue, network) scope;
        // non-principal flows pass None (venue-wide resolution, unchanged).
        assert_eq!(
            store
                .authorize(&instruction(), None, 3)
                .expect("sats decision"),
            MandateDecision::Authorized { revision: 2 }
        );
        let usdc_instruction = TradingInstruction {
            venue: "hyperliquid".into(),
            network: TradingNetwork::Mainnet,
            strategy_id: "hl_funding_carry".into(),
            collateral_asset: AssetId::usdc(),
            venue_balance_after: 200_000_000,
            position_notional_usd: 100,
            leverage: 1,
            daily_realized_loss: 0,
            orders_last_hour: 0,
            liquidation_buffer_bps: 10_000,
        };
        assert_eq!(
            store
                .authorize(&usdc_instruction, None, 3)
                .expect("usdc decision"),
            MandateDecision::Authorized { revision: 2 }
        );
        assert_eq!(
            store
                .authorize(
                    &TradingInstruction {
                        network: TradingNetwork::Signet,
                        ..usdc_instruction.clone()
                    },
                    None,
                    3
                )
                .expect("missing scope"),
            refused(MandateRefusal::Missing)
        );
        assert_eq!(
            store
                .authorize(
                    &TradingInstruction {
                        collateral_asset: AssetId::sats(),
                        ..usdc_instruction
                    },
                    None,
                    3
                )
                .expect("collateral mismatch"),
            refused(MandateRefusal::CollateralAssetMismatch {
                mandate_asset: AssetId::usdc(),
                instruction_asset: AssetId::sats(),
            })
        );

        // Revocation removes exactly one scope.
        let snapshot = store
            .revoke("hyperliquid", TradingNetwork::Mainnet, 4)
            .expect("revoke");
        assert_eq!(snapshot.mandates.len(), 1);
        assert!(
            snapshot
                .mandate_for(LEGACY_VENUE, TradingNetwork::Signet)
                .is_some()
        );
    }

    #[test]
    fn narrowing_and_revocation_apply_without_approval() {
        let store = MandateStore::in_memory().expect("store");
        let initial = mandate();
        approve(&store, initial.clone(), 1);
        let mut narrow = initial;
        narrow.max_position_usd -= 1;
        narrow.allowed_strategies.clear();
        narrow
            .allowed_strategies
            .insert("rebalance_to_target".into());
        narrow.expires_at_ms -= 1;
        let proposal = store.propose(narrow.clone()).expect("restriction");
        assert_eq!(proposal.change_class(), MandateChangeClass::Restriction);
        let snapshot = store.save_restriction(proposal, 2).expect("save");
        assert_eq!(
            snapshot.mandate_for(LEGACY_VENUE, TradingNetwork::Signet),
            Some(&narrow)
        );
        assert!(
            store
                .revoke(LEGACY_VENUE, TradingNetwork::Signet, 3)
                .expect("revoke")
                .mandates
                .is_empty()
        );
    }

    #[test]
    fn approval_is_bound_to_the_displayed_revision_and_candidate() {
        let store = MandateStore::in_memory().expect("store");
        let initial = mandate();
        approve(&store, initial.clone(), 1);
        let mut wider = initial.clone();
        wider.max_leverage += 1;
        let stale = store.propose(wider).expect("widening");

        let mut narrower = initial;
        narrower.max_position_usd -= 1;
        let restriction = store.propose(narrower).expect("restriction");
        store.save_restriction(restriction, 2).expect("save");
        assert!(store.apply_ui_approved(stale, 3).is_err());
    }

    #[test]
    fn instruction_enforcement_fails_closed_for_every_limit() {
        let store = MandateStore::in_memory().expect("store");
        assert_eq!(
            store.authorize(&instruction(), None, 1).expect("decision"),
            refused(MandateRefusal::Missing)
        );
        approve(&store, mandate(), 1);
        assert_eq!(
            store.authorize(&instruction(), None, 2).expect("decision"),
            MandateDecision::Authorized { revision: 1 }
        );

        let cases = [
            (
                TradingInstruction {
                    network: TradingNetwork::Mainnet,
                    ..instruction()
                },
                MandateRefusal::Missing,
            ),
            (
                TradingInstruction {
                    venue: "hyperliquid".into(),
                    ..instruction()
                },
                MandateRefusal::Missing,
            ),
            (
                TradingInstruction {
                    strategy_id: "funding_carry".into(),
                    ..instruction()
                },
                MandateRefusal::StrategyNotAllowed {
                    strategy_id: "funding_carry".into(),
                },
            ),
            (
                TradingInstruction {
                    collateral_asset: AssetId::usdc(),
                    ..instruction()
                },
                MandateRefusal::CollateralAssetMismatch {
                    mandate_asset: AssetId::sats(),
                    instruction_asset: AssetId::usdc(),
                },
            ),
            (
                TradingInstruction {
                    venue_balance_after: 100_001,
                    ..instruction()
                },
                MandateRefusal::VenueBalanceLimit {
                    asset: AssetId::sats(),
                    limit: 100_000,
                    requested: 100_001,
                },
            ),
            (
                TradingInstruction {
                    position_notional_usd: 501,
                    ..instruction()
                },
                MandateRefusal::PositionLimit {
                    limit_usd: 500,
                    requested_usd: 501,
                },
            ),
            (
                TradingInstruction {
                    leverage: 4,
                    ..instruction()
                },
                MandateRefusal::LeverageLimit {
                    limit: 3,
                    requested: 4,
                },
            ),
            (
                TradingInstruction {
                    daily_realized_loss: 5_000,
                    ..instruction()
                },
                MandateRefusal::DailyLossStop {
                    asset: AssetId::sats(),
                    limit: 5_000,
                    loss: 5_000,
                },
            ),
            (
                TradingInstruction {
                    orders_last_hour: 12,
                    ..instruction()
                },
                MandateRefusal::HourlyOrderLimit {
                    limit: 12,
                    orders_last_hour: 12,
                },
            ),
            (
                TradingInstruction {
                    liquidation_buffer_bps: 1_499,
                    ..instruction()
                },
                MandateRefusal::LiquidationBufferFloor {
                    minimum_bps: 1_500,
                    current_bps: 1_499,
                },
            ),
        ];
        for (request, reason) in cases {
            assert_eq!(
                store.authorize(&request, None, 2).expect("decision"),
                refused(reason)
            );
        }
        assert_eq!(
            store.authorize(&instruction(), None, 10_000).expect("expiry"),
            refused(MandateRefusal::Expired {
                expires_at_ms: 10_000
            })
        );
    }

    #[test]
    fn history_is_append_only_and_rejects_unapproved_widening() {
        let store = MandateStore::in_memory().expect("store");
        approve(&store, mandate(), 1);
        assert!(
            store
                .connection
                .lock()
                .execute(
                    "UPDATE trading_mandate_revisions SET changed_at_ms = 2 WHERE revision = 1",
                    [],
                )
                .is_err()
        );
        store
            .connection
            .lock()
            .execute_batch("DROP TRIGGER trading_mandate_no_update")
            .expect("drop test trigger");
        store
            .connection
            .lock()
            .execute(
                "UPDATE trading_mandate_revisions SET approval_digest = NULL WHERE revision = 1",
                [],
            )
            .expect("tamper fixture");
        assert!(store.verify().is_err());
    }

    #[test]
    fn version_one_stores_migrate_and_their_digests_still_verify() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("trading-mandate.db");
        {
            let connection = Connection::open(&path).expect("raw connection");
            connection
                .execute_batch(
                    "CREATE TABLE trading_mandate_revisions (
                         revision INTEGER PRIMARY KEY CHECK (revision > 0),
                         changed_at_ms INTEGER NOT NULL CHECK (changed_at_ms >= 0),
                         kind TEXT NOT NULL,
                         mandate_json TEXT,
                         approval_digest TEXT
                     ) STRICT;",
                )
                .expect("legacy schema");
            // Legacy rows serialized the pre-scoping field layout, which the
            // current serializer reproduces for LN Markets sats mandates, so
            // the stored digest matches a digest recomputed today.
            let legacy = mandate();
            let digest = proposal_digest(0, &legacy).expect("digest");
            connection
                .execute(
                    "INSERT INTO trading_mandate_revisions (
                         revision, changed_at_ms, kind, mandate_json, approval_digest
                     ) VALUES (1, 1, ?1, ?2, ?3)",
                    params![
                        serde_json::to_string(&MandateRevisionKind::Creation).expect("kind"),
                        serde_json::to_string(&legacy).expect("mandate"),
                        digest,
                    ],
                )
                .expect("legacy creation row");
        }

        let store = MandateStore::open(&path).expect("migrated store");
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot.mandate_for(LEGACY_VENUE, TradingNetwork::Signet),
            Some(&mandate())
        );
        // A pre-scoping revocation row has no scope columns; it still revokes
        // the sole active mandate.
        store
            .connection
            .lock()
            .execute(
                "INSERT INTO trading_mandate_revisions (
                     revision, changed_at_ms, kind, mandate_json, approval_digest, venue, network
                 ) VALUES (2, 2, ?1, NULL, NULL, NULL, NULL)",
                params![serde_json::to_string(&MandateRevisionKind::Revocation).expect("kind")],
            )
            .expect("legacy revocation row");
        assert!(store.snapshot().expect("snapshot").mandates.is_empty());
    }

    #[test]
    fn legacy_snapshot_json_still_deserializes() {
        let decoded: MandateSnapshot = serde_json::from_value(serde_json::json!({
            "revision": 3,
            "mandate": serde_json::to_value(mandate()).expect("mandate"),
        }))
        .expect("legacy snapshot");
        assert_eq!(decoded.revision, 3);
        assert_eq!(decoded.mandates, vec![mandate()]);

        let round_trip: MandateSnapshot =
            serde_json::from_value(serde_json::to_value(decoded.clone()).expect("serialize"))
                .expect("current snapshot");
        assert_eq!(round_trip, decoded);
    }

    #[test]
    fn legacy_refusal_json_still_deserializes() {
        let decoded: MandateRefusal = serde_json::from_value(serde_json::json!({
            "type": "venue_balance_limit",
            "limit_sats": 100_000,
            "requested_sats": 100_001,
        }))
        .expect("legacy refusal");
        assert_eq!(
            decoded,
            MandateRefusal::VenueBalanceLimit {
                asset: AssetId::sats(),
                limit: 100_000,
                requested: 100_001,
            }
        );
        let decoded: MandateRefusal = serde_json::from_value(serde_json::json!({
            "type": "daily_loss_stop",
            "limit_sats": 5_000,
            "loss_sats": 6_000,
        }))
        .expect("legacy loss refusal");
        assert_eq!(
            decoded,
            MandateRefusal::DailyLossStop {
                asset: AssetId::sats(),
                limit: 5_000,
                loss: 6_000,
            }
        );
    }

    #[test]
    fn store_survives_restart_beside_the_thread_store_shape() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("threads/trading-mandate.db");
        let store = MandateStore::open(&path).expect("store");
        approve(&store, mandate(), 1);
        drop(store);
        let reopened = MandateStore::open(&path).expect("reopen");
        assert_eq!(reopened.snapshot().expect("snapshot").revision, 1);
        assert_eq!(reopened.history().expect("history").len(), 1);
    }

    // -----------------------------------------------------------------------
    // WP-5: principal-pubkey-keyed spending authorizations (design §6.3,
    // SEC-2026-043). The scope key is now (venue, network, principal_pubkey);
    // existing venue-wide mandates keep their exact semantics.
    // -----------------------------------------------------------------------

    const AGENT_PUBKEY: &str =
        "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
    const OTHER_PUBKEY: &str =
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn principal_mandate(venue: &str, network: TradingNetwork, principal: &str) -> TradingMandate {
        TradingMandate {
            venue: venue.into(),
            network,
            principal_pubkey: Some(principal.into()),
            collateral_asset: AssetId::sats(),
            objective: "Pubkey-keyed spending authorization".into(),
            max_venue_balance: 50_000,
            max_position_usd: 1,
            max_leverage: 1,
            daily_loss_stop: 50_000,
            max_orders_per_hour: 60,
            min_liquidation_buffer_bps: 0,
            allowed_strategies: strategies(&["wallet_payment"]),
            review_cadence: ReviewCadence::Interval { seconds: 3_600 },
            expires_at_ms: 100_000,
        }
    }

    fn wallet_instruction(amount_sat: u64) -> TradingInstruction {
        TradingInstruction {
            venue: "sovereign-wallet".into(),
            network: TradingNetwork::Signet,
            strategy_id: "wallet_payment".into(),
            collateral_asset: AssetId::sats(),
            venue_balance_after: amount_sat,
            position_notional_usd: 0,
            leverage: 1,
            daily_realized_loss: 0,
            orders_last_hour: 0,
            liquidation_buffer_bps: 10_000,
        }
    }

    #[test]
    fn pubkey_keyed_mandates_are_a_distinct_scope_through_the_approval_door() {
        let store = MandateStore::in_memory().expect("store");
        // A principal-keyed mandate is a new scope: Creation through the same
        // widening door (apply_ui_approved), never save_restriction.
        let candidate = principal_mandate("hyperliquid", TradingNetwork::Testnet, AGENT_PUBKEY);
        let proposal = store.propose(candidate.clone()).expect("principal proposal");
        assert_eq!(proposal.change_class(), MandateChangeClass::Creation);
        assert!(store.save_restriction(proposal, 1).is_err());
        let proposal = store.propose(candidate.clone()).expect("principal proposal");
        store
            .apply_ui_approved(proposal, 1)
            .expect("approved principal mandate");

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.mandate_for_principal("hyperliquid", TradingNetwork::Testnet, Some(AGENT_PUBKEY)),
            Some(&candidate)
        );
        // The venue-wide slot for the same pair is untouched by the
        // principal-keyed mandate (None and Some are distinct scopes).
        assert!(
            snapshot
                .mandate_for_principal("hyperliquid", TradingNetwork::Testnet, None)
                .is_none()
        );

        let mut instruction = instruction();
        instruction.venue = "hyperliquid".into();
        instruction.network = TradingNetwork::Testnet;
        instruction.strategy_id = "wallet_payment".into();
        instruction.collateral_asset = AssetId::sats();
        instruction.venue_balance_after = 10_000;
        instruction.position_notional_usd = 0;
        instruction.leverage = 1;
        // Exact principal matches the principal-keyed mandate.
        assert_eq!(
            store
                .authorize(&instruction, Some(AGENT_PUBKEY), 2)
                .expect("agent decision"),
            MandateDecision::Authorized { revision: 1 }
        );
        // A different principal on a non-principal-only venue falls back to
        // the venue-wide slot — which does not exist here, so the refusal is
        // PrincipalNotAuthorized, not Missing.
        assert_eq!(
            store
                .authorize(&instruction, Some(OTHER_PUBKEY), 2)
                .expect("other principal decision"),
            refused(MandateRefusal::PrincipalNotAuthorized {
                principal: OTHER_PUBKEY.into(),
            })
        );
        // A None-principal flow resolves to the venue-wide slot (absent) →
        // Missing, preserving pre-principal semantics.
        assert_eq!(
            store.authorize(&instruction, None, 2).expect("venue-wide"),
            refused(MandateRefusal::Missing)
        );
    }

    #[test]
    fn venue_wide_fallback_still_authorizes_non_principal_flows() {
        let store = MandateStore::in_memory().expect("store");
        approve(&store, mandate(), 1);
        // A principal-keyed request on a non-principal-only venue with no
        // principal-scoped mandate resolves to the venue-wide mandate exactly
        // as a None-principal flow would (design §6.3.3 conservative default).
        assert_eq!(
            store
                .authorize(&instruction(), Some(AGENT_PUBKEY), 2)
                .expect("venue-wide fallback"),
            MandateDecision::Authorized { revision: 1 }
        );
        assert_eq!(
            store.authorize(&instruction(), None, 2).expect("venue-wide"),
            MandateDecision::Authorized { revision: 1 }
        );
    }

    #[test]
    fn sovereign_wallet_venue_is_principal_only_and_refuses_without_a_principal() {
        let store = MandateStore::in_memory().expect("store");
        // SEC-2026-043 (founder-resolved): a mandate for the sovereign-wallet
        // venue without principal_pubkey is refused by the widening door.
        let mut venue_wide = principal_mandate(
            SOVEREIGN_WALLET_VENUE,
            TradingNetwork::Signet,
            AGENT_PUBKEY,
        );
        venue_wide.principal_pubkey = None;
        let error = store
            .propose(venue_wide)
            .expect_err("a venue-wide sovereign-wallet mandate must be refused");
        assert!(
            error.to_string().contains("principal-only"),
            "expected the SEC-2026-043 principal-only refusal, got: {error}"
        );

        // The principal-keyed sovereign-wallet mandate is the only creatable
        // shape, through the same widening door.
        let candidate =
            principal_mandate(SOVEREIGN_WALLET_VENUE, TradingNetwork::Signet, AGENT_PUBKEY);
        let proposal = store.propose(candidate.clone()).expect("principal proposal");
        store
            .apply_ui_approved(proposal, 1)
            .expect("approved principal mandate");

        // The exact principal spend is authorized.
        let instruction = wallet_instruction(10_000);
        assert_eq!(
            store
                .authorize(&instruction, Some(AGENT_PUBKEY), 2)
                .expect("agent decision"),
            MandateDecision::Authorized { revision: 1 }
        );

        // A different principal is refused with PrincipalNotAuthorized even
        // though the pair has a principal-keyed mandate for another principal.
        assert_eq!(
            store
                .authorize(&instruction, Some(OTHER_PUBKEY), 2)
                .expect("other principal decision"),
            refused(MandateRefusal::PrincipalNotAuthorized {
                principal: OTHER_PUBKEY.into(),
            })
        );

        // SEC-2026-043 negative test: a principal-keyed spend with only a
        // venue-wide mandate on the pair must be refused. The widening door
        // makes that state unrepresentable through the API, so this proves the
        // enforcement at the replay layer instead: a hand-inserted venue-wide
        // sovereign-wallet row fails store verification (the invariant holds
        // even against a store bypass).
        {
            let connection = store.connection.lock();
            let digest = proposal_digest(0, &{
                let mut row = principal_mandate(
                    SOVEREIGN_WALLET_VENUE,
                    TradingNetwork::Signet,
                    AGENT_PUBKEY,
                );
                row.principal_pubkey = None;
                row
            })
            .expect("digest for the injected row");
            connection
                .execute(
                    "INSERT INTO trading_mandate_revisions (
                         revision, changed_at_ms, kind, mandate_json, approval_digest,
                         venue, network, principal_pubkey
                     ) VALUES (2, 2, ?1, ?2, ?3, ?4, ?5, NULL)",
                    params![
                        serde_json::to_string(&MandateRevisionKind::Creation).expect("kind"),
                        serde_json::to_string(&{
                            let mut row = principal_mandate(
                                SOVEREIGN_WALLET_VENUE,
                                TradingNetwork::Signet,
                                AGENT_PUBKEY,
                            );
                            row.principal_pubkey = None;
                            row
                        })
                        .expect("row mandate"),
                        digest,
                        SOVEREIGN_WALLET_VENUE,
                        "signet",
                    ],
                )
                .expect("inject a venue-wide sovereign-wallet row");
        } // connection guard dropped before verify() (non-reentrant lock)
        assert!(
            store.verify().is_err(),
            "a venue-wide sovereign-wallet mandate must fail store verification"
        );
    }

    #[test]
    fn principal_pubkey_is_validated_and_scope_change_is_creation() {
        let store = MandateStore::in_memory().expect("store");
        let mut bad = principal_mandate("hyperliquid", TradingNetwork::Testnet, AGENT_PUBKEY);
        bad.principal_pubkey = Some("not-hex".into());
        assert!(store.propose(bad).is_err(), "malformed principal must fail");

        let mut short = principal_mandate("hyperliquid", TradingNetwork::Testnet, AGENT_PUBKEY);
        short.principal_pubkey = Some("abc".into());
        assert!(store.propose(short).is_err(), "short principal must fail");

        // Moving a venue from venue-wide to principal-keyed is a NEW scope →
        // Creation (UI approval), not a widening of the venue-wide mandate.
        approve(&store, mandate(), 1);
        let candidate =
            principal_mandate(LEGACY_VENUE, TradingNetwork::Signet, AGENT_PUBKEY);
        let proposal = store.propose(candidate).expect("principal proposal");
        assert_eq!(proposal.change_class(), MandateChangeClass::Creation);

        // Widening a principal-keyed mandate's limits is still a Widening
        // behind the same approval door.
        let candidate = principal_mandate(LEGACY_VENUE, TradingNetwork::Signet, AGENT_PUBKEY);
        let proposal = store.propose(candidate.clone()).expect("creation");
        store
            .apply_ui_approved(proposal, 2)
            .expect("approved principal mandate");
        let mut wider = candidate;
        wider.max_venue_balance += 1;
        let proposal = store.propose(wider).expect("widening");
        assert_eq!(proposal.change_class(), MandateChangeClass::Widening);
        assert!(store.save_restriction(proposal, 3).is_err());
    }

    #[test]
    fn principal_keyed_restriction_keeps_the_no_approval_semantics() {
        let store = MandateStore::in_memory().expect("store");
        let candidate =
            principal_mandate("hyperliquid", TradingNetwork::Testnet, AGENT_PUBKEY);
        let proposal = store.propose(candidate.clone()).expect("creation");
        store
            .apply_ui_approved(proposal, 1)
            .expect("approved principal mandate");

        let mut narrowed = candidate;
        narrowed.max_venue_balance -= 1;
        let proposal = store.propose(narrowed.clone()).expect("restriction");
        assert_eq!(proposal.change_class(), MandateChangeClass::Restriction);
        let snapshot = store.save_restriction(proposal, 2).expect("save");
        assert_eq!(
            snapshot.mandate_for_principal("hyperliquid", TradingNetwork::Testnet, Some(AGENT_PUBKEY)),
            Some(&narrowed)
        );
    }

    #[test]
    fn revoke_removes_the_venue_wide_scope_only() {
        // OQ-WP5-3: revocation keeps its pre-principal signature and removes
        // the venue-wide (None) scope; principal-keyed revocation is not
        // wired this WP. A principal-keyed mandate survives a pair revoke.
        let store = MandateStore::in_memory().expect("store");
        approve(&store, mandate(), 1);
        let candidate = principal_mandate(LEGACY_VENUE, TradingNetwork::Signet, AGENT_PUBKEY);
        let proposal = store.propose(candidate.clone()).expect("creation");
        store
            .apply_ui_approved(proposal, 2)
            .expect("approved principal mandate");

        let snapshot = store
            .revoke(LEGACY_VENUE, TradingNetwork::Signet, 3)
            .expect("revoke venue-wide");
        assert!(
            snapshot
                .mandate_for_principal(LEGACY_VENUE, TradingNetwork::Signet, None)
                .is_none(),
            "the venue-wide mandate must be revoked"
        );
        assert_eq!(
            snapshot.mandate_for_principal(LEGACY_VENUE, TradingNetwork::Signet, Some(AGENT_PUBKEY)),
            Some(&candidate),
            "the principal-keyed mandate must survive a venue-wide revoke"
        );
    }

    #[test]
    fn version_two_stores_gain_the_principal_column_and_still_verify() {
        // A v2-schema store (venue/network columns, no principal_pubkey)
        // migrates additively: the new column is added, old rows read as
        // None (venue-wide), and their digests still verify.
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("trading-mandate.db");
        {
            let connection = Connection::open(&path).expect("raw connection");
            connection
                .execute_batch(
                    "CREATE TABLE trading_mandate_revisions (
                         revision INTEGER PRIMARY KEY CHECK (revision > 0),
                         changed_at_ms INTEGER NOT NULL CHECK (changed_at_ms >= 0),
                         kind TEXT NOT NULL,
                         mandate_json TEXT,
                         approval_digest TEXT,
                         venue TEXT,
                         network TEXT
                     ) STRICT;",
                )
                .expect("v2 schema");
            let legacy = mandate();
            let digest = proposal_digest(0, &legacy).expect("digest");
            connection
                .execute(
                    "INSERT INTO trading_mandate_revisions (
                         revision, changed_at_ms, kind, mandate_json, approval_digest, venue, network
                     ) VALUES (1, 1, ?1, ?2, ?3, ?4, ?5)",
                    params![
                        serde_json::to_string(&MandateRevisionKind::Creation).expect("kind"),
                        serde_json::to_string(&legacy).expect("mandate"),
                        digest,
                        LEGACY_VENUE,
                        "signet",
                    ],
                )
                .expect("v2 creation row");
        }
        let store = MandateStore::open(&path).expect("migrated store");
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot.mandate_for(LEGACY_VENUE, TradingNetwork::Signet),
            Some(&mandate())
        );
        let revisions = store.history().expect("history");
        assert_eq!(revisions[0].principal_pubkey, None);
    }
}
