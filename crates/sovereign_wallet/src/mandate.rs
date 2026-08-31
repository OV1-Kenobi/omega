//! MandateStore-gated spend check for the sovereign wallet (design §6.1
//! `mandate.rs`, §6.3.5).
//!
//! The sidecar's `pay-invoice` is only reachable from Rust call sites that
//! have already passed [`authorize_sovereign_spend`]: a `TradingInstruction`
//! for venue `sovereign-wallet` is built with the spending agent's Nostr
//! pubkey as the principal and run through the store's principal-aware
//! `authorize`. `MandateDecision::Refused` blocks the payment — mandates are
//! the only spend gate, and the sidecar cannot spend without an approved
//! mandate (WP-5 security constraint; SEC-2026-043 principal-only on this
//! venue).
//!
//! OMEGA-DELTA-0286: the instruction builder and the gate are network-aware.
//! The escrow fee composition passes the session's network, so a mainnet
//! escrow fee is gated by a `(sovereign-wallet, mainnet, principal)` mandate;
//! signet behavior is unchanged (existing mandates keep working — signet and
//! regtest both map to `TradingNetwork::Signet`, exactly as before).

use std::collections::BTreeSet;

use anyhow::Result;
use trading_mandate::{
    AssetId, MandateDecision, MandateStore, ReviewCadence, TradingInstruction, TradingMandate,
    TradingNetwork, SOVEREIGN_WALLET_VENUE,
};

/// The strategy id the sovereign wallet spend gate authorizes. The New
/// Authorization flow creates mandates whose `allowed_strategies` contain
/// exactly this id.
pub const SOVEREIGN_WALLET_STRATEGY: &str = "wallet_payment";

/// OMEGA-DELTA-0286: map the supervisor's configured network label onto the
/// mandate's `TradingNetwork`. signet/regtest mandates use `Signet` (the
/// pre-0286 behavior — unchanged); `mainnet` maps to `Mainnet` so mainnet
/// payments require a `(sovereign-wallet, mainnet, principal)` mandate.
pub fn sovereign_wallet_network(label: &str) -> TradingNetwork {
    if label == "mainnet" {
        TradingNetwork::Mainnet
    } else {
        TradingNetwork::Signet
    }
}

/// Build the spend instruction for a sovereign-wallet payment of `amount_sat`
/// on `network` (the session/configured network — OMEGA-DELTA-0286).
///
/// The instruction's limits are the wallet-payment shape: no position, no
/// leverage, no daily-loss accounting, no order-rate accounting; the only
/// meaningful control is `venue_balance_after` = the payment amount, capped by
/// the mandate's `max_venue_balance` (the per-payment cap the operator
/// approves).
pub fn sovereign_wallet_instruction(amount_sat: u64, network: TradingNetwork) -> TradingInstruction {
    TradingInstruction {
        venue: SOVEREIGN_WALLET_VENUE.to_string(),
        network,
        strategy_id: SOVEREIGN_WALLET_STRATEGY.to_string(),
        collateral_asset: AssetId::sats(),
        venue_balance_after: amount_sat,
        position_notional_usd: 0,
        leverage: 1,
        daily_realized_loss: 0,
        orders_last_hour: 0,
        liquidation_buffer_bps: 10_000,
    }
}

/// The single spend gate: authorize a sovereign-wallet payment of
/// `amount_sat` on `network` for `principal` (the spending agent's Nostr
/// pubkey hex).
///
/// `network` is the session/configured network (OMEGA-DELTA-0286): the escrow
/// composition passes the session's network; the L-402 client passes the
/// supervisor's configured network. Signet behavior is unchanged.
///
/// The store's `authorize` enforces SEC-2026-043 principal-only resolution on
/// the sovereign-wallet venue: an exact `(sovereign-wallet, <network>,
/// principal)` mandate is required; `PrincipalNotAuthorized` fires otherwise.
/// `Err` here means the gate could not be evaluated (store failure); `Refused`
/// means the payment is blocked by policy.
pub fn authorize_sovereign_spend(
    store: &MandateStore,
    amount_sat: u64,
    network: TradingNetwork,
    principal: Option<&str>,
    now_ms: i64,
) -> Result<MandateDecision> {
    store.authorize(&sovereign_wallet_instruction(amount_sat, network), principal, now_ms)
}

/// Build the candidate mandate for the dashboard's New Authorization flow:
/// a principal-keyed sovereign-wallet mandate on `network` authorizing
/// payments up to `max_payment_sat` per payment for `principal_pubkey_hex`.
///
/// The candidate is validated by `MandateStore::propose`; the widening door
/// (`apply_ui_approved`) is the only path that creates it, and the
/// principal-only venue policy (SEC-2026-043) refuses any candidate without a
/// principal.
pub fn sovereign_wallet_mandate_candidate(
    network: TradingNetwork,
    principal_pubkey_hex: &str,
    max_payment_sat: u64,
    expires_at_ms: i64,
) -> TradingMandate {
    TradingMandate {
        venue: SOVEREIGN_WALLET_VENUE.to_string(),
        network,
        principal_pubkey: Some(principal_pubkey_hex.to_string()),
        collateral_asset: AssetId::sats(),
        objective: format!(
            "Sovereign wallet payments up to {max_payment_sat} sats for agent {principal_pubkey_hex}"
        ),
        max_venue_balance: max_payment_sat,
        // Wallet payments carry no position or leverage; the limit gates are
        // inert by construction (the instruction passes 0 / 1), kept at their
        // minimal positive values per `TradingMandate::validate`.
        max_position_usd: 1,
        max_leverage: 1,
        daily_loss_stop: max_payment_sat.max(1),
        max_orders_per_hour: 1,
        min_liquidation_buffer_bps: 0,
        allowed_strategies: BTreeSet::from([SOVEREIGN_WALLET_STRATEGY.to_string()]),
        review_cadence: ReviewCadence::Interval { seconds: 3_600 },
        expires_at_ms,
        // OMEGA-DELTA-0285: escrow fields belong to the mkt-swp-escrow venue
        // only; a sovereign-wallet mandate carries none of them (mode `none`).
        allow_escrow: None,
        max_escrow_sats: None,
        escrow_timeout_blocks: None,
        arbitration_fee_flat_sats: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trading_mandate::MandateRefusal;

    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
    const OTHER: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn approve_agent_mandate(store: &MandateStore, max_payment_sat: u64, now: i64) {
        let candidate = sovereign_wallet_mandate_candidate(
            TradingNetwork::Signet,
            AGENT,
            max_payment_sat,
            now + 100_000,
        );
        let proposal = store.propose(candidate).expect("proposal");
        // The widening application is the store's own test-support seam (the
        // production widening door stays on the settings-UI approval path,
        // OMEGA-DELTA-0245).
        trading_mandate::apply_ui_approved_for_test(store, proposal, now)
            .expect("approved mandate");
    }

    #[test]
    fn the_gate_authorizes_an_approved_principal_payment() {
        let store = MandateStore::in_memory().expect("store");
        approve_agent_mandate(&store, 50_000, 1);
        assert_eq!(
            authorize_sovereign_spend(&store, 10_000, TradingNetwork::Signet, Some(AGENT), 2).expect("gate"),
            MandateDecision::Authorized { revision: 1 }
        );
    }

    #[test]
    fn the_gate_refuses_without_an_approved_mandate() {
        let store = MandateStore::in_memory().expect("store");
        assert_eq!(
            authorize_sovereign_spend(&store, 10_000, TradingNetwork::Signet, Some(AGENT), 1).expect("gate"),
            MandateDecision::Refused {
                reason: MandateRefusal::PrincipalNotAuthorized {
                    principal: AGENT.into(),
                },
                required_posture: trading_mandate::RequiredRiskPosture::FlatRisk,
            }
        );
        // A None-principal flow on the principal-only venue is Missing (no
        // venue-wide mandate can exist — SEC-2026-043).
        assert_eq!(
            authorize_sovereign_spend(&store, 10_000, TradingNetwork::Signet, None, 1).expect("gate"),
            MandateDecision::Refused {
                reason: MandateRefusal::Missing,
                required_posture: trading_mandate::RequiredRiskPosture::FlatRisk,
            }
        );
    }

    #[test]
    fn the_gate_refuses_a_principal_without_its_own_mandate() {
        let store = MandateStore::in_memory().expect("store");
        approve_agent_mandate(&store, 50_000, 1);
        // SEC-2026-043: another principal's spend is refused even though a
        // principal-keyed mandate exists on the pair (no venue-wide fallback).
        assert_eq!(
            authorize_sovereign_spend(&store, 10_000, TradingNetwork::Signet, Some(OTHER), 2).expect("gate"),
            MandateDecision::Refused {
                reason: MandateRefusal::PrincipalNotAuthorized {
                    principal: OTHER.into(),
                },
                required_posture: trading_mandate::RequiredRiskPosture::FlatRisk,
            }
        );
    }

    #[test]
    fn the_gate_caps_the_payment_at_the_approved_limit() {
        let store = MandateStore::in_memory().expect("store");
        approve_agent_mandate(&store, 50_000, 1);
        assert_eq!(
            authorize_sovereign_spend(&store, 50_001, TradingNetwork::Signet, Some(AGENT), 2).expect("gate"),
            MandateDecision::Refused {
                reason: MandateRefusal::VenueBalanceLimit {
                    asset: AssetId::sats(),
                    limit: 50_000,
                    requested: 50_001,
                },
                required_posture: trading_mandate::RequiredRiskPosture::FlatRisk,
            }
        );
    }

    #[test]
    fn the_gate_requires_a_mainnet_mandate_for_a_mainnet_instruction() {
        // OMEGA-DELTA-0286: a (sovereign-wallet, mainnet, principal) mandate
        // is required for a mainnet spend — the signet mandate does not
        // authorize it, and the mainnet mandate does.
        let store = MandateStore::in_memory().expect("store");
        approve_agent_mandate(&store, 50_000, 1);
        assert_eq!(
            authorize_sovereign_spend(&store, 10_000, TradingNetwork::Mainnet, Some(AGENT), 2).expect("gate"),
            MandateDecision::Refused {
                reason: MandateRefusal::PrincipalNotAuthorized {
                    principal: AGENT.into(),
                },
                required_posture: trading_mandate::RequiredRiskPosture::FlatRisk,
            }
        );
        let mainnet_candidate = sovereign_wallet_mandate_candidate(
            TradingNetwork::Mainnet,
            AGENT,
            50_000,
            100_000,
        );
        let proposal = store.propose(mainnet_candidate).expect("mainnet proposal");
        trading_mandate::apply_ui_approved_for_test(&store, proposal, 2)
            .expect("approved mainnet mandate");
        assert_eq!(
            authorize_sovereign_spend(&store, 10_000, TradingNetwork::Mainnet, Some(AGENT), 3).expect("gate"),
            MandateDecision::Authorized { revision: 2 }
        );
    }

    #[test]
    fn the_candidate_is_principal_only_and_digest_bound() {
        let store = MandateStore::in_memory().expect("store");
        let mut venue_wide =
            sovereign_wallet_mandate_candidate(TradingNetwork::Signet, AGENT, 50_000, 100_000);
        venue_wide.principal_pubkey = None;
        assert!(
            store.propose(venue_wide).is_err(),
            "a principal-less sovereign-wallet mandate must be refused (SEC-2026-043)"
        );
        // A changed principal is a different scope (Creation), never a widening.
        let candidate =
            sovereign_wallet_mandate_candidate(TradingNetwork::Signet, AGENT, 50_000, 100_000);
        let proposal = store.propose(candidate).expect("proposal");
        assert_eq!(
            proposal.change_class(),
            trading_mandate::MandateChangeClass::Creation
        );
    }
}