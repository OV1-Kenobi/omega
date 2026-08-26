//! Agent L-402 call path (design §5.7; WP-6) — the demo's paid-MCP lane on
//! signet, mandate-gated.
//!
//! Flow (MDK protocol; the audit's "Preferred v0" header convention):
//!
//! ```text
//! 1. call the protected route (no proof) -> HTTP 402 + WWW-Authenticate:
//!    L402 macaroon="…", invoice="lnbc…" + the challenge JSON body.
//! 2. pay_l402_challenge: the mandate gate FIRST (MandateStore is the ONLY
//!    spend authority, D1; the sovereign-wallet venue is principal-only,
//!    SEC-2026-043), then the sidecar's stdio pay-invoice -> preimage.
//! 3. retry with `X-OpenAgents-L402: <macaroon>:<preimage>` -> the protected
//!    response.
//! ```
//!
//! The real agent tool/MCP call seam (`context_server::transport::http`'s
//! `L402Payer` trait) is L-402-capable and tested with a fake payer. The
//! concrete mandate-gated payer this module implements is
//! [`pay_l402_challenge`]; attaching it to `ContextServerStore`-built
//! transports requires the supervisor-Send bridge (the supervisor is
//! `Rc`-based / UI-thread affine, while the transport payer must be
//! `Send + Sync`) — recorded as open question OQ-WP6-2.

use anyhow::{Context as _, Result, anyhow};
use context_server::transport::L402Challenge;
use http_client::{AsyncBody, HttpClient, Request, Response};

use crate::client::SovereignWalletError;
use crate::mandate::authorize_sovereign_spend;
use crate::supervisor::SovereignWalletSupervisor;
use trading_mandate::{MandateDecision, MandateRefusal, MandateStore};

/// The L-402 proof: the opaque credential plus the payment preimage. Sent as
/// `X-OpenAgents-L402: <macaroon>:<preimage>` (the audit's preferred v0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L402Proof {
    pub macaroon: String,
    pub preimage: String,
}

impl L402Proof {
    /// The `X-OpenAgents-L402` header value (the audit's "Preferred v0":
    /// agent identity keeps `Authorization: Bearer`, the proof travels here).
    pub fn header_value(&self) -> String {
        format!("{}:{}", self.macaroon, self.preimage)
    }
}

/// Errors from the mandate-gated L-402 pay step. The mandate gate is the ONLY
/// spend gate: a refused mandate never reaches the sidecar pay call (D1).
#[derive(Debug, thiserror::Error)]
pub enum L402PayError {
    #[error("the mandate gate refused the L-402 payment: {0:?}")]
    MandateRefused(MandateRefusal),
    #[error(transparent)]
    Protocol(#[from] SovereignWalletError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// The mandate-gated pay step (design §5.7; WP-6 acceptance "mandate-gated
/// pay — no mandate → refused"):
///
/// 1. `authorize_sovereign_spend` — the single spend gate (SEC-2026-043
///    principal-only on the sovereign-wallet venue). `Refused` returns
///    [`L402PayError::MandateRefused`] and NO payment is attempted.
/// 2. On `Authorized`, pays the challenge invoice through the sidecar's
///    stdio `pay-invoice` and returns the preimage proof.
///
/// The sidecar itself has no mandate knowledge: this Rust-side gate is the
/// enforcement surface (the sidecar's pay-invoice is only reachable from
/// call sites that pass it — WP-5).
pub async fn pay_l402_challenge(
    supervisor: &mut SovereignWalletSupervisor,
    mandate_store: &MandateStore,
    challenge: &L402Challenge,
    principal: Option<&str>,
    idempotency_key: &str,
    now_ms: i64,
) -> Result<L402Proof, L402PayError> {
    match authorize_sovereign_spend(mandate_store, challenge.amount_sats, principal, now_ms)? {
        MandateDecision::Authorized { .. } => {}
        MandateDecision::Refused { reason, .. } => {
            return Err(L402PayError::MandateRefused(reason));
        }
    }
    let paid = supervisor.pay_invoice(&challenge.invoice, idempotency_key).await?;
    let preimage = paid.preimage.ok_or_else(|| {
        anyhow!("the sidecar returned no preimage for the L-402 invoice (payment did not settle)")
    })?;
    Ok(L402Proof {
        macaroon: challenge.macaroon.clone(),
        preimage,
    })
}

/// The full agent L-402 flow against a protected route: attempt -> on 402,
/// mandate-gated pay -> retry with `X-OpenAgents-L402`. Returns the protected
/// response body. A non-402 first response is returned as-is (the route was
/// not L-402-gated for this caller).
pub async fn call_paid_route(
    http: &dyn HttpClient,
    url: &str,
    bearer_token: &str,
    body: Option<Vec<u8>>,
    pay: impl FnOnce(&L402Challenge) -> Result<L402Proof, L402PayError>,
) -> Result<Response<AsyncBody>> {
    let first_body = body.clone().unwrap_or_default();
    let mut first = Request::builder()
        .method(http_client::Method::POST)
        .uri(url)
        .header("Authorization", format!("Bearer {bearer_token}"));
    if body.is_some() {
        first = first.header("Content-Type", "application/json");
    }
    let mut response = http
        .send(first.body(AsyncBody::from(first_body))?)
        .await?;

    if response.status().as_u16() != 402 {
        return Ok(response);
    }

    // Parse the L-402 challenge (audit §"Response Contract").
    let mut challenge_body = String::new();
    futures::AsyncReadExt::read_to_string(response.body_mut(), &mut challenge_body).await?;
    let challenge: L402Challenge = serde_json::from_str(&challenge_body)
        .context("the 402 response was not a parseable L-402 challenge")?;

    let proof = pay(&challenge)?;

    let has_body = body.is_some();
    let mut retry = Request::builder()
        .method(http_client::Method::POST)
        .uri(url)
        .header("Authorization", format!("Bearer {bearer_token}"))
        .header("X-OpenAgents-L402", proof.header_value());
    if has_body {
        retry = retry.header("Content-Type", "application/json");
    }
    let retry = retry.body(AsyncBody::from(body.unwrap_or_default()))?;
    http.send(retry).await.context("the L-402 retry failed")
}

/// Parse an L-402 challenge from a 402 JSON body (unit-test seam).
pub fn parse_l402_challenge_body(body: &str) -> Result<L402Challenge> {
    serde_json::from_str(body).context("the 402 body was not an L-402 challenge")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SovereignWalletError;
    use crate::{
        SovereignWalletCommand, SovereignWalletSupervisor, SovereignWalletSupervisorOptions,
        default_options, fixture_command, fixture_command_with_network,
    };
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;

    const AGENT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
    const OTHER: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    /// The fixture's deterministic payment hash (sha256 of the "b"*64 preimage).
    const FIXTURE_PAYMENT_HASH: &str = "4ca14526b2751b640d549ce7caf8ac39438592211a0ec370064d57666a682ad6";

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-fixtures/fixture-sidecar.mjs")
    }

    fn make_supervisor(network: &str, command: SovereignWalletCommand) -> Result<SovereignWalletSupervisor> {
        let dir = tempdir().context("create temp data root")?;
        let options = SovereignWalletSupervisorOptions {
            data_root: dir.path().to_path_buf(),
            command,
            network: network.to_string(),
            initial_generation: 1,
            request_timeout: Duration::from_secs(10),
            node_require_minor: None,
        };
        SovereignWalletSupervisor::new(options)
    }

    fn challenge(amount_sats: u64) -> L402Challenge {
        L402Challenge {
            challenge_id: "l402_challenge_fixture".into(),
            macaroon: "v1.fixture-macaroon".into(),
            invoice: "lntbs100u1pfixture".into(),
            payment_hash: FIXTURE_PAYMENT_HASH.into(),
            amount_sats,
            expires_at: 1_893_456_000,
        }
    }

    fn approve_agent_mandate(store: &MandateStore, max_payment_sat: u64, now: i64) {
        let candidate =
            crate::sovereign_wallet_mandate_candidate(AGENT, max_payment_sat, now + 100_000);
        let proposal = store.propose(candidate).expect("proposal");
        trading_mandate::apply_ui_approved_for_test(store, proposal, now)
            .expect("approved mandate");
    }

    #[test]
    fn the_l402_pay_path_refuses_without_a_mandate_and_pays_with_one() {
        smol::block_on(async {
            let store = MandateStore::in_memory().expect("store");
            let mut supervisor =
                make_supervisor("signet", fixture_command(&fixture_path())).expect("supervisor");
            supervisor.start().await.context("initialize").unwrap();

            // No mandate -> the gate REFUSES and no payment is attempted
            // (the fixture would have answered pay-invoice; the refusal must
            // happen before any pay call).
            let refused = pay_l402_challenge(
                &mut supervisor,
                &store,
                &challenge(1),
                Some(AGENT),
                "l402-key-1",
                1,
            )
            .await
            .expect_err("no mandate must refuse the L-402 pay");
            match refused {
                L402PayError::MandateRefused(MandateRefusal::PrincipalNotAuthorized { principal }) => {
                    assert_eq!(principal, AGENT);
                }
                other => panic!("expected PrincipalNotAuthorized, got {other:?}"),
            }

            // With an approved principal mandate the payment goes through and
            // the preimage proof is returned.
            approve_agent_mandate(&store, 50_000, 1);
            let proof = pay_l402_challenge(
                &mut supervisor,
                &store,
                &challenge(1),
                Some(AGENT),
                "l402-key-2",
                2,
            )
            .await
            .expect("an approved mandate must authorize the L-402 pay");
            assert_eq!(proof.macaroon, "v1.fixture-macaroon");
            assert_eq!(proof.preimage, "b".repeat(64));
            assert_eq!(
                proof.header_value(),
                format!("v1.fixture-macaroon:{}", "b".repeat(64)),
                "the X-OpenAgents-L402 header value must be <macaroon>:<preimage>"
            );

            // Another principal is refused even though a principal-keyed
            // mandate exists on the pair (SEC-2026-043 principal-only venue).
            let other_refused = pay_l402_challenge(
                &mut supervisor,
                &store,
                &challenge(1),
                Some(OTHER),
                "l402-key-3",
                3,
            )
            .await
            .expect_err("another principal must be refused");
            assert!(matches!(
                other_refused,
                L402PayError::MandateRefused(MandateRefusal::PrincipalNotAuthorized { .. })
            ));

            supervisor.stop().await.ok();
        });
    }

    #[test]
    fn the_l402_pay_path_is_gated_before_any_pay_call() {
        smol::block_on(async {
            let store = MandateStore::in_memory().expect("store");
            let mut supervisor =
                make_supervisor("signet", fixture_command(&fixture_path())).expect("supervisor");
            supervisor.start().await.context("initialize").unwrap();

            // Refusal for a None principal (the venue is principal-only).
            let refused = pay_l402_challenge(
                &mut supervisor,
                &store,
                &challenge(1),
                None,
                "l402-key-4",
                1,
            )
            .await
            .expect_err("a None-principal L-402 pay must be refused on the principal-only venue");
            match refused {
                L402PayError::MandateRefused(MandateRefusal::Missing) => {}
                other => panic!("expected Missing, got {other:?}"),
            }

            // A malformed principal is refused (never authorizable).
            let malformed = pay_l402_challenge(
                &mut supervisor,
                &store,
                &challenge(1),
                Some("not-hex"),
                "l402-key-5",
                1,
            )
            .await
            .expect_err("a malformed principal must be refused");
            assert!(matches!(
                malformed,
                L402PayError::MandateRefused(MandateRefusal::PrincipalNotAuthorized { .. })
            ));

            supervisor.stop().await.ok();
        });
    }

    #[test]
    fn the_l402_pay_path_respects_the_mandate_limit() {
        smol::block_on(async {
            let store = MandateStore::in_memory().expect("store");
            approve_agent_mandate(&store, 50_000, 1);
            let mut supervisor =
                make_supervisor("signet", fixture_command(&fixture_path())).expect("supervisor");
            supervisor.start().await.context("initialize").unwrap();

            // A challenge above the approved per-payment cap is refused by the
            // gate (the sidecar is never asked to pay).
            let over = pay_l402_challenge(
                &mut supervisor,
                &store,
                &challenge(50_001),
                Some(AGENT),
                "l402-key-6",
                2,
            )
            .await
            .expect_err("a payment above the mandate cap must be refused");
            assert!(matches!(
                over,
                L402PayError::MandateRefused(MandateRefusal::VenueBalanceLimit { .. })
            ));

            supervisor.stop().await.ok();
        });
    }

    #[test]
    fn challenge_body_parsing_matches_the_gateway_wire_shape() {
        // The exact JSON body the sidecar gateway emits for a 402 challenge
        // (audit §"Response Contract").
        let body = r#"{
            "error": { "code": "payment_required", "message": "Payment required" },
            "challengeId": "l402_challenge_fixture",
            "macaroon": "v1.payload.signature",
            "invoice": "lntbs100u1qftest",
            "paymentHash": "4ca14526b2751b640d549ce7caf8ac39438592211a0ec370064d57666a682ad6",
            "amountSats": 1,
            "expiresAt": 1893456000
        }"#;
        let parsed = parse_l402_challenge_body(body).expect("parse");
        assert_eq!(parsed.challenge_id, "l402_challenge_fixture");
        assert_eq!(parsed.amount_sats, 1);
        assert_eq!(parsed.payment_hash, FIXTURE_PAYMENT_HASH);
    }

    #[test]
    fn protocol_errors_map_to_the_pay_error() {
        smol::block_on(async {
            let store = MandateStore::in_memory().expect("store");
            approve_agent_mandate(&store, 50_000, 1);
            let mut supervisor =
                make_supervisor("signet", fixture_command(&fixture_path())).expect("supervisor");
            supervisor.start().await.context("initialize").unwrap();

            // A mainnet invoice is refused by the sidecar with MAINNET_REFUSED
            // (the sidecar's guard), surfaced as a Protocol error.
            let mut mainnet_challenge = challenge(1);
            mainnet_challenge.invoice = "lnbc10u1p0example".into();
            let err = pay_l402_challenge(
                &mut supervisor,
                &store,
                &mainnet_challenge,
                Some(AGENT),
                "l402-key-7",
                2,
            )
            .await
            .expect_err("a mainnet invoice must be refused");
            match err {
                L402PayError::Protocol(SovereignWalletError::MainnetRefused) => {}
                other => panic!("expected MainnetRefused, got {other:?}"),
            }

            supervisor.stop().await.ok();
        });
    }
}