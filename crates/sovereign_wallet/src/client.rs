//! Typed client for the sovereign wallet sidecar loopback protocol (design §2).
//!
//! OMEGA-DELTA-0300: `make_invoice`/`pay_invoice` are the supervisor client
//! choke point every funded flow passes (escrow fee composition, mandate-
//! gated L-402 pay, wallet payments). Both consult the `spend_policy` (kill +
//! per-surface daily ceiling) BEFORE forwarding to the sidecar, and
//! `pay_invoice` runs the loss-rule expected-vs-actual settle comparison
//! (SEC-2026-098) on the result.

use anyhow::{anyhow, Result};
use serde_json::{Value, json};

use crate::protocol::{
    BalanceResult, BlockHeightResult, CreateWalletResult, ErrorCode, ExportNostrSecretResult,
    IdentityStatusResult, InvoiceResult, PayResult, StatusResult,
};
use crate::spend_policy::{SURFACE_WALLET_L402, bolt11_amount_sats};
use crate::supervisor::SovereignWalletSupervisor;
use trading_mandate::{MandateDecision, MandateStore, SOVEREIGN_WALLET_VENUE};

#[derive(Debug, thiserror::Error)]
pub enum SovereignWalletError {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error("stale generation")]
    StaleGeneration,
    #[error("protocol error ({code:?}): {message}")]
    Protocol {
        code: ErrorCode,
        message: String,
        retryable: bool,
        remediation: String,
    },
    #[error("mainnet refused")]
    MainnetRefused,
    /// OMEGA-DELTA-0300: the spend kill is set (env-level or the persisted
    /// loss-rule auto-kill) — the named halted state; every funded flow
    /// refuses until the founder re-enables.
    #[error("spend halted: {0}")]
    SpendHalted(String),
    /// OMEGA-DELTA-0300: the per-surface daily ceiling would be exceeded.
    #[error("spend policy refused: {0}")]
    SpendPolicyRefused(String),
}

impl SovereignWalletError {
    pub fn is_mainnet_refused(&self) -> bool {
        matches!(self, Self::MainnetRefused)
    }
}

fn decode<T: serde::de::DeserializeOwned>(result: Value, what: &str) -> Result<T, SovereignWalletError> {
    serde_json::from_value(result).map_err(|error| SovereignWalletError::Anyhow(anyhow!("decode {what}: {error}")))
}

/// Typed access to the sidecar's methods. Mirrors the effectd supervisor's
/// `request` discipline: generation-fenced, bounded, timeout-bounded. The
/// `initialize` handshake lives on the supervisor (`SovereignWalletSupervisor::start`),
/// where the mainnet-only rail gate is enforced (SEC-2026-050, OMEGA-DELTA-0305).
impl SovereignWalletSupervisor {
    pub async fn status(&mut self) -> Result<StatusResult, SovereignWalletError> {
        let result = self.request("status", None, self.generation()).await?;
        decode(result, "status result")
    }

    pub async fn balance(&mut self) -> Result<BalanceResult, SovereignWalletError> {
        let result = self.request("balance", None, self.generation()).await?;
        decode(result, "balance result")
    }

    /// WP-4b (SEC-2026-087) / OMEGA-DELTA-0304: the observed tip height,
    /// probed through the public tip-API (mempool.space / blockstream.info).
    /// The sidecar's wallet-height seam now calls the public tip-API;
    /// this client method forwards the request to the sidecar.
    pub async fn wallet_height(&mut self) -> Result<BlockHeightResult, SovereignWalletError> {
        let result = self.request("wallet-height", None, self.generation()).await?;
        decode(result, "wallet-height result")
    }

    pub async fn create_wallet(
        &mut self,
        idempotency_key: &str,
        password: &str,
    ) -> Result<CreateWalletResult, SovereignWalletError> {
        // Operator-only method; the response carries the show-once aezeed and
        // is never logged by the supervisor (SEC-2026-046).
        let result = self
            .request(
                "create-wallet",
                Some(json!({ "idempotencyKey": idempotency_key, "password": password })),
                self.generation(),
            )
            .await?;
        decode(result, "create-wallet result")
    }

    pub async fn unlock(&mut self, idempotency_key: &str, password: &str) -> Result<Value, SovereignWalletError> {
        self.request(
            "unlock",
            Some(json!({ "idempotencyKey": idempotency_key, "password": password })),
            self.generation(),
        )
        .await
    }

    pub async fn lock(&mut self) -> Result<Value, SovereignWalletError> {
        self.request("lock", None, self.generation()).await
    }

    pub async fn make_invoice(
        &mut self,
        amt_sat: u64,
        memo: &str,
        idempotency_key: &str,
    ) -> Result<InvoiceResult, SovereignWalletError> {
        // OMEGA-DELTA-0300 (C2, SEC-2026-100): the spend policy gate BEFORE
        // forwarding — a killed surface creates no new invoices either
        // (ALL-VALUE-TOUCHING); the daily ceiling counts mints + payments.
        let now = now_unix();
        self.spend_policy
            .check_spend(SURFACE_WALLET_L402, amt_sat, now)?;
        let result = self
            .request(
                "make-invoice",
                Some(json!({ "amtSat": amt_sat, "memo": memo, "idempotencyKey": idempotency_key })),
                self.generation(),
            )
            .await?;
        let invoice: InvoiceResult = decode(result, "invoice result")?;
        // Count real mints only (the sidecar confirmed the mint).
        self.spend_policy.record_spend(SURFACE_WALLET_L402, amt_sat, now)?;
        Ok(invoice)
    }

    pub async fn pay_invoice(&mut self, invoice: &str, idempotency_key: &str) -> Result<PayResult, SovereignWalletError> {
        // OMEGA-DELTA-0300: the spend policy gate BEFORE forwarding. The
        // ceiling amount is the invoice's BOLT11 amount (pay-any invoices
        // have no amount — the kill remains the hard control; recorded in
        // WP-3 evidence).
        let now = now_unix();
        let amount_sats = bolt11_amount_sats(invoice).unwrap_or(0);
        self.spend_policy
            .check_spend(SURFACE_WALLET_L402, amount_sats, now)?;
        let result = self
            .request(
                "pay-invoice",
                Some(json!({ "invoice": invoice, "idempotencyKey": idempotency_key })),
                self.generation(),
            )
            .await?;
        let pay: PayResult = decode(result, "pay result")?;
        // C3 / SEC-2026-098 — the loss rule: expected-vs-actual settle
        // comparison. The sidecar reports the prepared-for total outflow
        // (invoice amount + expected fee) and the actual outflow; a payment
        // that settles for MORE than the prepared total is an unexpected
        // loss: auto-set the kill FAIL-CLOSED, report the named halted
        // state, and refuse the result. The Debug & Incident route is opened
        // before anything resumes (Decision 4; WP-7 renders the state).
        if pay.total_outflow_known {
            let actual = pay.actual_amount_sat.parse::<u64>().unwrap_or(0);
            let expected = pay.expected_total_outflow_sat.parse::<u64>().unwrap_or(0);
            if actual > expected {
                let reason = format!(
                    "loss-rule: over-settlement (actual {actual} sats > expected {expected} sats)"
                );
                self.spend_policy.auto_kill_loss_rule(&reason, now)?;
                return Err(SovereignWalletError::SpendHalted(
                    self.spend_policy.halt_message(),
                ));
            }
        }
        // Count real payments only (the sidecar confirmed the payment).
        self.spend_policy.record_spend(SURFACE_WALLET_L402, amount_sats, now)?;
        Ok(pay)
    }

    pub async fn activity(&mut self, limit: u32) -> Result<Value, SovereignWalletError> {
        self.request(
            "activity",
            Some(json!({ "limit": limit })),
            self.generation(),
        )
        .await
    }

    pub async fn identity_status(&mut self) -> Result<IdentityStatusResult, SovereignWalletError> {
        let result = self
            .request("identity-status", None, self.generation())
            .await?;
        decode(result, "identity-status result")
    }

    /// Operator-only one-time Nostr-secret export (design §2.2; WP-5 seam).
    /// The sidecar refuses a second export with `ExportAlreadyConsumed`.
    pub async fn export_nostr_secret(&mut self) -> Result<ExportNostrSecretResult, SovereignWalletError> {
        let result = self
            .request("export-nostr-secret", None, self.generation())
            .await?;
        decode(result, "export-nostr-secret result")
    }

    /// WP-6: the L-402 gateway's MCP-server -> Nostr-identity attribution map
    /// (design §6.4 / §5.4). Returns `{ entries: { serverId: principalPubkey } }`
    /// — public pubkeys only, never key material.
    pub async fn mcp_identity_map_get(&mut self) -> Result<Value, SovereignWalletError> {
        self.request("mcp-identity-map-get", None, self.generation()).await
    }

    /// WP-6: set (or unset, with `None`) a server -> Nostr-identity mapping in
    /// the L-402 gateway store. `principal_pubkey` is a public 64-hex Nostr
    /// pubkey; the sidecar validates the shape.
    pub async fn mcp_identity_map_set(
        &mut self,
        server_id: &str,
        principal_pubkey: Option<&str>,
    ) -> Result<Value, SovereignWalletError> {
        self.request(
            "mcp-identity-map-set",
            Some(json!({ "serverId": server_id, "principalPubkey": principal_pubkey })),
            self.generation(),
        )
        .await
    }

    /// Operator-only identity ceremony step 1 (design §4.3): generate + show
    /// the mnemonic once and hold it pending the word-challenge commit.
    /// Returns `{ mnemonic, challengeLabels, note }`.
    pub async fn vault_init_prepare(&mut self) -> Result<Value, SovereignWalletError> {
        self.request("vault-init-prepare", None, self.generation()).await
    }

    /// Operator-only identity ceremony step 2 (design §4.3): commit the
    /// pending ceremony with the passphrase and the word-challenge answers
    /// (`{ "2": word, "7": word, "11": word }`). Returns
    /// `{ vaultState, npub, pubkeyHex }`.
    pub async fn vault_init(
        &mut self,
        passphrase: &str,
        answers: &Value,
    ) -> Result<Value, SovereignWalletError> {
        self.request(
            "vault-init",
            Some(json!({ "passphrase": passphrase, "answers": answers })),
            self.generation(),
        )
        .await
    }

    /// Operator-only vault unlock (design §4.2). Returns
    /// `{ vaultState, derivedNpub, derivedPubkeyHex }`.
    pub async fn vault_unlock(&mut self, passphrase: &str) -> Result<Value, SovereignWalletError> {
        self.request(
            "vault-unlock",
            Some(json!({ "passphrase": passphrase })),
            self.generation(),
        )
        .await
    }

    pub async fn shutdown(&mut self) -> Result<Value, SovereignWalletError> {
        self.request("shutdown", None, self.generation()).await
    }

    /// OMEGA-DELTA-0306 (design §3.4): the CLINK twin of `pay_l402_challenge`.
    ///
    /// Host-initiated settlement of a queued CLINK Debit. The sidecar's
    /// `pay-debit` never pays on its own — this wrapper is the authority gate:
    ///
    /// 1. `authorize_sovereign_spend` — principal = the REQUESTING AGENT
    ///    PUBKEY (the verified 21002 event author; SEC-2026-106a — never a
    ///    content field). `Refused` → the sidecar answers GFY code 1 denied
    ///    WITHOUT paying and NO phoenixd call happens (the negative is
    ///    provable from the fixture call log).
    /// 2. `spend_policy.check_spend(SURFACE_WALLET_L402, ...)` — kill + daily
    ///    ceiling on the Debits path (ALL-VALUE-TOUCHING: a killed rail
    ///    refuses debits too; refusal → GFY code 1/4 without paying).
    /// 3. On `Authorized`, forwards `pay-debit` to the sidecar — which pays
    ///    via phoenixd and publishes the 21002 success response.
    /// 4. Loss rule (expected-vs-actual) + `record_spend` on the settled pay.
    /// 5. NIP-AC 39243 after the local Authorized AND the settled pay (lane
    ///    `LANE_CLINK_DEBIT`; the settled amount is the sidecar's reported
    ///    actual — never a CLINK receipt's claim, design §3.4e).
    pub async fn pay_debit_invoice(
        &mut self,
        mandate_store: &MandateStore,
        debit_id: &str,
        principal: &str,
        invoice: &str,
        // The idempotency key is accepted for interface symmetry with
        // `pay_l402_challenge`; the CLINK debit path is idempotent by the
        // payment hash (a duplicate 21002 is a new queue entry with a new
        // debit id), so the sidecar does not key a replay cache on it.
        _idempotency_key: &str,
        now_ms: i64,
    ) -> Result<PayResult, SovereignWalletError> {
        let network = crate::mandate::sovereign_wallet_network(self.network())?;
        let amount_sats = bolt11_amount_sats(invoice).unwrap_or(0);
        // 1. The single spend gate (D2): authorize BEFORE any phoenixd call.
        let decision = crate::mandate::authorize_sovereign_spend(
            mandate_store,
            amount_sats,
            network,
            Some(principal),
            now_ms,
        )?;
        let refused_reason = match &decision {
            MandateDecision::Authorized { .. } => None,
            MandateDecision::Refused { reason, .. } => Some(reason),
        };
        if let Some(reason) = refused_reason {
            // GFY code 1 denied on the 21002 channel, WITHOUT paying.
            let refusal_text = serde_json::to_string(reason).unwrap_or_else(|_| "mandate refused".to_string());
            let _ = self
                .request(
                    "debit-refuse",
                    Some(json!({ "debitId": debit_id, "code": 1, "error": format!("denied: {refusal_text}") })),
                    self.generation(),
                )
                .await;
            return Err(SovereignWalletError::SpendPolicyRefused(format!(
                "CLINK debit {debit_id} refused by the mandate gate (OMEGA-DELTA-0306): {refusal_text}"
            )));
        }
        // 2. Kill + daily ceiling on the Debits path (0300 ALL-VALUE-TOUCHING).
        //    Design §3.4: a policy refusal or kill is answered on the 21002
        //    channel with the spec's GFY codes (1 denied / 4 rate limited)
        //    WITHOUT paying — the requesting peer gets a typed answer even
        //    when the local authority refuses (SEC-2026-116 closure).
        let now = now_unix();
        if let Err(error) = self
            .spend_policy
            .check_spend(SURFACE_WALLET_L402, amount_sats, now)
        {
            let (code, label) = if matches!(error, SovereignWalletError::SpendHalted(_)) {
                (1, "denied: rail halted")
            } else {
                (4, "rate limited: daily ceiling")
            };
            let _ = self
                .request(
                    "debit-refuse",
                    Some(json!({ "debitId": debit_id, "code": code, "error": format!("{label}: {error}") })),
                    self.generation(),
                )
                .await;
            return Err(error);
        }
        // 3. Forward the host-initiated settlement to the sidecar (the sidecar
        //    verifies principal == the verified event author and then pays).
        let result = self
            .request(
                "pay-debit",
                Some(json!({ "debitId": debit_id, "principal": principal })),
                self.generation(),
            )
            .await?;
        let pay: PayResult = decode(result, "pay-debit result")?;
        // 4. Loss rule: expected-vs-actual on the settled pay.
        if pay.total_outflow_known {
            let actual = pay.actual_amount_sat.parse::<u64>().unwrap_or(0);
            let expected = pay.expected_total_outflow_sat.parse::<u64>().unwrap_or(0);
            if actual > expected {
                let reason = format!(
                    "loss-rule: over-settlement on CLINK debit (actual {actual} sats > expected {expected} sats)"
                );
                // Design §3.4: a payment error is answered on the 21002
                // channel (GFY 1) before the fail-closed halt propagates.
                let _ = self
                    .request(
                        "debit-refuse",
                        Some(json!({ "debitId": debit_id, "code": 1, "error": format!("denied: {reason}") })),
                        self.generation(),
                    )
                    .await;
                self.spend_policy.auto_kill_loss_rule(&reason, now)?;
                return Err(SovereignWalletError::SpendHalted(
                    self.spend_policy.halt_message(),
                ));
            }
        }
        // Count real payments only (the sidecar confirmed the payment).
        self.spend_policy.record_spend(SURFACE_WALLET_L402, amount_sats, now)?;
        // 5. NIP-AC 39243 after the local Authorized AND the settled pay. The
        //    completion proof is the payment hash (the sidecar's reported
        //    payment hash — the preimage never travels in the projection).
        let payment_hash_digest = pay.payment_hash.as_deref().unwrap_or_default();
        crate::nipac::emit_settled_spend_pair(
            mandate_store,
            SOVEREIGN_WALLET_VENUE,
            network,
            Some(principal),
            &decision,
            amount_sats,
            Some(payment_hash_digest),
            crate::nipac::LANE_CLINK_DEBIT,
            pay.actual_amount_sat.parse::<u64>().ok(),
            payment_hash_digest,
        );
        Ok(pay)
    }

    /// OMEGA-DELTA-0306 (design §3.4): refuse a queued CLINK Debit WITHOUT
    /// paying (GFY on the 21002 channel). Used by the wrapper's caller when a
    /// Debit must be dropped for a host-level reason; the wrapper itself uses
    /// `debit-refuse` on mandate/policy refusal. Returns whether a queued
    /// debit was found and refused.
    pub async fn refuse_debit(&mut self, debit_id: &str, code: u32, error: &str) -> Result<bool, SovereignWalletError> {
        let result = self
            .request(
                "debit-refuse",
                Some(json!({ "debitId": debit_id, "code": code, "error": error })),
                self.generation(),
            )
            .await?;
        Ok(result
            .get("refused")
            .and_then(|value| value.as_bool())
            .unwrap_or(false))
    }
}

/// Current unix time in seconds (the spend policy's clock; UTC-day rollover
/// is computed from this).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}