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
}

/// Current unix time in seconds (the spend policy's clock; UTC-day rollover
/// is computed from this).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}