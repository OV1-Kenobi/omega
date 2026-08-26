//! Typed client for the sovereign wallet sidecar loopback protocol (design §2).

use anyhow::{anyhow, Result};
use serde_json::{Value, json};

use crate::protocol::{BalanceResult, ErrorCode, InvoiceResult, PayResult, StatusResult};
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
/// where the signet/regtest hard-bail is enforced (SEC-2026-050).
impl SovereignWalletSupervisor {
    pub async fn status(&mut self) -> Result<StatusResult, SovereignWalletError> {
        let result = self.request("status", None, self.generation()).await?;
        decode(result, "status result")
    }

    pub async fn balance(&mut self) -> Result<BalanceResult, SovereignWalletError> {
        let result = self.request("balance", None, self.generation()).await?;
        decode(result, "balance result")
    }

    pub async fn create_wallet(
        &mut self,
        idempotency_key: &str,
        password: &str,
    ) -> Result<Value, SovereignWalletError> {
        // Operator-only method; the response carries the show-once aezeed and
        // is never logged by the supervisor (SEC-2026-046).
        self.request(
            "create-wallet",
            Some(json!({ "idempotencyKey": idempotency_key, "password": password })),
            self.generation(),
        )
        .await
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
        let result = self
            .request(
                "make-invoice",
                Some(json!({ "amtSat": amt_sat, "memo": memo, "idempotencyKey": idempotency_key })),
                self.generation(),
            )
            .await?;
        decode(result, "invoice result")
    }

    pub async fn pay_invoice(&mut self, invoice: &str, idempotency_key: &str) -> Result<PayResult, SovereignWalletError> {
        let result = self
            .request(
                "pay-invoice",
                Some(json!({ "invoice": invoice, "idempotencyKey": idempotency_key })),
                self.generation(),
            )
            .await?;
        decode(result, "pay result")
    }

    pub async fn activity(&mut self, limit: u32) -> Result<Value, SovereignWalletError> {
        self.request(
            "activity",
            Some(json!({ "limit": limit })),
            self.generation(),
        )
        .await
    }

    pub async fn identity_status(&mut self) -> Result<Value, SovereignWalletError> {
        self.request("identity-status", None, self.generation()).await
    }

    pub async fn shutdown(&mut self) -> Result<Value, SovereignWalletError> {
        self.request("shutdown", None, self.generation()).await
    }
}