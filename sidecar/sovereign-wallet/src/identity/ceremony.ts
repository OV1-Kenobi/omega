//! Mnemonic show-once + word-challenge ceremony (WP-4).
//!
//! The 12-word BIP-39 mnemonic is generated once, shown once, then dropped —
//! never persisted in plaintext (satnam's "mnemonic shown once then dropped"
//! rule). Before the vault is considered initialized, the operator must confirm
//! they recorded the phrase by entering the words at fixed challenge positions
//! (2, 7, 11 — the satnam AuthPage challenge positions, 0-indexed [1, 6, 10]).
//!
//! The caller is responsible for zeroizing the mnemonic string and the derived
//! secret after sealing them into the vault (see `ceremony` helpers below and
//! the identity-status / create-wallet integration).

/** Fixed challenge positions (0-indexed into the 12-word phrase): 2nd, 7th, 11th. */
export const CHALLENGE_INDEXES = [1, 6, 10] as const;

export interface WordChallenge {
  indexes: readonly number[];
  answers: Record<number, string>;
}

/**
 * Verify the operator's challenge answers against the full mnemonic word list.
 * Only the words at CHALLENGE_INDEXES are compared; the challenge passes only
 * when every requested word matches case-insensitively.
 */
export function verifyChallenge(mnemonic: string, answers: Record<number, string>): boolean {
  const words = normalizeWords(mnemonic);
  if (words.length !== 12) return false;
  return CHALLENGE_INDEXES.every(
    (idx) => (answers[idx] ?? "").trim().toLowerCase() === (words[idx] ?? "").toLowerCase(),
  );
}

/** The challenge positions the operator must answer, as 1-based labels. */
export function challengeLabels(): number[] {
  return CHALLENGE_INDEXES.map((idx) => idx + 1);
}

function normalizeWords(mnemonic: string): string[] {
  return mnemonic.trim().split(/\s+/);
}
