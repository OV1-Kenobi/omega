//! Library records: the discoverable mirror of saved source analyses (PRD M5)
//! and the discovery-catalog records for capabilities (PRD M9), stored in the
//! sibling `library.db` inside the prompts LMDB environment.
//!
//! OMEGA-DELTA-0282. Upstream Zed's prompt store knows only prompt records
//! (id/title/default/saved_at). Omega adds two record kinds (saved-analysis
//! and capability), a modeled personal-vs-shared scope boundary, and
//! folder/tag/category organization metadata, all in place and backward
//! compatibly. The final record shape authority is `wp10-library-foundation
//! -design.md` section 3.4 (founder-approved 2026-08-16).
//!
//! Privacy line (PRD P10/P11): this store holds the founder's own local
//! knowledge. Nothing in it may ever be mirrored, logged, metered, or
//! transmitted to an operator-side surface (counts/digests/timestamps only).
//! Shared-library activation is a future founder privacy decision; the write
//! path rejects `LibraryScope::Shared` in V1.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Personal vs shared boundary, modeled from day one (PRD §5.6).
///
/// V1 is personal-only: the write path rejects `Shared`, so no record can
/// silently become shared. Activation later (PRD C4) changes the write
/// policy and the search-scope default, not this schema.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryScope {
    #[default]
    Personal,
    Shared,
}

impl fmt::Display for LibraryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LibraryScope::Personal => write!(f, "personal"),
            LibraryScope::Shared => write!(f, "shared"),
        }
    }
}

/// A library record's id: a UUIDv7, serialized transparently like the
/// existing `UserPromptId`. This is the same id WP1's T3 returns as
/// `record_id`, T4/T5 use as their lookup key, and `SourceArtifact.record`
/// carries — one value everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LibraryRecordId(pub Uuid);

impl LibraryRecordId {
    pub fn new() -> LibraryRecordId {
        LibraryRecordId(Uuid::now_v7())
    }
}

impl fmt::Display for LibraryRecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The three record kinds the library can hold. The serialized JSON carries
/// `record_kind` on every record (WP10 §3.3): `prompt`, `saved-analysis`,
/// or `capability`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryRecordKind {
    #[serde(rename = "prompt")]
    Prompt,
    #[serde(rename = "saved-analysis")]
    SavedAnalysis,
    #[serde(rename = "capability")]
    Capability,
}

impl LibraryRecordKind {
    pub fn label(self) -> &'static str {
        match self {
            LibraryRecordKind::Prompt => "prompt",
            LibraryRecordKind::SavedAnalysis => "saved-analysis",
            LibraryRecordKind::Capability => "capability",
        }
    }
}

/// A record stored in `library.db` (saved-analysis and capability kinds;
/// prompt records stay in `metadata.v2`/`bodies.v2`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "record_kind")]
pub enum LibraryRecord {
    #[serde(rename = "saved-analysis")]
    SavedAnalysis(SavedAnalysisRecord),
    #[serde(rename = "capability")]
    Capability(CapabilityRecord),
}

impl LibraryRecord {
    pub fn record_id(&self) -> LibraryRecordId {
        match self {
            LibraryRecord::SavedAnalysis(record) => record.record_id,
            LibraryRecord::Capability(record) => record.record_id,
        }
    }

    pub fn kind(&self) -> LibraryRecordKind {
        match self {
            LibraryRecord::SavedAnalysis(_) => LibraryRecordKind::SavedAnalysis,
            LibraryRecord::Capability(_) => LibraryRecordKind::Capability,
        }
    }

    pub fn scope(&self) -> LibraryScope {
        match self {
            LibraryRecord::SavedAnalysis(record) => record.scope,
            LibraryRecord::Capability(record) => record.scope,
        }
    }

    pub fn saved_at(&self) -> DateTime<Utc> {
        match self {
            LibraryRecord::SavedAnalysis(record) => record.saved_at,
            LibraryRecord::Capability(record) => record.saved_at,
        }
    }

    /// Searchable text used by the in-memory search index (WP10 §3.5).
    /// Saved analyses match on title + `search_text`; capabilities on
    /// name + description + tags.
    pub fn searchable_text(&self) -> String {
        match self {
            LibraryRecord::SavedAnalysis(record) => {
                format!("{} {}", record.record_title, record.search_text)
            }
            LibraryRecord::Capability(record) => {
                let mut text = format!("{} {}", record.name, record.description);
                if !record.tags.is_empty() {
                    text.push_str(" ");
                    text.push_str(&record.tags.join(" "));
                }
                text
            }
        }
    }

    /// The display title/name of the record, for search results and lists.
    pub fn title(&self) -> String {
        match self {
            LibraryRecord::SavedAnalysis(record) => record.record_title.clone(),
            LibraryRecord::Capability(record) => record.name.clone(),
        }
    }
}

/// The M5 discoverable mirror of a `SourceArtifact` (WP1 §3.4). Thread
/// persistence is the base; this record is the discoverable, reopenable
/// copy. `artifact_body` carries the signed artifact JSON so WP1's T4
/// across-thread reopen promise is a single store read.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedAnalysisRecord {
    pub record_id: LibraryRecordId,
    pub record_title: String,
    pub saved_at: DateTime<Utc>,
    pub scope: LibraryScope,
    pub artifact_id: String,
    pub artifact_digest: String,
    pub publisher_signature: String,
    pub publisher_npub: String,
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub category: Option<String>,
    /// Opaque locally stored searchable string, derived at save time from
    /// the title and the artifact's key points. Local founder-owned data;
    /// never mirrored to an operator surface (P10 boundary).
    pub search_text: String,
    /// The serialized signed `SourceArtifact` JSON.
    pub artifact_body: String,
}

/// The M9 discovery-catalog entry shape, canonical on the official MCP
/// Registry convention (founder lock, 2026-08-16): name, description, tags,
/// endpoint, L-402 payment mechanics denominated in sats (P9), and the
/// operator identity per #314 rule 7. V1 records carry the local stdio form;
/// `endpoint`/`price_per_run_sats` are populated by WP6 (value-pending).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityRecord {
    pub record_id: LibraryRecordId,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub endpoint: Option<String>,
    pub payment: PaymentTerms,
    pub operator_identity: OperatorIdentity,
    pub scope: LibraryScope,
    pub folder: Option<String>,
    pub category: Option<String>,
    pub saved_at: DateTime<Utc>,
}

/// Sats-denominated L-402 payment mechanics (PRD P1/P9). Value-pending in
/// V1 (pricing decision is WP6/D5); the shape is schema-final.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentTerms {
    pub method: String,
    pub price_per_run_sats: Option<u64>,
    pub terms: Option<String>,
}

/// The single durable Nostr service identity per #314 rule 7 (public,
/// persistent, multi-party, L-402-collecting, reputation-bearing). Declared
/// and held now (WP1 §3.4 item 4) so discovery, receipts, and the plugin
/// model bind to one identity without a later migration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub npub: String,
}

/// Exact-match filters over organization fields (WP10 §3.5). Folder/category
/// are single exact values; tags match when any requested tag is present.
/// `record_kind` narrows to one kind; None searches all three.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LibrarySearchFilters {
    pub folder: Option<String>,
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub record_kind: Option<LibraryRecordKind>,
    /// If None, the V1 default constrains the query to `Personal`.
    pub scope: Option<LibraryScope>,
}

/// One search hit, shaped for every later consumer (a library panel, a
/// command palette, a composer insert — WP10 §3.5). `snippet` is a bounded,
/// matched-text excerpt.
#[derive(Clone, Debug, Serialize)]
pub struct LibrarySearchResult {
    pub record_id: String,
    pub record_kind: String,
    pub title: String,
    pub scope: LibraryScope,
    pub saved_at: DateTime<Utc>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub category: Option<String>,
    pub snippet: Option<String>,
}

/// How wide the matched-text excerpt in a result may be.
pub const SNIPPET_CHARS: usize = 120;

/// Build a bounded matched-text excerpt from `text` for `query`. With no
/// query (pure list mode) the excerpt is the head of the text; otherwise it
/// is a window around the first case-insensitive match.
pub fn snippet_for(query: &str, text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let haystack = trimmed.to_lowercase();
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Some(clip(&trimmed.to_string(), SNIPPET_CHARS, 0));
    }
    match haystack.find(&needle) {
        Some(match_start) => {
            let window_start = match_start.saturating_sub(SNIPPET_CHARS / 2);
            Some(clip(trimmed, SNIPPET_CHARS, window_start))
        }
        None => Some(clip(trimmed, SNIPPET_CHARS, 0)),
    }
}

fn clip(text: &str, limit: usize, start: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let begin = start.min(chars.len());
    let end = (begin + limit.min(chars.len().saturating_sub(begin))).min(chars.len());
    let mut out: String = chars[begin..end].iter().collect();
    if end < chars.len() {
        out.push('…');
    }
    out
}
