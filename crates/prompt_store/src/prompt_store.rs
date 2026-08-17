pub mod library;
mod prompts;
pub mod rules_to_skills_migration;

pub use library::*;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use collections::HashMap;
use futures::FutureExt as _;
use futures::future::Shared;

use gpui::{App, AppContext, Entity, Global, ReadGlobal, SharedString, Task};
use heed::{
    Database, RoTxn,
    types::{SerdeBincode, SerdeJson, Str},
};
use parking_lot::RwLock;
pub use prompts::*;

use serde::{Deserialize, Serialize};
use std::{future::Future, path::PathBuf, sync::Arc};
use strum::{EnumIter, IntoEnumIterator as _};
use text::LineEnding;
use util::ResultExt;
use uuid::Uuid;

/// Init starts loading the PromptStore in the background and assigns
/// a shared future to a global.
pub fn init(cx: &mut App) {
    let db_path = paths::prompts_dir().join("prompts-library-db.0.mdb");
    let prompt_store_task = PromptStore::new(db_path, cx);
    let prompt_store_entity_task = cx
        .spawn(async move |cx| {
            prompt_store_task
                .await
                .map(|prompt_store| cx.new(|_cx| prompt_store))
                .map_err(Arc::new)
        })
        .shared();
    cx.set_global(GlobalPromptStore(prompt_store_entity_task))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptMetadata {
    pub id: PromptId,
    pub title: Option<SharedString>,
    pub default: bool,
    pub saved_at: DateTime<Utc>,
    // OMEGA-DELTA-0282. Serde defaults are mandatory: existing metadata.v2
    // rows carry none of these fields, and the store's fail-open cache skips
    // rows it cannot decode — a missing default would silently drop every
    // existing prompt from the cache.
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub scope: LibraryScope,
}

impl PromptMetadata {
    fn builtin(builtin: BuiltInPrompt) -> Self {
        Self {
            id: PromptId::BuiltIn(builtin),
            title: Some(builtin.title().into()),
            default: false,
            saved_at: DateTime::default(),
            folder: None,
            tags: Vec::new(),
            category: None,
            scope: LibraryScope::Personal,
        }
    }
}

/// Built-in prompts that have default content and can be customized by users.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter)]
pub enum BuiltInPrompt {
    CommitMessage,
}

impl BuiltInPrompt {
    pub fn title(&self) -> &'static str {
        match self {
            Self::CommitMessage => "Commit message",
        }
    }

    /// Returns the default content for this built-in prompt.
    pub fn default_content(&self) -> &'static str {
        match self {
            Self::CommitMessage => include_str!("../../git_ui/src/commit_message_prompt.txt"),
        }
    }
}

impl std::fmt::Display for BuiltInPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommitMessage => write!(f, "Commit message"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum PromptId {
    User { uuid: UserPromptId },
    BuiltIn(BuiltInPrompt),
}

impl PromptId {
    pub fn new() -> PromptId {
        UserPromptId::new().into()
    }

    pub fn as_user(&self) -> Option<UserPromptId> {
        match self {
            Self::User { uuid } => Some(*uuid),
            Self::BuiltIn { .. } => None,
        }
    }

    pub fn as_built_in(&self) -> Option<BuiltInPrompt> {
        match self {
            Self::User { .. } => None,
            Self::BuiltIn(builtin) => Some(*builtin),
        }
    }

    pub fn is_built_in(&self) -> bool {
        matches!(self, Self::BuiltIn { .. })
    }
}

impl From<BuiltInPrompt> for PromptId {
    fn from(builtin: BuiltInPrompt) -> Self {
        PromptId::BuiltIn(builtin)
    }
}

impl From<UserPromptId> for PromptId {
    fn from(uuid: UserPromptId) -> Self {
        PromptId::User { uuid }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserPromptId(pub Uuid);

impl UserPromptId {
    pub fn new() -> UserPromptId {
        UserPromptId(Uuid::new_v4())
    }
}

impl From<Uuid> for UserPromptId {
    fn from(uuid: Uuid) -> Self {
        UserPromptId(uuid)
    }
}

impl std::fmt::Display for PromptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptId::User { uuid } => write!(f, "{}", uuid.0),
            PromptId::BuiltIn(builtin) => write!(f, "{}", builtin),
        }
    }
}

pub struct PromptStore {
    env: heed::Env,
    metadata_cache: RwLock<MetadataCache>,
    bodies: Database<SerdeJson<PromptId>, Str>,
    // OMEGA-DELTA-0282. Sibling library database holding saved-analysis and
    // capability records (prompt records stay in metadata.v2 / bodies.v2 so
    // existing consumers iterate prompts unchanged).
    library: Database<SerdeJson<LibraryRecordId>, SerdeJson<LibraryRecord>>,
    library_cache: RwLock<LibraryCache>,
}

#[derive(Default)]
struct MetadataCache {
    metadata: Vec<PromptMetadata>,
    metadata_by_id: HashMap<PromptId, PromptMetadata>,
}

/// In-memory search layer for the library (WP10 §3.5): library records from
/// `library.db` and the prompt search text (title + body) pulled from
/// `bodies.v2` at open. Expected personal-library sizes make a full
/// in-memory substring pass instant (N3); the scale guard is the WP10
/// re-evaluate trigger, not a schema change.
#[derive(Default)]
struct LibraryCache {
    records: Vec<LibraryRecord>,
    records_by_id: HashMap<LibraryRecordId, LibraryRecord>,
    prompt_bodies: HashMap<PromptId, String>,
}

impl MetadataCache {
    fn from_db(
        db: Database<SerdeJson<PromptId>, SerdeJson<PromptMetadata>>,
        txn: &RoTxn,
    ) -> Result<Self> {
        let mut cache = MetadataCache::default();
        for result in db.iter(txn)? {
            // Fail-open: skip records that can't be decoded (e.g. from a different branch)
            // rather than failing the entire prompt store initialization.
            let Ok((prompt_id, metadata)) = result else {
                log::warn!(
                    "Skipping unreadable prompt record in database: {:?}",
                    result.err()
                );
                continue;
            };
            cache.metadata.push(metadata.clone());
            cache.metadata_by_id.insert(prompt_id, metadata);
        }

        // Insert all the built-in prompts that were not customized by the user
        for builtin in BuiltInPrompt::iter() {
            let builtin_id = PromptId::BuiltIn(builtin);
            if !cache.metadata_by_id.contains_key(&builtin_id) {
                let metadata = PromptMetadata::builtin(builtin);
                cache.metadata.push(metadata.clone());
                cache.metadata_by_id.insert(builtin_id, metadata);
            }
        }
        cache.sort();
        Ok(cache)
    }

    fn sort(&mut self) {
        self.metadata.sort_unstable_by(|a, b| {
            a.title
                .cmp(&b.title)
                .then_with(|| b.saved_at.cmp(&a.saved_at))
        });
    }
}

impl LibraryCache {
    fn from_db(
        db: Database<SerdeJson<LibraryRecordId>, SerdeJson<LibraryRecord>>,
        bodies: Database<SerdeJson<PromptId>, Str>,
        txn: &RoTxn,
    ) -> Result<Self> {
        let mut cache = LibraryCache::default();
        for result in db.iter(txn)? {
            // Fail-open, matching MetadataCache: skip records that can't be
            // decoded (e.g. from a different branch) rather than failing the
            // whole store open.
            let Ok((record_id, record)) = result else {
                log::warn!(
                    "Skipping unreadable library record in database: {:?}",
                    result.err()
                );
                continue;
            };
            cache.records.push(record.clone());
            cache.records_by_id.insert(record_id, record);
        }
        cache.records.sort_unstable_by(|a, b| {
            b.saved_at()
                .cmp(&a.saved_at())
                .then_with(|| a.record_id().0.cmp(&b.record_id().0))
        });
        for result in bodies.iter(txn)? {
            let Ok((prompt_id, body)) = result else {
                // Same fail-open posture as the metadata cache.
                continue;
            };
            cache.prompt_bodies.insert(prompt_id, body.to_string());
        }
        Ok(cache)
    }
}

impl PromptStore {
    pub fn global(cx: &App) -> impl Future<Output = Result<Entity<Self>>> + use<> {
        let store = GlobalPromptStore::global(cx).0.clone();
        async move { store.await.map_err(|err| anyhow!(err)) }
    }

    pub fn new(db_path: PathBuf, cx: &App) -> Task<Result<Self>> {
        cx.background_spawn(async move { Self::open(db_path) })
    }

    /// Synchronous constructor used by `new` (which runs it on the background
    /// executor) and by the `library_cli` bridge binary, which cannot
    /// construct a gpui `App`.
    pub fn open(db_path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&db_path)?;

        let db_env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(1024 * 1024 * 1024) // 1GB
                // OMEGA-DELTA-0282. The two existing slots are
                // metadata.v2 + bodies.v2 (plus their v1-reserve pair);
                // library.db is the added sibling. Two new slots: the active
                // library database and a named-DB reserve, mirroring the
                // established v1-reserve pattern.
                .max_dbs(6)
                .open(db_path)?
        };

        let mut txn = db_env.write_txn()?;
        let metadata = db_env.create_database(&mut txn, Some("metadata.v2"))?;
        let bodies = db_env.create_database(&mut txn, Some("bodies.v2"))?;
        // OMEGA-DELTA-0282. Sibling database for saved-analysis and
        // capability records; prompt records remain in metadata.v2/bodies.v2.
        let library = db_env.create_database(&mut txn, Some("library.db"))?;
        txn.commit()?;

        Self::upgrade_dbs(&db_env, metadata, bodies).log_err();

        let txn = db_env.read_txn()?;
        let metadata_cache = MetadataCache::from_db(metadata, &txn)?;
        let library_cache = LibraryCache::from_db(library, bodies, &txn)?;
        txn.commit()?;

        Ok(PromptStore {
            env: db_env,
            metadata_cache: RwLock::new(metadata_cache),
            bodies,
            library,
            library_cache: RwLock::new(library_cache),
        })
    }

    fn upgrade_dbs(
        env: &heed::Env,
        metadata_db: heed::Database<SerdeJson<PromptId>, SerdeJson<PromptMetadata>>,
        bodies_db: heed::Database<SerdeJson<PromptId>, Str>,
    ) -> Result<()> {
        let mut txn = env.write_txn()?;
        let Some(bodies_v1_db) = env
            .open_database::<SerdeBincode<PromptIdV1>, SerdeBincode<String>>(
                &txn,
                Some("bodies"),
            )?
        else {
            return Ok(());
        };
        let mut bodies_v1 = bodies_v1_db
            .iter(&txn)?
            .collect::<heed::Result<HashMap<_, _>>>()?;

        let Some(metadata_v1_db) = env
            .open_database::<SerdeBincode<PromptIdV1>, SerdeBincode<PromptMetadataV1>>(
                &txn,
                Some("metadata"),
            )?
        else {
            return Ok(());
        };
        let metadata_v1 = metadata_v1_db
            .iter(&txn)?
            .collect::<heed::Result<HashMap<_, _>>>()?;

        for (prompt_id_v1, metadata_v1) in metadata_v1 {
            let prompt_id_v2 = UserPromptId(prompt_id_v1.0).into();
            let Some(body_v1) = bodies_v1.remove(&prompt_id_v1) else {
                continue;
            };

            if metadata_db
                .get(&txn, &prompt_id_v2)?
                .is_none_or(|metadata_v2| metadata_v1.saved_at > metadata_v2.saved_at)
            {
                metadata_db.put(
                    &mut txn,
                    &prompt_id_v2,
                    &PromptMetadata {
                        id: prompt_id_v2,
                        title: metadata_v1.title.clone(),
                        default: metadata_v1.default,
                        saved_at: metadata_v1.saved_at,
                        // OMEGA-DELTA-0282. Migrated v1 rows carry the
                        // defaulted organization fields, same as fresh rows.
                        folder: None,
                        tags: Vec::new(),
                        category: None,
                        scope: LibraryScope::Personal,
                    },
                )?;
                bodies_db.put(&mut txn, &prompt_id_v2, &body_v1)?;
            }
        }

        txn.commit()?;

        Ok(())
    }

    pub fn load(&self, id: PromptId, cx: &App) -> Task<Result<String>> {
        let env = self.env.clone();
        let bodies = self.bodies;
        cx.background_spawn(async move {
            let txn = env.read_txn()?;
            let mut prompt: String = match bodies.get(&txn, &id)? {
                Some(body) => body.into(),
                None => {
                    if let Some(built_in) = id.as_built_in() {
                        built_in.default_content().into()
                    } else {
                        anyhow::bail!("prompt not found")
                    }
                }
            };
            LineEnding::normalize(&mut prompt);
            Ok(prompt)
        })
    }

    pub fn all_prompt_metadata(&self) -> Vec<PromptMetadata> {
        self.metadata_cache.read().metadata.clone()
    }

    // ------------------------------------------------------------
    // OMEGA-DELTA-0282. Library records (saved-analysis + capability) and
    // the in-memory search layer (WP10 §3.5). This is the only read path for
    // library records, so the later #316 UI and the MCP tools draw from one
    // query layer.
    // ------------------------------------------------------------

    /// Persist a `saved-analysis` or `capability` record into `library.db`
    /// and the in-memory cache. The personal-only write gate rejects
    /// `LibraryScope::Shared` in V1 (PRD §5.6; activation would be a founder
    /// privacy decision).
    pub fn save_library_record(&self, record: LibraryRecord) -> Result<LibraryRecordId> {
        if record.scope() == LibraryScope::Shared {
            anyhow::bail!(
                "shared library records are not writable in V1 (OMEGA-DELTA-0282); \
                 the personal-only write path rejects them"
            );
        }
        let record_id = record.record_id();
        {
            let cache = self.library_cache.read();
            if cache.records_by_id.contains_key(&record_id) {
                anyhow::bail!("library record already exists: {record_id}");
            }
        }
        let mut txn = self.env.write_txn()?;
        self.library.put(&mut txn, &record_id, &record)?;
        txn.commit()?;
        let mut cache = self.library_cache.write();
        cache.records.push(record.clone());
        cache.records_by_id.insert(record_id, record);
        cache.records.sort_unstable_by(|a, b| {
            b.saved_at()
                .cmp(&a.saved_at())
                .then_with(|| a.record_id().0.cmp(&b.record_id().0))
        });
        Ok(record_id)
    }

    /// Read one library record by id — the single store read WP1's T4 reopen
    /// promise is built on. Missing records return `Ok(None)`.
    pub fn get_library_record(&self, record_id: LibraryRecordId) -> Result<Option<LibraryRecord>> {
        let txn = self.env.read_txn()?;
        let record = self.library.get(&txn, &record_id)?;
        txn.commit()?;
        Ok(record)
    }

    /// Remove a library record from `library.db` and the cache. Returns
    /// `Ok(true)` when a record was deleted, `Ok(false)` when none existed.
    pub fn delete_library_record(&self, record_id: LibraryRecordId) -> Result<bool> {
        let exists = self
            .library_cache
            .read()
            .records_by_id
            .contains_key(&record_id);
        if !exists {
            return Ok(false);
        }
        let mut txn = self.env.write_txn()?;
        self.library.delete(&mut txn, &record_id)?;
        txn.commit()?;
        let mut cache = self.library_cache.write();
        cache.records_by_id.remove(&record_id);
        cache
            .records
            .retain(|record| record.record_id() != record_id);
        Ok(true)
    }

    /// Case-insensitive keyword search over prompt (title + body) and library
    /// records (saved-analysis title + search_text; capability name +
    /// description + tags), with exact-match folder/category/tags filters and
    /// a personal-scope default (WP10 §3.5). `None` query is a pure list.
    pub fn search_library(
        &self,
        query: Option<&str>,
        filters: &LibrarySearchFilters,
        limit: usize,
        offset: usize,
    ) -> Vec<LibrarySearchResult> {
        let scope = filters.scope.unwrap_or(LibraryScope::Personal);
        let needle = query.unwrap_or_default().trim();

        let mut results: Vec<LibrarySearchResult> = Vec::new();

        if filters
            .record_kind
            .is_none_or(|kind| kind == LibraryRecordKind::Prompt)
        {
            let cache = self.metadata_cache.read();
            let bodies = self.library_cache.read();
            for metadata in cache.metadata.iter() {
                if metadata.scope != scope {
                    continue;
                }
                if let Some(folder) = &filters.folder {
                    if metadata.folder.as_ref() != Some(folder) {
                        continue;
                    }
                }
                if let Some(category) = &filters.category {
                    if metadata.category.as_ref() != Some(category) {
                        continue;
                    }
                }
                if !filters.tags.is_empty()
                    && !filters.tags.iter().any(|tag| metadata.tags.contains(tag))
                {
                    continue;
                }
                let body = bodies.prompt_bodies.get(&metadata.id).cloned();
                let title = metadata
                    .title
                    .as_ref()
                    .map(|title| title.to_string())
                    .unwrap_or_default();
                let mut search_text = title.clone();
                if let Some(body) = &body {
                    search_text.push(' ');
                    search_text.push_str(body);
                }
                let haystack = search_text.to_lowercase();
                if !needle.is_empty() && !haystack.contains(&needle.to_lowercase()) {
                    continue;
                }
                let snippet = snippet_for(needle, &search_text);
                results.push(LibrarySearchResult {
                    record_id: metadata.id.to_string(),
                    record_kind: LibraryRecordKind::Prompt.label().into(),
                    title: title.clone(),
                    scope: metadata.scope,
                    saved_at: metadata.saved_at,
                    folder: metadata.folder.clone(),
                    tags: metadata.tags.clone(),
                    category: metadata.category.clone(),
                    snippet,
                });
            }
        }

        let wants_library = filters.record_kind.is_none_or(|kind| {
            kind == LibraryRecordKind::SavedAnalysis || kind == LibraryRecordKind::Capability
        });
        if wants_library {
            let cache = self.library_cache.read();
            for record in cache.records.iter() {
                if record.scope() != scope {
                    continue;
                }
                if let Some(kind) = filters.record_kind {
                    if record.kind() != kind {
                        continue;
                    }
                }
                if let Some(folder) = &filters.folder {
                    let record_folder = match record {
                        LibraryRecord::SavedAnalysis(r) => r.folder.clone(),
                        LibraryRecord::Capability(r) => r.folder.clone(),
                    };
                    if record_folder != Some(folder.clone()) {
                        continue;
                    }
                }
                if let Some(category) = &filters.category {
                    let record_category = match record {
                        LibraryRecord::SavedAnalysis(r) => r.category.clone(),
                        LibraryRecord::Capability(r) => r.category.clone(),
                    };
                    if record_category != Some(category.clone()) {
                        continue;
                    }
                }
                let record_tags: Vec<String> = match record {
                    LibraryRecord::SavedAnalysis(r) => r.tags.clone(),
                    LibraryRecord::Capability(r) => r.tags.clone(),
                };
                if !filters.tags.is_empty()
                    && !filters.tags.iter().any(|tag| record_tags.contains(tag))
                {
                    continue;
                }
                let searchable = record.searchable_text();
                if !needle.is_empty() && !searchable.to_lowercase().contains(&needle.to_lowercase())
                {
                    continue;
                }
                let snippet = snippet_for(needle, &searchable);
                let (folder, category, tags) = match record {
                    LibraryRecord::SavedAnalysis(r) => {
                        (r.folder.clone(), r.category.clone(), r.tags.clone())
                    }
                    LibraryRecord::Capability(r) => {
                        (r.folder.clone(), r.category.clone(), r.tags.clone())
                    }
                };
                results.push(LibrarySearchResult {
                    record_id: record.record_id().to_string(),
                    record_kind: record.kind().label().into(),
                    title: record.title(),
                    scope: record.scope(),
                    saved_at: record.saved_at(),
                    folder,
                    tags,
                    category,
                    snippet,
                });
            }
        }

        results.sort_unstable_by(|a, b| {
            // Deterministic ordering for the V1 search surface: newest first,
            // then kind (prompt < saved-analysis < capability), then title.
            b.saved_at
                .cmp(&a.saved_at)
                .then_with(|| a.record_kind.cmp(&b.record_kind))
                .then_with(|| b.title.to_lowercase().cmp(&a.title.to_lowercase()))
        });

        results.into_iter().skip(offset).take(limit).collect()
    }
}

/// Deprecated: Legacy V1 prompt ID format, used only for migrating data from old databases. Use `PromptId` instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
struct PromptIdV1(Uuid);

impl From<UserPromptId> for PromptIdV1 {
    fn from(id: UserPromptId) -> Self {
        PromptIdV1(id.0)
    }
}

/// Deprecated: Legacy V1 prompt metadata format, used only for migrating data from old databases. Use `PromptMetadata` instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PromptMetadataV1 {
    id: PromptIdV1,
    title: Option<SharedString>,
    default: bool,
    saved_at: DateTime<Utc>,
}

/// Wraps a shared future to a prompt store so it can be assigned as a context global.
pub struct GlobalPromptStore(Shared<Task<Result<Entity<PromptStore>, Arc<anyhow::Error>>>>);

impl Global for GlobalPromptStore {}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::TestAppContext;

    #[gpui::test]
    async fn test_built_in_prompt_load(cx: &mut TestAppContext) {
        cx.executor().allow_parking();

        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("prompts-db");

        let store = cx.update(|cx| PromptStore::new(db_path, cx)).await.unwrap();
        let store = cx.new(|_cx| store);

        let commit_message_id = PromptId::BuiltIn(BuiltInPrompt::CommitMessage);

        let loaded_content = store
            .update(cx, |store, cx| store.load(commit_message_id, cx))
            .await
            .unwrap();

        let mut expected_content = BuiltInPrompt::CommitMessage.default_content().to_string();
        LineEnding::normalize(&mut expected_content);
        assert_eq!(
            loaded_content.trim(),
            expected_content.trim(),
            "Loading a built-in prompt not in DB should return default content"
        );

        assert!(
            store.read_with(cx, |store, _| {
                store
                    .all_prompt_metadata()
                    .iter()
                    .any(|metadata| metadata.id == commit_message_id)
            }),
            "Built-in prompt should always be in cache"
        );
    }

    /// OMEGA-DELTA-0282. Rows written before the library extension (no
    /// folder/tags/category/scope fields) must decode with serde defaults,
    /// not be dropped by the fail-open cache.
    #[test]
    fn test_legacy_prompt_rows_decode_with_defaulted_library_fields() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("prompts-db");
        let store = PromptStore::open(db_path.clone()).unwrap();

        // The pre-extension prompt metadata shape.
        #[derive(Serialize, Deserialize)]
        struct LegacyPromptMetadata {
            id: PromptId,
            title: Option<SharedString>,
            default: bool,
            saved_at: DateTime<Utc>,
        }
        let legacy_id = PromptId::new();
        let legacy = LegacyPromptMetadata {
            id: legacy_id,
            title: Some("Legacy prompt".into()),
            default: true,
            saved_at: Utc::now(),
        };
        {
            let mut txn = store.env.write_txn().unwrap();
            let legacy_db: heed::Database<SerdeJson<PromptId>, SerdeJson<LegacyPromptMetadata>> =
                store
                    .env
                    .create_database(&mut txn, Some("metadata.v2"))
                    .unwrap();
            legacy_db.put(&mut txn, &legacy_id, &legacy).unwrap();
            txn.commit().unwrap();
        }
        drop(store);

        let reopened = PromptStore::open(db_path).unwrap();
        let metadata = reopened
            .all_prompt_metadata()
            .into_iter()
            .find(|metadata| metadata.id == legacy_id)
            .expect("legacy row must decode into the cache and not be skipped");
        assert_eq!(metadata.scope, LibraryScope::Personal);
        assert_eq!(metadata.folder, None);
        assert_eq!(metadata.category, None);
        assert!(metadata.tags.is_empty());
        assert!(metadata.default);
    }

    /// OMEGA-DELTA-0282. The library-record round trip: save → search →
    /// reopen (single store read) → delete, plus the personal-only write
    /// gate. This is the WP3 QA round-trip in miniature.
    #[test]
    fn test_library_record_round_trip_save_search_get_delete() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("prompts-db");
        let store = PromptStore::open(db_path).unwrap();

        let record_id = LibraryRecordId::new();
        let artifact_body = serde_json::json!({
            "id": "0197-summarized",
            "kind": "source-analysis",
            "summary": "The warranty covers parts but not labor after year one.",
        })
        .to_string();
        let record = LibraryRecord::SavedAnalysis(SavedAnalysisRecord {
            record_id,
            record_title: "Warranty inspection summary".into(),
            saved_at: Utc::now(),
            scope: LibraryScope::Personal,
            artifact_id: "0197-summarized".into(),
            artifact_digest: "abc123".into(),
            publisher_signature: "signature".into(),
            publisher_npub: "npub1placeholderidentity".into(),
            folder: Some("research".into()),
            tags: vec!["hvac".into(), "warranty".into()],
            category: Some("reference".into()),
            search_text: "warranty inspection scope spare parts".into(),
            artifact_body,
        });

        let saved_id = store.save_library_record(record.clone()).unwrap();
        assert_eq!(saved_id, record_id);

        let filters = LibrarySearchFilters {
            record_kind: Some(LibraryRecordKind::SavedAnalysis),
            scope: Some(LibraryScope::Personal),
            ..LibrarySearchFilters::default()
        };
        let hits = store.search_library(Some("warranty"), &filters, 10, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, record_id.to_string());
        assert_eq!(hits[0].record_kind, "saved-analysis");
        assert_eq!(hits[0].title, "Warranty inspection summary");
        assert!(
            hits[0]
                .snippet
                .as_deref()
                .is_some_and(|snippet| snippet.to_lowercase().contains("warranty"))
        );

        assert!(
            store
                .search_library(Some("boiler"), &filters, 10, 0)
                .is_empty(),
            "unrelated query must not match the saved analysis"
        );

        // Reopen path: a single store read by record id.
        let expected_artifact_body = match &record {
            LibraryRecord::SavedAnalysis(saved) => saved.artifact_body.clone(),
            _ => panic!("fixture must be a saved-analysis"),
        };
        let loaded = store
            .get_library_record(record_id)
            .unwrap()
            .expect("record must reopen by id");
        match &loaded {
            LibraryRecord::SavedAnalysis(reopened) => {
                assert_eq!(reopened.artifact_body, expected_artifact_body);
                assert_eq!(reopened.artifact_digest, "abc123");
                assert_eq!(reopened.publisher_npub, "npub1placeholderidentity");
            }
            _ => panic!("reopened record must be a saved-analysis"),
        }

        assert!(
            store.save_library_record(record.clone()).is_err(),
            "duplicate record id must be refused"
        );

        // Personal-only write gate: a fresh shared-scope record is refused.
        let mut shared = record.clone();
        let shared_id = LibraryRecordId::new();
        if let LibraryRecord::SavedAnalysis(shared_record) = &mut shared {
            shared_record.record_id = shared_id;
            shared_record.scope = LibraryScope::Shared;
        }
        let scope_error = store.save_library_record(shared).unwrap_err();
        assert!(
            scope_error.to_string().contains("not writable"),
            "shared records must be refused with an honest message"
        );

        assert!(store.delete_library_record(record_id).unwrap());
        assert!(!store.delete_library_record(record_id).unwrap());
        assert!(store.get_library_record(record_id).unwrap().is_none());
    }

    /// OMEGA-DELTA-0282. Capability records (M9 catalog shape) are saved,
    /// searched by name/description/tags, and returned with their L-402
    /// payment and operator-identity blocks intact.
    #[test]
    fn test_capability_record_save_and_search() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("prompts-db");
        let store = PromptStore::open(db_path).unwrap();

        let record = LibraryRecord::Capability(CapabilityRecord {
            record_id: LibraryRecordId::new(),
            name: "Omega Source Summarization".into(),
            description: "Summarize and conversationally analyze any URL source; grounded follow-up; saved analyses.".into(),
            tags: vec!["summarization".into(), "mcp".into(), "url".into()],
            endpoint: None,
            payment: PaymentTerms {
                method: "l402".into(),
                price_per_run_sats: None,
                terms: None,
            },
            operator_identity: OperatorIdentity {
                npub: "npub1placeholderidentity".into(),
            },
            scope: LibraryScope::Personal,
            folder: Some("catalog".into()),
            category: Some("capability".into()),
            saved_at: Utc::now(),
        });
        let record_id = store.save_library_record(record).unwrap();

        let filters = LibrarySearchFilters {
            record_kind: Some(LibraryRecordKind::Capability),
            scope: Some(LibraryScope::Personal),
            ..LibrarySearchFilters::default()
        };
        let by_name = store.search_library(Some("summarization"), &filters, 10, 0);
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].record_id, record_id.to_string());
        assert_eq!(by_name[0].record_kind, "capability");

        let tagged = LibrarySearchFilters {
            record_kind: Some(LibraryRecordKind::Capability),
            tags: vec!["mcp".into()],
            scope: Some(LibraryScope::Personal),
            ..LibrarySearchFilters::default()
        };
        assert_eq!(store.search_library(None, &tagged, 10, 0).len(), 1);

        let unrelated = store.search_library(Some("pricing"), &filters, 10, 0);
        assert!(unrelated.is_empty());
    }
}
