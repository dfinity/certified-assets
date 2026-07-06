//! Durable storage layer for the assets canister.
//!
//! [`Store`] owns every piece of state persisted in stable memory via
//! `ic-stable-structures`: the authorized set, the redirect-rule list, the two
//! monotonic id counters, per-asset metadata, content chunk bytes (through
//! [`BlobStore`]), per-chunk cert data, the cached state hash, and the
//! access-protection settings + token store. It is the single owner of the
//! `MemoryId` layout (the constants below) and the only place that touches
//! `StableCell`/`StableBTreeMap`/`BlobStore` directly.
//!
//! Everything *above* the store — asset CRUD, certification, HTTP serving, the
//! access-protection state machine, the sync harness — lives on
//! [`crate::state::State`], which holds one `Store` plus the derived/transient
//! heap state and calls these typed methods rather than reaching into stable
//! structures. Why each piece gets its own memory region is documented on the
//! types in [`crate::stable_store`].

use candid::Principal;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use serde_bytes::ByteBuf;

use crate::blob_store::BlobStore;
use crate::certification::AssetKey;
use crate::stable_store::{
    AssetMeta, AuthorizedSet, ChunkCert, ContentChunkKey, ProtectionSettings, RedirectRules,
    StateHash, TokenMeta,
};
use wire_types::{RedirectRule, SessionId};

type Mem = VirtualMemory<DefaultMemoryImpl>;

const AUTHORIZED_MEMORY: MemoryId = MemoryId::new(0);
const REDIRECT_RULES_MEMORY: MemoryId = MemoryId::new(1);
const NEXT_SESSION_ID_MEMORY: MemoryId = MemoryId::new(2);
const NEXT_CONTENT_ID_MEMORY: MemoryId = MemoryId::new(3);
const METADATA_MEMORY: MemoryId = MemoryId::new(4);
/// Content chunk index (`ContentChunkKey -> BlobRef`); the bytes live in
/// `CONTENT_DATA_MEMORY`. See [`crate::blob_store`].
const CONTENT_INDEX_MEMORY: MemoryId = MemoryId::new(5);
/// Raw contiguous chunk bytes managed by the [`BlobStore`] allocator.
const CONTENT_DATA_MEMORY: MemoryId = MemoryId::new(6);
/// Per-chunk certification data (`ContentChunkKey -> ChunkCert`); read by the
/// 206 certify/serve paths so neither has to re-hash or fully read content.
const CHUNK_CERT_MEMORY: MemoryId = MemoryId::new(7);
/// Cached canonical state hash (`StateHash`), recomputed at the end of every
/// final sync. Its own cell so the frequent counter bumps don't touch it.
const STATE_HASH_MEMORY: MemoryId = MemoryId::new(8);
/// Access-protection settings (`ProtectionSettings`): one small cell that flips
/// the canister between public and private. `None` login page ⇒ public.
const PROTECTION_MEMORY: MemoryId = MemoryId::new(9);
/// Live access tokens, keyed by their unique **label** (`label -> TokenMeta`).
/// The management view: issue/revoke/list. Empty unless protection is on. The
/// hot-path gate index is *derived* from this (in heap; see `State::token_index`).
const TOKENS_MEMORY: MemoryId = MemoryId::new(10);

/// The canister's durable state, one field per stable-memory region.
///
/// Every method here is a typed operation over one (or, for content, a paired
/// two) of those regions; callers never see a `StableCell`/`StableBTreeMap` or a
/// `MemoryId`. Reads that return an owned value (`get_asset`, `read_chunk`)
/// deserialize out of stable memory; reads that return a borrow
/// (`redirect_rules`) hand back the `StableCell`'s in-memory cached value for
/// free.
pub struct Store {
    /// Principals authorized to sync (controllers are always allowed, unstored).
    authorized: StableCell<AuthorizedSet, Mem>,
    /// Ordered redirect-rule list. Its own cell so a counter bump doesn't
    /// reserialize it (it can be large; the counters are bumped frequently).
    redirect_rules: StableCell<RedirectRules, Mem>,
    /// Monotonic, never-reused sync session id allocator.
    next_session_id: StableCell<u64, Mem>,
    /// Monotonic, never-reused chunk-group id allocator.
    next_content_id: StableCell<u64, Mem>,
    /// Per-asset metadata, ordered by key so pagination can range-seek with a
    /// key cursor instead of sorting the keyspace per query.
    metadata: StableBTreeMap<AssetKey, AssetMeta, Mem>,
    /// Raw content bytes, one chunk per `(content_id, index)`, stored
    /// contiguously in a stable region (not inline in a BTree) so reads/writes
    /// are a single `stable64_read`/`write`. See [`crate::blob_store`].
    content: BlobStore<Mem>,
    /// Per-chunk certification data (length + SHA-256), keyed by the same
    /// `(content_id, chunk_index)` as the content blob. Lets the 206 certify
    /// path stay content-free and the serve path avoid reading every chunk to
    /// locate a range. Freed alongside its content group.
    chunk_certs: StableBTreeMap<ContentChunkKey, ChunkCert, Mem>,
    /// Cached canonical state hash, recomputed at the end of every final sync
    /// and returned verbatim by the public `state_hash` endpoint. `[0; 32]`
    /// until the first sync finalizes.
    state_hash: StableCell<StateHash, Mem>,
    /// Access-protection settings. `login_page == None` (the default) ⇒ a fully
    /// public app.
    protection: StableCell<ProtectionSettings, Mem>,
    /// Live access tokens keyed by their unique **label** — the management view
    /// (issue/revoke/list, all O(log n) by label). Empty when protection is off.
    tokens: StableBTreeMap<String, TokenMeta, Mem>,
}

impl Store {
    /// Builds a `Store` over the given stable memory. `StableCell`/
    /// `StableBTreeMap` init transparently picks up existing data if the memory
    /// was already populated (e.g. after an upgrade), or starts empty over fresh
    /// memory.
    ///
    /// The explicit-memory constructor is what makes the upgrade-roundtrip unit
    /// test possible: off-wasm `DefaultMemoryImpl` is a cheaply-cloneable handle
    /// to a shared byte buffer, so a test can build two states over the same
    /// memory to simulate an upgrade.
    pub fn new(memory: DefaultMemoryImpl) -> Self {
        let mm = MemoryManager::init(memory);
        Self {
            authorized: StableCell::init(mm.get(AUTHORIZED_MEMORY), AuthorizedSet::default()),
            redirect_rules: StableCell::init(
                mm.get(REDIRECT_RULES_MEMORY),
                RedirectRules::default(),
            ),
            next_session_id: StableCell::init(mm.get(NEXT_SESSION_ID_MEMORY), 0),
            next_content_id: StableCell::init(mm.get(NEXT_CONTENT_ID_MEMORY), 0),
            metadata: StableBTreeMap::init(mm.get(METADATA_MEMORY)),
            content: BlobStore::init(mm.get(CONTENT_INDEX_MEMORY), mm.get(CONTENT_DATA_MEMORY)),
            chunk_certs: StableBTreeMap::init(mm.get(CHUNK_CERT_MEMORY)),
            state_hash: StableCell::init(mm.get(STATE_HASH_MEMORY), StateHash::default()),
            protection: StableCell::init(mm.get(PROTECTION_MEMORY), ProtectionSettings::default()),
            tokens: StableBTreeMap::init(mm.get(TOKENS_MEMORY)),
        }
    }

    // ---- id counters ----

    /// Allocates a fresh, never-reused content group id. Bumps only the
    /// counter's own cell — no other state is reserialized.
    fn alloc_content_id(&mut self) -> u64 {
        let id = *self.next_content_id.get();
        self.next_content_id.set(id + 1);
        id
    }

    /// Allocates a fresh, never-reused sync session id.
    pub fn alloc_session_id(&mut self) -> SessionId {
        let id = *self.next_session_id.get();
        self.next_session_id.set(id + 1);
        id
    }

    // ---- authorized set ----

    pub fn authorize(&mut self, principal: Principal) {
        let mut authorized = self.authorized.get().clone();
        authorized.0.insert(principal);
        self.authorized.set(authorized);
    }

    pub fn deauthorize(&mut self, principal: &Principal) {
        let mut authorized = self.authorized.get().clone();
        authorized.0.remove(principal);
        self.authorized.set(authorized);
    }

    pub fn list_authorized(&self) -> Vec<Principal> {
        self.authorized.get().0.iter().copied().collect()
    }

    pub fn is_authorized(&self, principal: &Principal) -> bool {
        self.authorized.get().0.contains(principal)
    }

    // ---- asset metadata ----

    /// Whether an asset exists at `key`.
    pub fn contains_asset(&self, key: &AssetKey) -> bool {
        self.metadata.contains_key(key)
    }

    /// The asset metadata at `key`, deserialized out of stable memory.
    pub fn get_asset(&self, key: &AssetKey) -> Option<AssetMeta> {
        self.metadata.get(key)
    }

    /// Inserts or replaces the metadata at `key`.
    pub fn put_asset(&mut self, key: AssetKey, meta: AssetMeta) {
        self.metadata.insert(key, meta);
    }

    /// Removes and returns the metadata at `key` (content bytes are freed
    /// separately via [`Self::delete_content_group`]).
    pub fn remove_asset(&mut self, key: &AssetKey) -> Option<AssetMeta> {
        self.metadata.remove(key)
    }

    /// Number of assets — the `asset_count` folded into the state-hash digest.
    pub fn asset_count(&self) -> u64 {
        self.metadata.len()
    }

    /// Every asset key, ascending. Materialized into a `Vec` so the caller can
    /// mutate assets while iterating (e.g. re-certify each in turn).
    pub fn asset_keys(&self) -> Vec<AssetKey> {
        self.metadata.keys().collect()
    }

    /// Assets in ascending key order, starting strictly after `start_after`
    /// (`None` ⇒ from the first key). Backs both paginated `get_asset_details`
    /// and the one-asset-per-step state-hash fold.
    pub fn assets_from(
        &self,
        start_after: Option<&AssetKey>,
    ) -> impl Iterator<Item = (AssetKey, AssetMeta)> + '_ {
        use std::ops::Bound::{Excluded, Unbounded};
        let lower = match start_after {
            Some(key) => Excluded(key.clone()),
            None => Unbounded,
        };
        self.metadata
            .range((lower, Unbounded))
            .map(|e| e.into_pair())
    }

    // ---- content chunks (bytes + per-chunk certs travel together) ----

    /// Writes one encoding's chunks into the content store under a fresh
    /// content-group id, returning that id and the total content length. When
    /// `chunk_hashes` is non-empty (multi-chunk encodings), also records the
    /// per-chunk cert data keyed by the same `(content_id, index)`; single-chunk
    /// encodings pass an empty slice and skip the `chunk_certs` write (the
    /// whole-encoding `sha256` covers them). `chunk_hashes`, when present, must
    /// be the same length as `chunks`.
    pub fn store_content(&mut self, chunks: &[ByteBuf], chunk_hashes: &[[u8; 32]]) -> (u64, u64) {
        let content_id = self.alloc_content_id();
        let mut content_len = 0u64;
        for (index, chunk) in chunks.iter().enumerate() {
            self.content.insert(content_id, index as u32, chunk);
            if !chunk_hashes.is_empty() {
                self.chunk_certs.insert(
                    ContentChunkKey::new(content_id, index as u32),
                    ChunkCert {
                        len: chunk.len() as u32,
                        sha256: chunk_hashes[index],
                    },
                );
            }
            content_len += chunk.len() as u64;
        }
        (content_id, content_len)
    }

    /// Frees every chunk belonging to a content group, including its per-chunk
    /// certification entries — the two regions are kept in lockstep here so no
    /// caller can free one without the other.
    pub fn delete_content_group(&mut self, content_id: u64) {
        self.content.delete_group(content_id);
        let keys: Vec<ContentChunkKey> = self
            .chunk_certs
            .range(ContentChunkKey::range(content_id))
            .map(|e| e.into_pair().0)
            .collect();
        for key in keys {
            self.chunk_certs.remove(&key);
        }
    }

    /// One chunk's bytes, or empty if absent (callers only request indices the
    /// metadata claims exist).
    pub fn read_chunk(&self, content_id: u64, chunk_index: u32) -> Vec<u8> {
        self.content
            .get(content_id, chunk_index)
            .unwrap_or_default()
    }

    /// The per-chunk cert data of a content group in `chunk_index` order, as
    /// `(chunk_index, ChunkCert)`. Tiny fixed entries; never reads chunk bytes.
    /// Feeds 206 certification, the state-hash manifest, and range serving.
    pub fn chunk_certs_of(&self, content_id: u64) -> impl Iterator<Item = (u32, ChunkCert)> + '_ {
        self.chunk_certs
            .range(ContentChunkKey::range(content_id))
            .map(|e| {
                let (key, cert) = e.into_pair();
                (key.chunk_index, cert)
            })
    }

    // ---- cached state hash ----

    /// The cached canonical state hash. `[0; 32]` before the first sync
    /// finalizes.
    pub fn cached_state_hash(&self) -> [u8; 32] {
        self.state_hash.get().0
    }

    /// Stores a freshly-computed state hash in its cell.
    pub fn cache_state_hash(&mut self, hash: [u8; 32]) {
        self.state_hash.set(StateHash(hash));
    }

    // ---- redirect rules ----

    /// The redirect-rule list in match order. Returns the `StableCell`'s cached
    /// value by reference (no clone); serving scans it on every request.
    pub fn redirect_rules(&self) -> &[RedirectRule] {
        &self.redirect_rules.get().0
    }

    /// Replaces the whole redirect-rule list. Certified entries are rebuilt by
    /// the caller (`State::on_redirect_rules_change`).
    pub fn set_redirect_rules(&mut self, rules: Vec<RedirectRule>) {
        self.redirect_rules.set(RedirectRules(rules));
    }

    // ---- access-protection settings ----

    /// The configured login-page path when the gate is on, else `None`.
    pub fn protection_login_page(&self) -> Option<String> {
        self.protection.get().login_page.clone()
    }

    /// Whether access protection is enabled (the gate is on).
    pub fn protection_enabled(&self) -> bool {
        self.protection.get().login_page.is_some()
    }

    /// Sets the login page (`Some` ⇒ gate on, `None` ⇒ public). A single small
    /// cell write; certification is the caller's responsibility.
    pub fn set_protection_login_page(&mut self, login_page: Option<String>) {
        self.protection.set(ProtectionSettings { login_page });
    }

    // ---- access tokens (management store; the hot-path index is heap) ----

    /// Records a token under its unique `label`.
    pub fn insert_token(&mut self, label: String, meta: TokenMeta) {
        self.tokens.insert(label, meta);
    }

    /// Removes and returns the token with `label`, if present.
    pub fn remove_token(&mut self, label: &str) -> Option<TokenMeta> {
        self.tokens.remove(&label.to_string())
    }

    /// Live tokens as `(label, TokenMeta)`. Backs list/sweep/rebuild/reassert.
    pub fn iter_tokens(&self) -> impl Iterator<Item = (String, TokenMeta)> + '_ {
        self.tokens.iter().map(|e| e.into_pair())
    }

    /// Drops every token. The certified redeem responses are cleared by the
    /// caller (they live under the login-page subtree).
    pub fn clear_tokens(&mut self) {
        let labels: Vec<String> = self.tokens.keys().collect();
        for label in labels {
            self.tokens.remove(&label);
        }
    }
}
