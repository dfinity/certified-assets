//! The certified-assets state machine: the orchestrator that ties the durable
//! store to the certification layer and exposes the canister's behavior.
//!
//! [`State`] itself holds no stable structures and no certified tree directly. It
//! composes two owned pieces plus the small transient/heap bits that don't belong
//! to either:
//! - [`crate::store::Store`] — all durable state in stable memory (settings,
//!   per-asset metadata, content chunks, tokens). The sole owner of the
//!   `ic-stable-structures` handles and the memory layout.
//! - [`crate::certifier::Certifier`] — the derived certified-response tree, the
//!   per-rule certified entries, the env cookie, and the policy that maintains
//!   them so the certified leaf always matches the served response.
//! - transient upload state (staged chunks, the active sync session) and the
//!   hot-path token gate index, which live on `State`.
//!
//! `State`'s methods are the orchestration: an asset mutation writes the `Store`
//! then asks the `Certifier` to re-certify; serving reads the `Store` for content
//! and the `Certifier` for witnesses. There is no serialize/deserialize step
//! across upgrades — `pre_upgrade` is gone and `post_upgrade` only rebuilds the
//! derived heap state from the store (see [`State::post_upgrade_rebuild`]).
//!
//! NB. This module does not depend on `ic_cdk` for environment access (time,
//! certificates): those are passed in as formal arguments so the state machine
//! is easy to test. It does use `ic-stable-structures`' `DefaultMemoryImpl`,
//! which transparently resolves to real stable memory on wasm and to an
//! in-process `VectorMemory` off-wasm (which is what lets the tests drive a full
//! upgrade roundtrip over a shared memory handle).

use crate::asset::{AssetMeta, EncodingMeta};
use crate::certification::AssetKey;
use crate::certifier::Certifier;
use crate::store::Store;
use crate::sync::{Chunk, SyncSession};
use candid::Principal;
use ic_certification::Hash;
use ic_stable_structures::DefaultMemoryImpl;
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;

use wire_types::{
    AssetDetails, AssetEncodingDetails, CreateAssetArguments, DeleteAssetArguments, RedirectRule,
    SessionId, SetAssetContentArguments, SetAssetHeadersArguments, UnsetAssetContentArguments,
};

/// Maximum number of items the canister returns from a single paginated query
/// (`get_asset_details`, `get_redirect_rules`). The caller follows the cursor
/// until it sees a short or empty page; it never needs to know this value.
pub const PAGE_SIZE: usize = 100;

pub struct State {
    /// Durable state: everything persisted in stable memory. All storage access
    /// funnels through this typed interface — `State` never touches a
    /// `StableCell`/`StableBTreeMap`/`MemoryId` directly. `pub(crate)` so the
    /// `impl State` blocks split across sibling files (`serving`, `access`,
    /// `sync`) can reach it; the store's own internals stay private.
    /// See [`Store`].
    pub(crate) store: Store,

    // ---- transient heap (lost on upgrade) ----
    /// Chunks staged by `upload_chunks` for the current sync, in upload order:
    /// the slot index is the chunk id (`ChunkId`). `SetAssetContent` `take()`s
    /// each slot as it consumes the bytes, leaving a `None` hole, so memory is
    /// freed incrementally without renumbering the surviving slots. Cleared on
    /// sync start/finish. The plugin reproduces these same indices locally, so
    /// they are never sent over the wire.
    pub(crate) chunks: Vec<Option<Chunk>>,
    /// The single in-progress sync, if any. At most one runs at a time.
    pub(crate) sync_session: Option<SyncSession>,

    // ---- derived heap (rebuilt in post_upgrade) ----
    /// The certified-response tree, the per-rule certified entries, the env
    /// cookie, and the policy that maintains them. All derived from `store`
    /// (plus the env snapshot) and rebuilt on upgrade. Serving reads it for
    /// witnesses; the mutation paths drive its (re)certification. `pub(crate)`
    /// for the same split-`impl` reason as `store`. See [`Certifier`].
    pub(crate) certifier: Certifier,
    /// Hot-path gate index: `SHA-256(value) -> expires_at`. The per-request gate
    /// hashes the presented cookie and looks it up here — a heap-map read, no
    /// stable access or `TokenMeta` deserialize. Pure derived state (every entry
    /// is reconstructable from the token store, which carries each token's
    /// `token_id` and expiry), so it lives in heap and is rebuilt on upgrade like
    /// the certified tree. Kept one-to-one with the token store; revocation/expiry
    /// are live.
    pub(crate) token_index: HashMap<[u8; 32], u64>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(DefaultMemoryImpl::default())
    }
}

impl State {
    /// Builds a `State` over the given stable memory. The durable [`Store`]
    /// transparently picks up existing data if the memory was already populated
    /// (e.g. after an upgrade), or starts empty over fresh memory; the heap
    /// fields start empty and are rebuilt from that durable state in
    /// `post_upgrade`.
    ///
    /// The explicit-memory constructor is what makes the upgrade-roundtrip unit
    /// test possible: off-wasm `DefaultMemoryImpl` is a cheaply-cloneable handle
    /// to a shared byte buffer, so a test can build two `State`s over the same
    /// memory to simulate an upgrade.
    pub fn new(memory: DefaultMemoryImpl) -> Self {
        Self {
            store: Store::new(memory),
            chunks: Vec::new(),
            sync_session: None,
            certifier: Certifier::default(),
            token_index: HashMap::new(),
        }
    }

    // ---- settings accessors ----

    /// Allocates a fresh, never-reused sync session id.
    pub fn alloc_session_id(&mut self) -> SessionId {
        self.store.alloc_session_id()
    }

    /// Whether an asset exists at `key`.
    pub fn contains_asset(&self, key: &AssetKey) -> bool {
        self.store.contains_asset(key)
    }

    /// Whether the asset at `key` exists and stores any encoding as more than one
    /// chunk. A 4xx custom-error-page rule can only serve a single-chunk target
    /// (see the alias-rule certification in [`Certifier`]), so the sync op guard
    /// rejects 4xx rules whose target is already multi-chunk.
    pub fn target_is_multichunk(&self, key: &str) -> bool {
        self.store
            .get_asset(&key.to_string())
            .is_some_and(|meta| meta.encodings.values().any(|e| e.num_chunks > 1))
    }

    pub fn authorize(&mut self, principal: Principal) {
        self.store.authorize(principal);
    }

    pub fn deauthorize(&mut self, principal: &Principal) {
        self.store.deauthorize(principal);
    }

    pub fn list_authorized(&self) -> Vec<Principal> {
        self.store.list_authorized()
    }

    pub fn is_authorized(&self, principal: &Principal) -> bool {
        self.store.is_authorized(principal)
    }

    pub fn root_hash(&self) -> Hash {
        self.certifier.root_hash()
    }

    // ---- asset mutations ----

    pub fn create_asset(&mut self, arg: CreateAssetArguments) -> Result<(), String> {
        if self.store.contains_asset(&arg.key) {
            return Err("asset already exists".to_string());
        }

        self.store.put_asset(
            arg.key,
            AssetMeta {
                content_type: arg.content_type,
                headers: arg.headers,
                encodings: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Test/helper entry point that collects the staged chunks and delegates to
    /// [`Self::complete_set_asset_content`]. The live sync path collects chunks
    /// in `execute_operations` and calls that method directly.
    #[cfg(test)]
    pub fn set_asset_content(&mut self, arg: SetAssetContentArguments) -> Result<(), String> {
        if arg.chunk_ids.is_empty() {
            return Err("encoding must have at least one chunk".to_string());
        }
        if !self.store.contains_asset(&arg.key) {
            return Err("asset not found".to_string());
        }

        let mut content_chunks = vec![];
        for &chunk_id in arg.chunk_ids.iter() {
            let chunk = self
                .chunks
                .get_mut(chunk_id as usize)
                .and_then(Option::take)
                .expect("chunk not found");
            content_chunks.push(chunk);
        }

        self.complete_set_asset_content(arg, content_chunks)
    }

    /// Writes an encoding's content into the chunk store and re-certifies the
    /// asset. Replacing an existing encoding frees the old content group first.
    ///
    /// The hashes in `arg` (`sha256` for the whole encoding, `chunk_sha256` per
    /// chunk) are **trusted, not recomputed** — see [`SetAssetContentArguments`]
    /// for why that's safe. The canister therefore does no content hashing on the
    /// commit path; it only validates the hashes' shape before storing them.
    pub fn complete_set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
        content_chunks: Vec<ByteBuf>,
    ) -> Result<(), String> {
        let sha256: [u8; 32] = arg
            .sha256
            .as_ref()
            .try_into()
            .map_err(|_| "invalid SHA-256".to_string())?;

        let num_chunks = content_chunks.len() as u32;
        let multi_chunk = num_chunks > 1;

        // Per-chunk cert data (length + hash) is only needed to serve/certify 206
        // ranges, which only happen for multi-chunk encodings — so single-chunk
        // assets (the common case) skip the `chunk_certs` write and reuse the
        // whole-encoding `sha256`. For multi-chunk assets we trust the client's
        // per-chunk hashes; parse them up front so a malformed or wrong-length
        // list fails before any state mutation.
        let chunk_hashes: Vec<[u8; 32]> = if multi_chunk {
            if arg.chunk_sha256.len() != content_chunks.len() {
                return Err("chunk_sha256 length must match chunk_ids".to_string());
            }
            arg.chunk_sha256
                .iter()
                .map(|h| {
                    h.as_ref()
                        .try_into()
                        .map_err(|_| "invalid chunk SHA-256".to_string())
                })
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };

        let mut meta = self
            .store
            .get_asset(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        // Free the chunks of any encoding we're replacing.
        if let Some(old) = meta.encodings.get(&arg.encoding) {
            self.store.delete_content_group(old.content_id);
        }

        // Write the chunks (and, for multi-chunk encodings, their per-chunk cert
        // data) under a fresh content-group id. `chunk_hashes` is empty for
        // single-chunk encodings, so the store skips the `chunk_certs` write.
        let (content_id, content_len) = self.store.store_content(&content_chunks, &chunk_hashes);

        meta.encodings.insert(
            arg.encoding,
            EncodingMeta {
                content_id,
                num_chunks,
                sha256,
                content_len,
            },
        );
        self.certifier.recertify_asset(&self.store, &arg.key, &meta);
        self.store.put_asset(arg.key, meta);

        Ok(())
    }

    pub fn unset_asset_content(&mut self, arg: UnsetAssetContentArguments) -> Result<(), String> {
        let mut meta = self
            .store
            .get_asset(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        if let Some(old) = meta.encodings.remove(&arg.encoding) {
            self.store.delete_content_group(old.content_id);
            self.certifier.recertify_asset(&self.store, &arg.key, &meta);
            self.store.put_asset(arg.key, meta);
        }

        Ok(())
    }

    pub fn delete_asset(&mut self, arg: DeleteAssetArguments) {
        if let Some(meta) = self.store.remove_asset(&arg.key) {
            self.certifier.remove_responses_for_path(&arg.key);
            for enc in meta.encodings.values() {
                self.store.delete_content_group(enc.content_id);
            }
        }
    }

    pub fn set_asset_headers(&mut self, arg: SetAssetHeadersArguments) -> Result<(), String> {
        let mut meta = self
            .store
            .get_asset(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        meta.headers = arg.headers;
        self.certifier.recertify_asset(&self.store, &arg.key, &meta);
        self.store.put_asset(arg.key, meta);

        Ok(())
    }

    // ---- access protection ----

    /// The configured login-page path when the gate is on, else `None`. Reads
    /// the in-memory `StableCell`, so it is cheap enough to call per request.
    pub fn protection_login_page(&self) -> Option<String> {
        self.store.protection_login_page()
    }

    // ---- queries ----

    /// Serves the `get_asset_details` endpoint: one page of assets ordered by
    /// key. `start_after` is exclusive — pass the last key of the previous page
    /// to get the next one, or `None` to start at the beginning. At most
    /// `PAGE_SIZE` assets are returned; an empty result means there is nothing
    /// after `start_after`.
    pub fn get_asset_details(&self, start_after: Option<AssetKey>) -> Vec<AssetDetails> {
        self.store
            .assets_from(start_after.as_ref())
            .take(PAGE_SIZE)
            .map(|(key, meta)| {
                let mut encodings: Vec<_> = meta
                    .encodings
                    .iter()
                    .map(|(&encoding, enc)| AssetEncodingDetails {
                        encoding,
                        sha256: ByteBuf::from(enc.sha256),
                    })
                    .collect();
                encodings.sort_by_key(|l| l.encoding);

                AssetDetails {
                    key,
                    content_type: meta.content_type,
                    encodings,
                    headers: meta.headers,
                }
            })
            .collect()
    }

    /// Serves the `get_redirect_rules` endpoint: one page of rules in match
    /// order. Rules live in a `Vec` whose order is semantic (first match wins)
    /// and where no element has a unique key, so the cursor is a positional
    /// `start_index`. `start_index` is the number of rules already seen; at most
    /// `PAGE_SIZE` rules are returned, and an empty result means there is nothing
    /// at or after `start_index`.
    pub fn get_redirect_rules(&self, start_index: u64) -> Vec<RedirectRule> {
        let start = start_index as usize;
        self.store
            .redirect_rules()
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take(PAGE_SIZE)
            .cloned()
            .collect()
    }

    // ---- state hash ----

    /// The cached canonical state hash (see the `state-hash` crate). `[0; 32]`
    /// before the first sync finalizes. Read by the public `state_hash` endpoint.
    pub fn cached_state_hash(&self) -> [u8; 32] {
        self.store.cached_state_hash()
    }

    /// Number of assets the staged hash will fold in — the `asset_count` written
    /// into the digest header (see `state_hash::StateHasher::begin`).
    pub(crate) fn state_hash_asset_count(&self) -> u64 {
        self.store.asset_count()
    }

    /// The next asset (in ascending key order) strictly after `resume_after`,
    /// shaped as a `state_hash::ManifestAsset` ready to fold into the digest, and
    /// returning its key so the caller can resume after it. `None` once the
    /// keyspace is exhausted. Folding one asset per step keeps a many-asset state
    /// within the per-message instruction limit.
    pub(crate) fn next_manifest_asset(
        &self,
        resume_after: &Option<AssetKey>,
    ) -> Option<(AssetKey, state_hash::ManifestAsset)> {
        let (key, meta) = self.store.assets_from(resume_after.as_ref()).next()?;
        let asset = self.manifest_asset(&key, &meta);
        Some((key, asset))
    }

    /// Builds the manifest view of one stored asset. Reads the per-encoding
    /// `EncodingMeta` and, for multi-chunk encodings only, scans the per-chunk
    /// `ChunkCert`s in index order — exactly the gateway-enforced hashes the
    /// digest folds in (single-chunk encodings are covered by the whole `sha256`).
    fn manifest_asset(&self, key: &str, meta: &AssetMeta) -> state_hash::ManifestAsset {
        let encodings = meta
            .encodings
            .iter()
            .map(|(&encoding, enc)| {
                if enc.num_chunks > 1 {
                    let chunks = self
                        .store
                        .chunk_certs_of(enc.content_id)
                        .map(|(_, cert)| state_hash::ManifestChunk {
                            len: cert.len,
                            sha256: cert.sha256,
                        })
                        .collect();
                    state_hash::ManifestEncoding {
                        encoding,
                        sha256: enc.sha256,
                        content_len: enc.content_len,
                        num_chunks: enc.num_chunks,
                        chunks,
                    }
                } else {
                    state_hash::ManifestEncoding::single_chunk(
                        encoding,
                        enc.sha256,
                        enc.content_len,
                    )
                }
            })
            .collect();

        state_hash::ManifestAsset {
            key: key.to_string(),
            content_type: meta.content_type.clone(),
            headers: meta.headers.clone(),
            encodings,
        }
    }

    /// Folds the stored redirect rules (in match order) into `hasher` — the final
    /// step of the staged digest, after every asset.
    pub(crate) fn fold_redirect_rules(&self, hasher: &mut state_hash::StateHasher) {
        hasher.write_redirect_rules(self.store.redirect_rules());
    }

    /// Stores a freshly-computed state hash in its cell.
    pub(crate) fn cache_state_hash(&mut self, hash: [u8; 32]) {
        self.store.cache_state_hash(hash);
    }

    /// Recomputes the canonical state hash in one pass and caches it. Off-staging
    /// path used by tests; production finalizes via the staged
    /// `ExecuteOperationsProgress::HashingState` machine.
    #[cfg(test)]
    pub(crate) fn recompute_state_hash(&mut self) -> [u8; 32] {
        let mut hasher = state_hash::StateHasher::begin(self.state_hash_asset_count());
        let mut resume_after: Option<AssetKey> = None;
        while let Some((key, asset)) = self.next_manifest_asset(&resume_after) {
            hasher.write_asset(&asset);
            resume_after = Some(key);
        }
        self.fold_redirect_rules(&mut hasher);
        let hash = hasher.finish();
        self.cache_state_hash(hash);
        hash
    }

    // ---- redirect rules ----

    /// Rebuilds the certified-tree entries for the redirect rules and the
    /// built-in 404 fallback (and, under protection, the rule/root unauthenticated
    /// siblings). Called whenever the rule list changes (in `execute_operations`),
    /// after asset ops that could clobber a rule's tree slot, and on upgrade.
    /// Delegates to the [`Certifier`]; the caller refreshes `certified_data`
    /// afterwards.
    pub fn on_redirect_rules_change(&mut self) {
        self.certifier.on_redirect_rules_change(&self.store);
    }

    /// Replaces the redirect rules and rebuilds their certified entries.
    pub fn set_redirect_rules(&mut self, rules: Vec<RedirectRule>) {
        self.store.set_redirect_rules(rules);
        self.on_redirect_rules_change();
    }

    // ---- environment cookie ----

    /// Stores the rendered env cookie from a freshly captured snapshot **without**
    /// re-certifying. Used by `post_upgrade` *before* `post_upgrade_rebuild`, so
    /// the rebuild — which re-certifies every asset from scratch — picks the
    /// cookie up through `effective_headers`.
    pub fn store_env(&mut self, env: &crate::runtime::CanisterEnv) {
        self.certifier.set_env_cookie(env.render_cookie());
    }

    /// Captures the env at the **start of a sync**, so the operations that follow
    /// certify their assets against the current cookie (no end-of-sync re-cert
    /// pass). If the rendered cookie is unchanged — the common case, since env
    /// vars rarely change between syncs — this is a no-op: existing certs are
    /// already correct and the sync's own ops will re-use the same cookie. Only
    /// when it *changed* must we re-certify here (via [`Self::refresh_env`]):
    /// otherwise HTML assets the sync doesn't touch would keep an old-cookie
    /// certificate while `effective_headers` serves the new cookie, and the
    /// gateway would reject them. Caller publishes `certified_data` afterwards.
    pub fn capture_env_at_sync_start(&mut self, env: &crate::runtime::CanisterEnv) {
        if self.certifier.env_cookie() != Some(env.render_cookie().as_str()) {
            self.refresh_env(env);
        }
    }

    /// Captures a new env snapshot on an already-running canister and re-certifies
    /// everything it affects: every `text/html` asset (its effective header set
    /// changed) and the redirect-rule entries (a 200-rewrite to an HTML asset
    /// borrows the cookie). Non-HTML assets are untouched. Caller must refresh
    /// `certified_data` afterwards. Mirrors `set_redirect_rules` →
    /// `on_redirect_rules_change`.
    pub fn refresh_env(&mut self, env: &crate::runtime::CanisterEnv) {
        self.store_env(env);
        let keys = self.store.asset_keys();
        for key in keys {
            if let Some(meta) = self.store.get_asset(&key) {
                if crate::asset::is_html_content_type(&meta.content_type) {
                    self.certifier.recertify_asset(&self.store, &key, &meta);
                }
            }
        }
        // Rebuild rule entries: a 200-rewrite (e.g. the `/` SPA alias) to an HTML
        // target must pick up the cookie via its now-changed certified response.
        self.on_redirect_rules_change();
    }

    // ---- upgrade ----

    /// Rebuilds all derived heap state from the durable stable-memory state
    /// after an upgrade: the certified-response tree for every asset, the
    /// redirect-rule certified entries, the built-in 404 fallback (the last two
    /// via `on_redirect_rules_change`), and the token gate index. The caller
    /// publishes `certified_data` afterwards.
    pub fn post_upgrade_rebuild(&mut self) {
        self.certifier.recertify_all_assets(&self.store);
        self.on_redirect_rules_change();
        self.rebuild_token_index();
        // If protection is on but the login page asset isn't present, the asset
        // loop above didn't re-assert its redeem responses — do it explicitly so
        // the redeem endpoint survives the upgrade even in the degraded state.
        if let Some(login_page) = self.protection_login_page() {
            if !self.store.contains_asset(&login_page) {
                self.certifier
                    .reassert_login_responses(&self.store, &login_page);
            }
        }
    }

    /// Rebuilds the in-heap gate index (`token_id → expires_at`) from the durable
    /// `tokens` store after an upgrade. Lossless: every entry is derivable from a
    /// `TokenMeta`. Cheap — the token set is small.
    fn rebuild_token_index(&mut self) {
        self.token_index = self
            .store
            .iter_tokens()
            .map(|(_, meta)| (meta.token_id, meta.expires_at))
            .collect();
    }
}
