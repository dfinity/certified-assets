//! This module contains a pure implementation of the certified assets state machine.
//!
//! Durable state (settings, per-asset metadata, content chunks) lives in stable
//! memory via `ic-stable-structures`; derived state (the certified-response
//! tree, per-rule certified entries) and transient upload state (staged chunks,
//! the active sync session) live in the heap. There is no serialize/deserialize
//! step across upgrades — `pre_upgrade` is gone and `post_upgrade` only rebuilds
//! the derived heap state (see [`State::post_upgrade_rebuild`]).
//!
//! NB. This module does not depend on `ic_cdk` for environment access (time,
//! certificates): those are passed in as formal arguments so the state machine
//! is easy to test. It does use `ic-stable-structures`' `DefaultMemoryImpl`,
//! which transparently resolves to real stable memory on wasm and to an
//! in-process `VectorMemory` off-wasm (which is what lets the tests drive a full
//! upgrade roundtrip over a shared memory handle).

use crate::asset::{
    certificate_expression_for, headers_for, range_certificate_expression_for, range_headers_for,
    range_response_hash, response_hashes_for,
};
use crate::blob_store::BlobStore;
use crate::certification::{
    build_ic_certificate_expression_header, response_hash, AssetKey, AssetPath,
    CertificateExpression, CertifiedResponses, HashTreePath, NestedTreeKey, RequestHash,
    ResponseHash,
};
use crate::http::{HeaderField, HttpRequest, HttpResponse};
use crate::protection::{ProtectionResponse, ProtectionStatus, TokenInfo};
use crate::stable_store::{
    AssetMeta, AuthorizedSet, ChunkCert, ContentChunkKey, EncodingMeta, ProtectionSettings,
    RedirectRules, StateHash, TokenMeta,
};
use crate::sync::{Chunk, SyncSession};
use crate::url::url_decode;
use candid::Principal;
use ic_certification::{AsHashTree, Hash};
use ic_representation_independent_hash::Value;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;

use wire_types::{
    AssetDetails, AssetEncodingDetails, CreateAssetArguments, DeleteAssetArguments, Encoding,
    RedirectRule, RulePattern, SessionId, SetAssetContentArguments, SetAssetHeadersArguments,
    UnsetAssetContentArguments,
};

/// Maximum number of items the canister returns from a single paginated query
/// (`get_asset_details`, `get_redirect_rules`). The caller follows the cursor
/// until it sees a short or empty page; it never needs to know this value.
pub const PAGE_SIZE: usize = 100;

/// Parse an `If-None-Match` request header into the content hashes the client
/// already holds. Our `ETag` is `"<hex sha256>"` (see [`crate::asset::etag_value`]),
/// so each token is unquoted and hex-decoded back to a 32-byte hash; the weak
/// prefix `W/` is stripped first (RFC 7232 §3.2 mandates the weak comparison for
/// `If-None-Match`). Tokens we can't read as a 32-byte hash — `*`, or any
/// validator we didn't mint — simply don't match, so the client gets a normal
/// 200.
fn parse_if_none_match(value: &str) -> Vec<Hash> {
    value
        .split(',')
        .filter_map(|token| {
            let token = token.trim();
            let token = token.strip_prefix("W/").unwrap_or(token).trim();
            let token = token.strip_prefix('"')?.strip_suffix('"')?;
            let bytes = hex::decode(token).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect()
}

/// Phase 0 spike: parse the *start* byte of a single `Range: bytes=<start>-[end]`
/// header. The end is ignored (we serve the containing chunk). Multi-range
/// (comma) and suffix (`bytes=-N`) forms return `None` → the request is served
/// as a normal full response.
fn parse_range_start(value: &str) -> Option<usize> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, _end) = spec.split_once('-')?;
    start.trim().parse::<usize>().ok()
}

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
/// hot-path gate index is *derived* from this (in heap; see `token_index`).
const TOKENS_MEMORY: MemoryId = MemoryId::new(10);

pub struct State {
    // ---- durable (stable memory) ----
    /// Principals authorized to sync (controllers are always allowed, unstored).
    authorized: StableCell<AuthorizedSet, Mem>,
    /// Ordered redirect-rule list. Its own cell so a counter bump doesn't
    /// reserialize it (it can be large; the counters are bumped frequently).
    redirect_rules: StableCell<RedirectRules, Mem>,
    /// Monotonic, never-reused sync session id allocator.
    next_session_id: StableCell<u64, Mem>,
    /// Monotonic, never-reused chunk-group id allocator.
    next_content_id: StableCell<u64, Mem>,
    /// Per-asset metadata, ordered by key so `get_asset_details` can page with a
    /// key cursor (a `range` seek) instead of sorting the keyspace per query.
    metadata: StableBTreeMap<AssetKey, AssetMeta, Mem>,
    /// Raw content bytes, one chunk per `(content_id, index)`, stored contiguously
    /// in a stable region (not inline in a BTree) so reads/writes are a single
    /// `stable64_read`/`write` instead of an overflow-page walk. See
    /// [`crate::blob_store`].
    content: BlobStore<Mem>,
    /// Per-chunk certification data (length + SHA-256), keyed by the same
    /// `(content_id, chunk_index)` as the content blob. Lets the 206 certify path
    /// stay content-free (no re-hash in `post_upgrade`) and the serve path avoid
    /// reading every chunk to locate a range. Freed alongside its content group.
    chunk_certs: StableBTreeMap<ContentChunkKey, ChunkCert, Mem>,
    /// Cached canonical state hash, recomputed at the end of every final sync and
    /// returned verbatim by the public `state_hash` endpoint. `[0; 32]` until the
    /// first sync finalizes. See [`State::cached_state_hash`].
    state_hash: StableCell<StateHash, Mem>,
    /// Access-protection settings. `login_page == None` (the default) ⇒ a fully
    /// public app: the gate, the no-store override, and the certified
    /// unauthenticated siblings are all absent. See the access-protection design.
    protection: StableCell<ProtectionSettings, Mem>,
    /// Live access tokens keyed by their unique **label** — the management view
    /// (issue/revoke/list, all O(log n) by label). Empty when protection is off.
    tokens: StableBTreeMap<String, TokenMeta, Mem>,

    // ---- transient heap (lost on upgrade) ----
    /// Chunks staged by `upload_chunks` for the current sync, in upload order:
    /// the slot index is the chunk id (`ChunkId`). `SetAssetContent` `take()`s
    /// each slot as it consumes the bytes, leaving a `None` hole, so memory is
    /// freed incrementally without renumbering the surviving slots. Cleared on
    /// sync start/finish. The plugin reproduces these same indices locally, so
    /// they are never sent over the wire.
    pub chunks: Vec<Option<Chunk>>,
    /// The single in-progress sync, if any. At most one runs at a time.
    pub sync_session: Option<SyncSession>,

    // ---- derived heap (rebuilt in post_upgrade) ----
    pub asset_hashes: CertifiedResponses,
    /// Per-rule certified-tree entries, parallel to `settings.redirect_rules`. A
    /// `None` slot means the rule has no certified entry — either because an
    /// asset shadows an exact rule at the same path, or because an alias rule
    /// (200/4xx) points at a target asset that doesn't exist yet.
    pub rule_certified_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>>,
    /// The fully rendered `Set-Cookie: ic_env=…` value layered onto every
    /// `text/html` response, or `None` before any env snapshot has been
    /// captured. Owned by the canister (never stored in `meta.headers`) and
    /// recomputed on capture; rebuilt from the live system API in `post_upgrade`
    /// (the env vars themselves survive as canister settings), exactly like
    /// `asset_hashes`. See [`State::effective_headers`].
    pub env_cookie: Option<String>,
    /// Hot-path gate index: `SHA-256(value) -> expires_at`. The per-request gate
    /// hashes the presented cookie and looks it up here — a heap-map read, no
    /// stable access or `TokenMeta` deserialize. Pure derived state (every entry
    /// is reconstructable from `tokens`, which carries each token's `token_id` and
    /// expiry), so it lives in heap and is rebuilt on upgrade like `asset_hashes`.
    /// Kept one-to-one with `tokens`; revocation/expiry are live.
    token_index: HashMap<[u8; 32], u64>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(DefaultMemoryImpl::default())
    }
}

impl State {
    /// Builds a `State` over the given stable memory. `StableCell`/`StableBTreeMap`
    /// init transparently picks up existing data if the memory was already
    /// populated (e.g. after an upgrade), or starts empty over fresh memory.
    ///
    /// The explicit-memory constructor is what makes the upgrade-roundtrip unit
    /// test possible: off-wasm `DefaultMemoryImpl` is a cheaply-cloneable handle
    /// to a shared byte buffer, so a test can build two `State`s over the same
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
            chunks: Vec::new(),
            sync_session: None,
            asset_hashes: CertifiedResponses::default(),
            rule_certified_entries: Vec::new(),
            env_cookie: None,
            token_index: HashMap::new(),
        }
    }

    // ---- settings accessors ----

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

    /// Whether an asset exists at `key`.
    pub fn contains_asset(&self, key: &AssetKey) -> bool {
        self.metadata.contains_key(key)
    }

    /// Whether the asset at `key` exists and stores any encoding as more than one
    /// chunk. A 4xx custom-error-page rule can only serve a single-chunk target
    /// (see [`State::build_alias_rule_entry`]), so the sync op guard rejects 4xx
    /// rules whose target is already multi-chunk.
    pub fn target_is_multichunk(&self, key: &str) -> bool {
        self.metadata
            .get(&key.to_string())
            .is_some_and(|meta| meta.encodings.values().any(|e| e.num_chunks > 1))
    }

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

    pub fn root_hash(&self) -> Hash {
        self.asset_hashes.root_hash()
    }

    // ---- chunk store helpers ----

    /// Fetches one chunk's bytes from the content store as `ByteBuf`. A missing
    /// chunk yields empty bytes (callers only request indices the metadata
    /// claims exist).
    fn chunk_bytes(&self, content_id: u64, chunk_index: usize) -> ByteBuf {
        self.content
            .get(content_id, chunk_index as u32)
            .map(ByteBuf::from)
            .unwrap_or_default()
    }

    /// Frees every chunk belonging to a content group, including its per-chunk
    /// certification entries.
    fn delete_content(&mut self, content_id: u64) {
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

    // ---- asset mutations ----

    pub fn create_asset(&mut self, arg: CreateAssetArguments) -> Result<(), String> {
        if self.metadata.contains_key(&arg.key) {
            return Err("asset already exists".to_string());
        }

        self.metadata.insert(
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
        if !self.metadata.contains_key(&arg.key) {
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
            .metadata
            .get(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        // Free the chunks of any encoding we're replacing.
        if let Some(old) = meta.encodings.get(&arg.encoding) {
            self.delete_content(old.content_id);
        }

        let content_id = self.alloc_content_id();
        let mut content_len = 0u64;
        for (index, chunk) in content_chunks.iter().enumerate() {
            self.content.insert(content_id, index as u32, chunk);
            if multi_chunk {
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

        meta.encodings.insert(
            arg.encoding,
            EncodingMeta {
                content_id,
                num_chunks,
                sha256,
                content_len,
            },
        );
        self.recertify_asset(&arg.key, &meta);
        self.metadata.insert(arg.key, meta);

        Ok(())
    }

    pub fn unset_asset_content(&mut self, arg: UnsetAssetContentArguments) -> Result<(), String> {
        let mut meta = self
            .metadata
            .get(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        if let Some(old) = meta.encodings.remove(&arg.encoding) {
            self.delete_content(old.content_id);
            self.recertify_asset(&arg.key, &meta);
            self.metadata.insert(arg.key, meta);
        }

        Ok(())
    }

    pub fn delete_asset(&mut self, arg: DeleteAssetArguments) {
        if let Some(meta) = self.metadata.remove(&arg.key) {
            self.asset_hashes.remove_responses_for_path(&arg.key);
            for enc in meta.encodings.values() {
                self.delete_content(enc.content_id);
            }
        }
    }

    pub fn set_asset_headers(&mut self, arg: SetAssetHeadersArguments) -> Result<(), String> {
        let mut meta = self
            .metadata
            .get(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        meta.headers = arg.headers;
        self.recertify_asset(&arg.key, &meta);
        self.metadata.insert(arg.key, meta);

        Ok(())
    }

    /// The header list a response actually certifies and serves: the asset's own
    /// `meta.headers`, plus the canister-owned env cookie on `text/html` assets
    /// when a snapshot exists. The cookie is *never* stored in `meta.headers`
    /// (`_headers` remains the sole owner of that field); it is layered on here
    /// at the single point every cert/serve site funnels through, guaranteeing
    /// the certified set and the served set agree. A user's own `_headers`
    /// `Set-Cookie` coexists as a separate entry (per-asset headers are a `Vec`,
    /// not a name-keyed map, so neither overwrites the other).
    fn effective_headers(&self, meta: &AssetMeta) -> Vec<(String, String)> {
        let mut headers = meta.headers.clone();
        if let Some(cookie) = &self.env_cookie {
            if crate::asset::is_html_content_type(&meta.content_type) {
                headers.push(("set-cookie".to_string(), cookie.clone()));
            }
        }
        // Under protection, force `Cache-Control: no-store` on every served
        // response. The boundary cache is cookie-blind (keys on path+range, no
        // `Vary`), so a cached `200` could be replayed to a no-token request
        // (asset leak) or a cached `307`/`401` to an authorized user. `no-store`
        // is certified like any other header, so an honest gateway can't strip
        // it. This overrides any user `_headers` cache-control while protected;
        // public apps (`protection == None`) are untouched.
        if self.protection_enabled() {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cache-control"));
            headers.push(("cache-control".to_string(), "no-store".to_string()));
        }
        headers
    }

    // ---- access protection ----

    /// The configured login-page path when the gate is on, else `None`. Reads
    /// the in-memory `StableCell`, so it is cheap enough to call per request.
    pub fn protection_login_page(&self) -> Option<String> {
        self.protection.get().login_page.clone()
    }

    /// Whether access protection is enabled (the gate is on).
    pub fn protection_enabled(&self) -> bool {
        self.protection.get().login_page.is_some()
    }

    /// Removes and recomputes every certified response for one asset from its
    /// metadata. Recompute is cheap: it reads only headers/content_type/sha256,
    /// never content bytes.
    fn recertify_asset(&mut self, key: &AssetKey, meta: &AssetMeta) {
        self.asset_hashes.remove_responses_for_path(key);
        if !meta.encodings.is_empty() {
            self.certify_asset_encodings(key, meta);
        }

        // Access protection: this path may also carry the gate's certified
        // unauthenticated sibling — or, for the login page itself, its redeem
        // responses (which share this subtree and were wiped above).
        if let Some(login_page) = self.protection_login_page() {
            if key.as_str() == login_page {
                self.reassert_login_responses(&login_page);
            } else {
                self.certify_unauth_sibling(key, meta, &login_page);
            }
        }
    }

    /// Certifies the 200/304 (single-chunk) or N×206 (multi-chunk) responses for
    /// every encoding of an asset. Split out of [`Self::recertify_asset`] so the
    /// access-protection tail there runs even for a content-less asset.
    fn certify_asset_encodings(&mut self, key: &AssetKey, meta: &AssetMeta) {
        let effective_headers = self.effective_headers(meta);
        let path = AssetPath::from(key.as_str());
        for (&encoding, enc) in &meta.encodings {
            let cert_expr = certificate_expression_for(&effective_headers, encoding, &enc.sha256);
            let response_hashes = response_hashes_for(
                &effective_headers,
                &meta.content_type,
                encoding,
                &cert_expr,
                &enc.sha256,
            );
            // Always certify the 304 (empty body). Certify the full 200 only for
            // single-chunk encodings — a multi-chunk asset is served as N×206 (the
            // gateway reassembles them into a 200), so a full 200 is never served
            // and certifying it would be dead weight in the tree.
            let hash_304 = path.hash_tree_path(
                &cert_expr,
                &RequestHash::default(),
                ResponseHash::from(&response_hashes[&304]),
            );
            self.asset_hashes.certify_response_precomputed(&hash_304);
            if enc.num_chunks == 1 {
                let hash_200 = path.hash_tree_path(
                    &cert_expr,
                    &RequestHash::default(),
                    ResponseHash::from(&response_hashes[&200]),
                );
                self.asset_hashes.certify_response_precomputed(&hash_200);
            } else {
                // Multi-chunk: certify one 206 per chunk (response-only).
                let (range_cert_expr, resp_hashes) = self.range_response_certs(
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    enc,
                );
                for resp_hash in resp_hashes {
                    let hash_path = path.hash_tree_path(
                        &range_cert_expr,
                        &RequestHash::default(),
                        ResponseHash::from(&resp_hash),
                    );
                    self.asset_hashes.certify_response_precomputed(&hash_path);
                }
            }
        }
    }

    /// Content-free per-chunk 206 certification data for a multi-chunk encoding:
    /// the shared range certificate expression plus one response hash per chunk,
    /// in chunk order. Derived from `chunk_certs` + `content_len`, so it never
    /// reads chunk bytes. Both the direct-asset path (`recertify_asset`) and the
    /// alias path (`build_alias_rule_entry`) use it, each placing the resulting
    /// leaves at its own tree location.
    fn range_response_certs(
        &self,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> (CertificateExpression, Vec<[u8; 32]>) {
        let range_cert_expr =
            range_certificate_expression_for(effective_headers, encoding, &enc.sha256);
        let total = enc.content_len;
        let chunk_infos: Vec<(u32, [u8; 32])> = self
            .chunk_certs
            .range(ContentChunkKey::range(enc.content_id))
            .map(|e| {
                let cc = e.into_pair().1;
                (cc.len, cc.sha256)
            })
            .collect();
        let mut resp_hashes = Vec::with_capacity(chunk_infos.len());
        let mut offset: u64 = 0;
        for (len, sha256) in chunk_infos {
            let len = len as u64;
            let content_range = format!("bytes {}-{}/{}", offset, offset + len - 1, total);
            resp_hashes.push(range_response_hash(
                effective_headers,
                content_type,
                encoding,
                &enc.sha256,
                &content_range,
                &sha256,
            ));
            offset += len;
        }
        (range_cert_expr, resp_hashes)
    }

    // ---- queries ----

    /// Serves the `get_asset_details` endpoint: one page of assets ordered by
    /// key. `start_after` is exclusive — pass the last key of the previous page
    /// to get the next one, or `None` to start at the beginning. At most
    /// `PAGE_SIZE` assets are returned; an empty result means there is nothing
    /// after `start_after`.
    pub fn get_asset_details(&self, start_after: Option<AssetKey>) -> Vec<AssetDetails> {
        use std::ops::Bound::{Excluded, Unbounded};
        let lower = match start_after {
            Some(key) => Excluded(key),
            None => Unbounded,
        };

        self.metadata
            .range((lower, Unbounded))
            .take(PAGE_SIZE)
            .map(|entry| {
                let (key, meta) = entry.into_pair();
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
        self.redirect_rules
            .get()
            .0
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
        self.state_hash.get().0
    }

    /// Number of assets the staged hash will fold in — the `asset_count` written
    /// into the digest header (see `state_hash::StateHasher::begin`).
    pub(crate) fn state_hash_asset_count(&self) -> u64 {
        self.metadata.len()
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
        use std::ops::Bound::{Excluded, Unbounded};
        let lower = match resume_after {
            Some(key) => Excluded(key.clone()),
            None => Unbounded,
        };
        let (key, meta) = self.metadata.range((lower, Unbounded)).next()?.into_pair();
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
                        .chunk_certs
                        .range(ContentChunkKey::range(enc.content_id))
                        .map(|entry| {
                            let (_key, cert) = entry.into_pair();
                            state_hash::ManifestChunk {
                                len: cert.len,
                                sha256: cert.sha256,
                            }
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
        hasher.write_redirect_rules(&self.redirect_rules.get().0);
    }

    /// Stores a freshly-computed state hash in its cell.
    pub(crate) fn cache_state_hash(&mut self, hash: [u8; 32]) {
        self.state_hash.set(StateHash(hash));
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

    // ---- HTTP serving ----

    fn build_http_response(
        &self,
        certificate: &[u8],
        path: &str,
        requested_encodings: Vec<Encoding>,
        etags: Vec<Hash>,
        range_start: Option<usize>,
    ) -> HttpResponse {
        // Asset at the requested path wins.
        if let Some(meta) = self.metadata.get(&path.to_string()) {
            let (cert_header, _) = self.asset_hashes.witness_to_header(path, certificate);
            if let Some(response) = self.build_asset_response(
                &meta,
                &requested_encodings,
                Some(&cert_header),
                &etags,
                None,
                range_start,
            ) {
                return response;
            }
        }

        // Scan redirect rules in declaration order; first match wins.
        let redirect_rules = self.redirect_rules.get();
        for (idx, rule) in redirect_rules.0.iter().enumerate() {
            if !crate::redirect::matches(rule, path) {
                continue;
            }
            let Some(entry) = self
                .rule_certified_entries
                .get(idx)
                .and_then(|e| e.as_ref())
            else {
                continue;
            };
            return self.build_redirect_rule_response(
                rule,
                entry,
                path,
                certificate,
                &requested_encodings,
                &etags,
                range_start,
            );
        }

        let (certificate_header, _) = self.asset_hashes.witness_to_header(path, certificate);
        HttpResponse::build_404(certificate_header)
    }

    /// Builds the 200/304 (or status-overridden) response for the best matching
    /// encoding of `meta`, or `None` if the asset has no encodings. Every
    /// encoding present in the metadata is certified, so encoding selection is
    /// just preference order.
    #[allow(clippy::too_many_arguments)]
    fn build_asset_response(
        &self,
        meta: &AssetMeta,
        requested_encodings: &[Encoding],
        certificate_header: Option<&HeaderField>,
        etags: &[Hash],
        status_override: Option<u16>,
        range_start: Option<usize>,
    ) -> Option<HttpResponse> {
        // A status-overridden response (a 4xx custom error page) is served as a
        // single inline body with that status — there is no way to deliver a
        // multi-chunk body under a non-200 status now that callback streaming is
        // gone and 206 reassembly always yields a 200 (see D6). So restrict those
        // to single-chunk encodings; the certify side does the same.
        let acceptable = |e: &Encoding| match status_override {
            Some(_) => meta.encodings.get(e).is_some_and(|enc| enc.num_chunks == 1),
            None => meta.encodings.contains_key(e),
        };
        // Honour the client's listed order first; if it expressed no acceptable
        // encoding, fall back to our preference order (identity-first).
        let encoding = requested_encodings
            .iter()
            .copied()
            .find(|e| acceptable(e))
            .or_else(|| {
                Encoding::PREFERENCE_ORDER
                    .into_iter()
                    .find(|e| acceptable(e))
            })?;
        let enc = meta.encodings.get(&encoding)?;
        Some(self.build_ok_http_response(
            meta,
            encoding,
            enc,
            certificate_header,
            etags,
            status_override,
            range_start,
        ))
    }

    /// Builds the response for one encoding.
    ///
    /// When `status_override` is `None` this serves the normal 200/304 path
    /// (etag-based not-modified). When it is `Some(s)` — used by redirect rules
    /// that serve a custom error page — the response always carries the body
    /// with status `s`, and the etag / 304 logic is skipped.
    #[allow(clippy::too_many_arguments)]
    fn build_ok_http_response(
        &self,
        meta: &AssetMeta,
        encoding: Encoding,
        enc: &EncodingMeta,
        certificate_header: Option<&HeaderField>,
        etags: &[Hash],
        status_override: Option<u16>,
        range_start: Option<usize>,
    ) -> HttpResponse {
        // Serve multi-chunk encodings as certified 206s. A plain GET (no Range)
        // returns chunk 0 — that is what drives the gateway's Flow B reassembly
        // into a full 200. A Range request returns the containing chunk (start
        // snapped down to the chunk boundary). Conditional (304) and
        // status-override (4xx error-page) responses keep their normal path; the
        // latter only ever reaches here with a single-chunk encoding.
        if status_override.is_none() && !etags.contains(&enc.sha256) && enc.num_chunks > 1 {
            let start = range_start.unwrap_or(0);
            if let Some(response) =
                self.build_range_response(meta, encoding, enc, start, certificate_header)
            {
                return response;
            }
        }

        let mut headers = headers_for(
            &self.effective_headers(meta),
            &meta.content_type,
            encoding,
            &enc.sha256,
        );
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }

        // Reaching here means a single-chunk body — multi-chunk 200s are served as
        // 206 above, and multi-chunk 4xx error pages are filtered out in
        // `build_asset_response` — so the whole body is chunk 0. The
        // canister-managed `etag` header is already in `headers` (and certified),
        // so both the 200 and the 304 carry it.
        let (status_code, body) = if let Some(status) = status_override {
            (status, self.chunk_bytes(enc.content_id, 0))
        } else if etags.contains(&enc.sha256) {
            // Conditional request matched: serve the certified 304 (empty body).
            (304, ByteBuf::new())
        } else {
            (200, self.chunk_bytes(enc.content_id, 0))
        };

        HttpResponse {
            status_code,
            headers,
            body,
            upgrade: None,
        }
    }

    /// Build a certified 206 for the chunk containing byte `start` (snapped down
    /// to the chunk boundary). Returns `None` (caller falls back to the normal 200
    /// path) when the encoding is empty or `start` is past the end.
    ///
    /// Lean: locates the target chunk by scanning `chunk_certs` (tiny fixed
    /// entries, early exit), then reads only that one chunk's bytes.
    fn build_range_response(
        &self,
        meta: &AssetMeta,
        encoding: Encoding,
        enc: &EncodingMeta,
        start: usize,
        certificate_header: Option<&HeaderField>,
    ) -> Option<HttpResponse> {
        let total = enc.content_len as usize;
        if total == 0 {
            return None;
        }
        // An out-of-range start (no byte to satisfy) is treated as "ignore the
        // Range": serve chunk 0, which the gateway reassembles into the full 200.
        // Returning `None` here would instead fall through to a plain 200 carrying
        // only chunk 0 — a truncated body for a multi-chunk asset.
        let start = if start >= total { 0 } else { start };
        // Find the chunk whose [offset, offset+len) contains `start`.
        let mut offset = 0usize;
        let mut target: Option<(u32, usize, usize)> = None; // (chunk_index, chunk_start, len)
        for entry in self
            .chunk_certs
            .range(ContentChunkKey::range(enc.content_id))
        {
            let (key, cc) = entry.into_pair();
            let len = cc.len as usize;
            if start < offset + len {
                target = Some((key.chunk_index, offset, len));
                break;
            }
            offset += len;
        }
        let (chunk_index, chunk_start, len) = target?;

        let chunk = self
            .content
            .get(enc.content_id, chunk_index)
            .unwrap_or_default();
        let content_range = format!("bytes {}-{}/{}", chunk_start, chunk_start + len - 1, total);
        let mut headers = range_headers_for(
            &self.effective_headers(meta),
            &meta.content_type,
            encoding,
            &enc.sha256,
            &content_range,
        );
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }
        Some(HttpResponse {
            status_code: 206,
            headers,
            body: ByteBuf::from(chunk),
            upgrade: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_redirect_rule_response(
        &self,
        rule: &RedirectRule,
        entry: &crate::redirect::CertifiedRuleEntry,
        path: &str,
        certificate: &[u8],
        requested_encodings: &[Encoding],
        etags: &[Hash],
        range_start: Option<usize>,
    ) -> HttpResponse {
        let cert_header =
            self.asset_hashes
                .witness_to_header_with_location(path, &entry.location, certificate);
        match &entry.kind {
            crate::redirect::CertifiedRuleEntryKind::Synthetic { expression } => {
                // Synthetic entries only cover 3xx redirects — empty body.
                let cert_expr_header =
                    crate::certification::build_ic_certificate_expression_header(expression);
                let mut headers = crate::redirect::certified_headers(rule);
                headers.push((cert_expr_header.0, cert_expr_header.1));
                headers.push(cert_header);

                HttpResponse {
                    status_code: rule.status,
                    headers,
                    body: ByteBuf::new(),
                    upgrade: None,
                }
            }
            crate::redirect::CertifiedRuleEntryKind::AliasOf { target_key, status } => {
                let Some(meta) = self.metadata.get(target_key) else {
                    return HttpResponse::build_404(cert_header);
                };
                let status_override = (*status != 200).then_some(*status);
                self.build_asset_response(
                    &meta,
                    requested_encodings,
                    Some(&cert_header),
                    etags,
                    status_override,
                    range_start,
                )
                .unwrap_or_else(|| HttpResponse::build_404(cert_header))
            }
        }
    }

    // ---- access-protection certify/serve helpers ----

    /// Certifies one [`ProtectionResponse`] as a response-only leaf at `location`
    /// (an asset `<$>`, a rule `<$>`/`<*>`, or the root `<*>`). Returns the leaf's
    /// `HashTreePath` so per-token redeem leaves can be stored for later removal.
    fn certify_protection_response(
        &mut self,
        location: &HashTreePath,
        resp: &ProtectionResponse,
    ) -> HashTreePath {
        let cert_expr = resp.cert_expr();
        let resp_hash = resp.response_hash();
        let tp = crate::redirect::alias_tree_path(location, cert_expr.expression_hash, resp_hash);
        self.asset_hashes.certify_response_precomputed(&tp);
        tp
    }

    /// Builds the served `HttpResponse` for a [`ProtectionResponse`], attaching the
    /// `IC-CertificateExpression` header and the `IC-Certificate` witness for
    /// `location`. The bytes match the certified leaf exactly (same constructor),
    /// so the gateway verifies it.
    fn serve_protection_response(
        &self,
        resp: &ProtectionResponse,
        request_path: &str,
        location: &HashTreePath,
        certificate: &[u8],
    ) -> HttpResponse {
        let cert_expr = resp.cert_expr();
        let cert_expr_header = build_ic_certificate_expression_header(&cert_expr);
        let cert_header =
            self.asset_hashes
                .witness_to_header_with_location(request_path, location, certificate);
        let mut headers = resp.headers.clone();
        headers.push(cert_expr_header);
        headers.push(cert_header);
        HttpResponse {
            status_code: resp.status,
            headers,
            body: ByteBuf::from(resp.body.clone()),
            upgrade: None,
        }
    }

    /// Certifies the unauthenticated sibling for a protected asset path: a
    /// `307 → <login_page>` for HTML (humans navigate to documents) or a `401`
    /// for anything else (a redirect would hand a subresource the wrong content
    /// type).
    fn certify_unauth_sibling(&mut self, key: &AssetKey, meta: &AssetMeta, login_page: &str) {
        let resp = if crate::asset::is_html_content_type(&meta.content_type) {
            ProtectionResponse::redirect_to_login(login_page)
        } else {
            ProtectionResponse::unauthorized()
        };
        let location = AssetPath::from(key.as_str()).asset_hash_path_root();
        self.certify_protection_response(&location, &resp);
    }

    /// (Re)certifies the login page's `POST` responses: the shared redeem-failure
    /// `401` plus each live token's `302 + Set-Cookie` redeem response. The `200`
    /// page comes from the sync at the same subtree, so this must run whenever
    /// that subtree is rebuilt (and on upgrade). Token redeem leaves are
    /// re-inserted from their stored paths — no plaintext needed.
    fn reassert_login_responses(&mut self, login_page: &str) {
        let location = AssetPath::from(login_page).asset_hash_path_root();
        self.certify_protection_response(&location, &ProtectionResponse::redeem_failure());
        let paths: Vec<Vec<NestedTreeKey>> = self
            .tokens
            .iter()
            .map(|e| e.into_pair().1.redeem_path)
            .collect();
        for path in paths {
            self.asset_hashes
                .certify_response_precomputed(&HashTreePath(path));
        }
    }

    /// Whether the request carries a currently-valid `certified_assets_access` cookie: some
    /// presented value hashes to a stored, unexpired token. Plain string parsing
    /// of the `Cookie` header, so `ic_env` and any other cookie are irrelevant.
    fn cookie_token_valid(&self, req: &HttpRequest, now: u64) -> bool {
        crate::protection::access_cookie_values(req)
            .into_iter()
            .any(|value| {
                self.token_index
                    .get(&crate::protection::token_id(&value))
                    .is_some_and(|&expires_at| expires_at > now)
            })
    }

    /// Serves the certified unauthenticated response for `path`, mirroring the
    /// resolution order of [`Self::build_http_response`] so the witness lands at
    /// the most-specific certified location: an asset's sibling, a matching
    /// rule's `307`, or the universal root `<*>` `307`.
    fn serve_unauthenticated(
        &self,
        path: &str,
        login_page: &str,
        certificate: &[u8],
    ) -> HttpResponse {
        // 1. Exact asset at this path → its 307/401 sibling.
        if let Some(meta) = self.metadata.get(&path.to_string()) {
            let resp = if crate::asset::is_html_content_type(&meta.content_type) {
                ProtectionResponse::redirect_to_login(login_page)
            } else {
                ProtectionResponse::unauthorized()
            };
            let location = AssetPath::from(path).asset_hash_path_root();
            return self.serve_protection_response(&resp, path, &location, certificate);
        }
        // 2. Matching redirect rule → a 307 at the rule's location instead of
        //    following the rule (which could leak content).
        let redirect_rules = self.redirect_rules.get();
        for (idx, rule) in redirect_rules.0.iter().enumerate() {
            if !crate::redirect::matches(rule, path) {
                continue;
            }
            if self
                .rule_certified_entries
                .get(idx)
                .and_then(|e| e.as_ref())
                .is_none()
            {
                continue;
            }
            let resp = ProtectionResponse::redirect_to_login(login_page);
            let location = crate::redirect::tree_location(rule);
            return self.serve_protection_response(&resp, path, &location, certificate);
        }
        // 3. No asset, no rule → the universal root `<*>` 307.
        let resp = ProtectionResponse::redirect_to_login(login_page);
        let location = HashTreePath::not_found_base_path();
        self.serve_protection_response(&resp, path, &location, certificate)
    }

    /// Handles `POST <login_page>` (a certified query — no upgrade). Reads the
    /// presented value from the form body and returns this token's certified
    /// `302 + Set-Cookie` on success, or the certified `401` re-prompt otherwise.
    fn serve_redeem(
        &self,
        req: &HttpRequest,
        login_page: &str,
        certificate: &[u8],
        now: u64,
    ) -> HttpResponse {
        let location = AssetPath::from(login_page).asset_hash_path_root();
        if let Some(value) = crate::protection::parse_form_token(req.body.as_ref()) {
            if self
                .token_index
                .get(&crate::protection::token_id(&value))
                .is_some_and(|&expires_at| expires_at > now)
            {
                let resp = ProtectionResponse::redeem_success(&value);
                return self.serve_protection_response(&resp, login_page, &location, certificate);
            }
        }
        let resp = ProtectionResponse::redeem_failure();
        self.serve_protection_response(&resp, login_page, &location, certificate)
    }

    /// Adds the protection layer's redirect-rule siblings after a rule rebuild:
    /// the universal root `<*>` `307 → login`, plus a `307` at every non-root rule
    /// location (whose exact entry would otherwise reject the root wildcard). The
    /// per-rule siblings are tracked on the rule entry so the next rebuild removes
    /// them; the root one is re-added each rebuild (cleared by
    /// `remove_fallback_responses`). Only called while protection is on.
    fn certify_rule_unauth_siblings(&mut self, login_page: &str) {
        let redirect = ProtectionResponse::redirect_to_login(login_page);
        let root = HashTreePath::not_found_base_path();
        self.certify_protection_response(&root, &redirect);
        for idx in 0..self.rule_certified_entries.len() {
            let Some(location) = self
                .rule_certified_entries
                .get(idx)
                .and_then(|e| e.as_ref())
                .map(|e| e.location.clone())
            else {
                continue;
            };
            if location.0 == root.0 {
                continue; // root <*> already covered by the universal sibling
            }
            let tp = self.certify_protection_response(&location, &redirect);
            if let Some(entry) = self.rule_certified_entries[idx].as_mut() {
                entry.tree_paths.push(tp);
            }
        }
    }

    // ---- access-protection state management (controller-driven) ----

    /// Re-certifies every asset from its metadata. Shared by the protection
    /// toggles and `post_upgrade_rebuild`.
    fn recertify_all_assets(&mut self) {
        let keys: Vec<AssetKey> = self.metadata.keys().collect();
        for key in keys {
            if let Some(meta) = self.metadata.get(&key) {
                self.recertify_asset(&key, &meta);
            }
        }
    }

    /// Removes every certified response under the login page's subtree (redeem
    /// `302`s, the `401`, and the `200` page if synced) and drops all tokens. A
    /// following recertify re-adds the `200` for a still-present asset.
    fn clear_tokens_and_login_responses(&mut self, login_page: &str) {
        // The whole login subtree (redeem 302s, the 401, the 200 page) goes in one
        // shot, so per-token cert removal isn't needed — just empty the store and
        // the (heap) gate index.
        self.asset_hashes.remove_responses_for_path(login_page);
        let labels: Vec<String> = self.tokens.keys().collect();
        for label in labels {
            self.tokens.remove(&label);
        }
        self.token_index.clear();
    }

    /// Turns the gate **on** with the given login page (controller-guarded at the
    /// endpoint). Enabling on a fresh canister before the first sync is the secure
    /// ordering — no window in which assets are world-readable. Idempotent if
    /// already enabled at the same page; re-pointing to a different page drops the
    /// old tokens (their redeem certs live under the old subtree). Caller
    /// publishes `certified_data` afterwards.
    pub fn enable_protection(&mut self, login_page: String) {
        let previous = self.protection_login_page();
        if previous.as_deref() == Some(login_page.as_str()) {
            return;
        }
        if let Some(old) = previous {
            self.clear_tokens_and_login_responses(&old);
        }
        self.protection.set(ProtectionSettings {
            login_page: Some(login_page.clone()),
        });
        self.recertify_all_assets();
        self.on_redirect_rules_change();
        // Enable-first: if the page isn't synced yet, the asset loop didn't touch
        // it, but the redeem endpoint must still work — assert its responses.
        if !self.metadata.contains_key(&login_page) {
            self.reassert_login_responses(&login_page);
        }
    }

    /// Turns the gate **off** and drops all tokens, restoring a fully public app.
    /// Caller publishes `certified_data` afterwards.
    pub fn disable_protection(&mut self) {
        let Some(login_page) = self.protection_login_page() else {
            return;
        };
        self.protection.set(ProtectionSettings { login_page: None });
        self.clear_tokens_and_login_responses(&login_page);
        self.recertify_all_assets();
        self.on_redirect_rules_change();
    }

    /// Mints a token under `label`: stores the record (`token_id`, expiry,
    /// redeem-cert path) and the gate-index entry (`token_id → expiry`), certifies
    /// this token's redeem response, and first sweeps expired tokens so the
    /// store/tree track only live tokens. The plaintext `value` is supplied by the
    /// caller (random or chosen) and is never stored. Errors if protection is off.
    /// Caller publishes `certified_data` afterwards.
    pub fn issue_token(
        &mut self,
        value: String,
        label: String,
        ttl_secs: u32,
        now: u64,
    ) -> Result<(), String> {
        let Some(login_page) = self.protection_login_page() else {
            return Err("protection is not enabled".to_string());
        };
        self.sweep_expired_tokens(now);
        // Labels are the unique identifier: re-issuing under an existing label
        // rotates it — drop the old token's gate-index entry and redeem cert first.
        self.remove_token(&label);
        let expires_at = now.saturating_add((ttl_secs as u64).saturating_mul(1_000_000_000));
        let location = AssetPath::from(login_page.as_str()).asset_hash_path_root();
        let redeem_tp = self
            .certify_protection_response(&location, &ProtectionResponse::redeem_success(&value));
        let token_id = crate::protection::token_id(&value);
        self.token_index.insert(token_id, expires_at);
        self.tokens.insert(
            label,
            TokenMeta {
                token_id,
                expires_at,
                redeem_path: redeem_tp.0,
            },
        );
        Ok(())
    }

    /// Removes the token with `label` from the store and gate index and drops its
    /// redeem cert. No-op if absent. The single place token removal happens —
    /// shared by `revoke_token`, the rotate path of `issue_token`, and the GC
    /// sweep. O(log n).
    fn remove_token(&mut self, label: &str) {
        if let Some(meta) = self.tokens.remove(&label.to_string()) {
            self.token_index.remove(&meta.token_id);
            self.asset_hashes
                .remove_response_precomputed(&HashTreePath(meta.redeem_path));
        }
    }

    /// Drops every token at or past expiry. Run at the start of `issue_token` (the
    /// op that grows the store) to bound growth. The full scan here is over the
    /// rare management map, not the hot gate path.
    fn sweep_expired_tokens(&mut self, now: u64) {
        let expired: Vec<String> = self
            .tokens
            .iter()
            .filter_map(|e| {
                let (label, meta) = e.into_pair();
                (meta.expires_at <= now).then_some(label)
            })
            .collect();
        for label in expired {
            self.remove_token(&label);
        }
    }

    /// Revokes the token with the given label (live — the next request bearing it
    /// fails the gate). O(log n) by label. Caller publishes `certified_data`.
    pub fn revoke_token(&mut self, label: &str) {
        self.remove_token(label);
    }

    /// Live tokens (label + expiry) for the management UI. Controller-guarded at
    /// the endpoint.
    pub fn list_tokens(&self) -> Vec<TokenInfo> {
        self.tokens
            .iter()
            .map(|e| {
                let (label, meta) = e.into_pair();
                TokenInfo {
                    label,
                    expires_at: meta.expires_at,
                }
            })
            .collect()
    }

    /// Whether protection is off, on-and-healthy, or on-but-degraded (login page
    /// asset absent).
    pub fn check_protection_status(&self) -> ProtectionStatus {
        match self.protection_login_page() {
            None => ProtectionStatus::Disabled,
            Some(login_page) => {
                if self.metadata.contains_key(&login_page) {
                    ProtectionStatus::Enabled { login_page }
                } else {
                    ProtectionStatus::EnabledLoginPageMissing { login_page }
                }
            }
        }
    }

    pub fn http_request(&self, req: HttpRequest, certificate: &[u8], now: u64) -> HttpResponse {
        let mut encodings: Vec<Encoding> = vec![];
        let mut etags: Vec<Hash> = vec![];
        let mut range_start: Option<usize> = None;
        for (name, value) in req.headers.iter() {
            if name.eq_ignore_ascii_case("Accept-Encoding") {
                encodings.extend(Encoding::parse_accept_encoding(value));
            } else if name.eq_ignore_ascii_case("If-None-Match") {
                etags.extend(parse_if_none_match(value));
            } else if name.eq_ignore_ascii_case("Range") {
                range_start = parse_range_start(value);
            }
        }

        let path = match req.url.find('?') {
            Some(i) => &req.url[..i],
            None => &req.url[..],
        };

        match url_decode(path) {
            Ok(path) => {
                // ---- access-protection gate ----
                // Runs before asset/redirect resolution so an unauthenticated
                // request never reaches asset content (a public app skips this
                // entirely — `protection_login_page()` is `None`).
                if let Some(login_page) = self.protection_login_page() {
                    if path == login_page {
                        // The login surface is gate-exempt. A POST is a login
                        // attempt (validate + Set-Cookie / 401); a GET serves the
                        // page itself, so it falls through to normal serving.
                        if req.method.eq_ignore_ascii_case("POST") {
                            return self.serve_redeem(&req, &login_page, certificate, now);
                        }
                    } else if !self.cookie_token_valid(&req, now) {
                        return self.serve_unauthenticated(&path, &login_page, certificate);
                    }
                }
                self.build_http_response(certificate, &path, encodings, etags, range_start)
            }
            // Malformed percent-encoding (invalid UTF-8 once decoded). This 400
            // is intentionally uncertified: the body is per-request (it echoes
            // the bad path), so it can't be pinned to a certified hash, and a
            // malformed URL has no certifiable response anyway. The HTTP gateway
            // rejects uncertified responses, so a browser never sees this body —
            // it surfaces only to a direct query call of `http_request` (e.g.
            // `dfx canister call`), where it serves as a diagnostic.
            Err(err) => HttpResponse {
                status_code: 400,
                headers: vec![],
                body: ByteBuf::from(format!("failed to decode path '{path}': {err}")),
                upgrade: None,
            },
        }
    }

    // ---- redirect rules ----

    /// Rebuild the certified-tree entries for the redirect rules. Called
    /// whenever the rule list changes (in `execute_operations`) or assets are
    /// restored from stable memory (in `post_upgrade_rebuild`). Caller must
    /// refresh `certified_data` after this.
    ///
    /// Status-200 rules borrow each encoding's certificate expression and
    /// response hash from the target asset, so this also has to run after any
    /// asset change that could affect those values.
    ///
    /// This is also the single owner of the root `<*>` fallback slot: a root
    /// `/*` rule and the built-in 404 are mutually exclusive occupants of it, so
    /// after rebuilding the rules we (re)certify the built-in 404 exactly when
    /// no active rule claims `<*>`. That keeps `build_http_response`'s
    /// fallthrough certified — the gateway rejects uncertified responses, so an
    /// uncertified fallback 404 would be unservable.
    pub fn on_redirect_rules_change(&mut self) {
        for entry in self.rule_certified_entries.drain(..).flatten() {
            for tp in &entry.tree_paths {
                self.asset_hashes.remove_response_precomputed(tp);
            }
        }
        // Drop any built-in 404 before rebuilding so a rule taking over `<*>`
        // doesn't leave a stale fallback hash beside it (and removing it now is
        // safe — we re-add below if `<*>` ends up rule-free).
        self.asset_hashes.remove_fallback_responses();

        let rules = self.redirect_rules.get().0.clone();
        let mut new_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>> =
            Vec::with_capacity(rules.len());
        for rule in &rules {
            new_entries.push(self.build_rule_entry(rule));
        }
        self.rule_certified_entries = new_entries;

        if !self.asset_hashes.has_fallback_response() {
            self.certify_not_found_fallback();
        }

        // Under protection, every certified path needs an unauthenticated sibling
        // (and a universal root `<*>` fallback) so the gate can serve a verifiable
        // 307/401 there. Added after the rules + built-in 404 so it layers on top.
        if let Some(login_page) = self.protection_login_page() {
            self.certify_rule_unauth_siblings(&login_page);
        }
    }

    /// Certifies the canister's built-in last-resort 404 ("not found") at the
    /// root `<*>` fallback path. Callers must ensure `<*>` is otherwise free;
    /// `on_redirect_rules_change` is the only caller and gates on that.
    fn certify_not_found_fallback(&mut self) {
        let response = HttpResponse::uncertified_404();
        let headers: Vec<_> = response
            .headers
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
        self.asset_hashes.certify_fallback_response(
            response.status_code,
            &headers,
            &response.body,
            None,
        );
    }

    /// Replaces the redirect rules and rebuilds their certified entries.
    pub fn set_redirect_rules(&mut self, rules: Vec<RedirectRule>) {
        self.redirect_rules.set(RedirectRules(rules));
        self.on_redirect_rules_change();
    }

    fn build_rule_entry(
        &mut self,
        rule: &RedirectRule,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        if let RulePattern::Exact(src) = &rule.from {
            if self.metadata.contains_key(src) {
                // Asset at the source path shadows the rule.
                return None;
            }
        }
        match rule.status {
            // 200 rewrites and 4xx custom error pages both borrow body + headers
            // from the target asset (4xx re-certifies with the override status;
            // see `build_alias_rule_entry`).
            200 | 404 | 410 => self.build_alias_rule_entry(rule, rule.status),
            // 3xx redirects synthesize an empty body; only the headers
            // (content-type, Location) are certified.
            _ => {
                let entry = crate::redirect::build_synthetic_entry(rule);
                for tp in &entry.tree_paths {
                    self.asset_hashes.certify_response_precomputed(tp);
                }
                Some(entry)
            }
        }
    }

    fn build_alias_rule_entry(
        &mut self,
        rule: &RedirectRule,
        status: u16,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        let target_key = rule.to.clone();
        let meta = self.metadata.get(&target_key)?;
        // Mirror the target asset's effective headers (incl. the env cookie on
        // an HTML target) so the alias reuses the same certified response the
        // direct hit / serve path produces.
        let effective_headers = self.effective_headers(&meta);
        let location = crate::redirect::tree_location(rule);
        let mut tree_paths = Vec::new();
        for (&encoding, enc) in &meta.encodings {
            // A 4xx custom error page is served as a single inline body with the
            // override status — 206 reassembly always yields a 200, so a
            // multi-chunk encoding can't carry it. Mirror the serve-side
            // `acceptable` filter and skip such encodings; certifying them here
            // would leave an unservable leaf the serve path never reproduces (it
            // falls back to the built-in 404), so the gateway would reject the
            // mismatched response. If *every* encoding is multi-chunk the rule
            // gets no leaves and goes inert (built-in 404 fallthrough). The sync
            // op guard rejects this combination up front; this keeps the
            // certified tree sound even if some other caller slips it through.
            if status != 200 && enc.num_chunks > 1 {
                continue;
            }
            let cert_expr = certificate_expression_for(&effective_headers, encoding, &enc.sha256);

            // A 200-rewrite to a multi-chunk target serves N×206 (the gateway
            // reassembles them into a 200), exactly like a direct hit. Certify
            // those 206 leaves at the alias location and move on.
            if status == 200 && enc.num_chunks > 1 {
                let (range_cert_expr, resp_hashes) = self.range_response_certs(
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    enc,
                );
                for resp_hash in resp_hashes {
                    let tp = crate::redirect::alias_tree_path(
                        &location,
                        range_cert_expr.expression_hash,
                        resp_hash,
                    );
                    self.asset_hashes.certify_response_precomputed(&tp);
                    tree_paths.push(tp);
                }
                continue;
            }

            let resp_hash = if status == 200 {
                // The encoding's already-certified 200 response hash.
                response_hashes_for(
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    &cert_expr,
                    &enc.sha256,
                )[&200]
            } else {
                // 4xx custom error page: re-certify with the override status
                // using the same headers and body the asset would serve at 200.
                let base_headers: Vec<(String, Value)> = headers_for(
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    &enc.sha256,
                )
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
                response_hash(&base_headers, status, &enc.sha256).0
            };
            let tp =
                crate::redirect::alias_tree_path(&location, cert_expr.expression_hash, resp_hash);
            self.asset_hashes.certify_response_precomputed(&tp);
            tree_paths.push(tp);
        }
        if tree_paths.is_empty() {
            return None;
        }
        Some(crate::redirect::CertifiedRuleEntry {
            tree_paths,
            location,
            kind: crate::redirect::CertifiedRuleEntryKind::AliasOf { target_key, status },
        })
    }

    // ---- environment cookie ----

    /// Stores the rendered env cookie from a freshly captured snapshot **without**
    /// re-certifying. Used by `post_upgrade` *before* `post_upgrade_rebuild`, so
    /// the rebuild — which re-certifies every asset from scratch — picks the
    /// cookie up through `effective_headers`.
    pub fn store_env(&mut self, env: &crate::runtime::CanisterEnv) {
        self.env_cookie = Some(env.render_cookie());
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
        if self.env_cookie.as_deref() != Some(env.render_cookie().as_str()) {
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
        let keys: Vec<AssetKey> = self.metadata.keys().collect();
        for key in keys {
            if let Some(meta) = self.metadata.get(&key) {
                if crate::asset::is_html_content_type(&meta.content_type) {
                    self.recertify_asset(&key, &meta);
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
        self.recertify_all_assets();
        self.on_redirect_rules_change();
        self.rebuild_token_index();
        // If protection is on but the login page asset isn't present, the asset
        // loop above didn't re-assert its redeem responses — do it explicitly so
        // the redeem endpoint survives the upgrade even in the degraded state.
        if let Some(login_page) = self.protection_login_page() {
            if !self.metadata.contains_key(&login_page) {
                self.reassert_login_responses(&login_page);
            }
        }
    }

    /// Rebuilds the in-heap gate index (`token_id → expires_at`) from the durable
    /// `tokens` store after an upgrade. Lossless: every entry is derivable from a
    /// `TokenMeta`. Cheap — the token set is small.
    fn rebuild_token_index(&mut self) {
        self.token_index = self
            .tokens
            .iter()
            .map(|e| {
                let meta = e.into_pair().1;
                (meta.token_id, meta.expires_at)
            })
            .collect();
    }
}
