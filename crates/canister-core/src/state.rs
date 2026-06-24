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
    certificate_expression_for, headers_for, response_hashes_for, STATUS_CODES_TO_CERTIFY,
};
use crate::blob_store::BlobStore;
use crate::certification::{
    response_hash, AssetKey, AssetPath, CertifiedResponses, RequestHash, ResponseHash,
};
use crate::http::{
    CallbackFunc, HeaderField, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
    StreamingCallbackToken, StreamingStrategy,
};
use crate::rc_bytes::RcBytes;
use crate::stable_store::{AssetMeta, AuthorizedSet, EncodingMeta, RedirectRules};
use crate::sync::{Chunk, SyncSession};
use crate::url::url_decode;
use candid::Principal;
use ic_certification::{AsHashTree, Hash};
use ic_representation_independent_hash::Value;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
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
            chunks: Vec::new(),
            sync_session: None,
            asset_hashes: CertifiedResponses::default(),
            rule_certified_entries: Vec::new(),
            env_cookie: None,
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

    /// Fetches one chunk's bytes from the content store as `RcBytes`. A missing
    /// chunk yields empty bytes (callers only request indices the metadata
    /// claims exist).
    fn chunk_bytes(&self, content_id: u64, chunk_index: usize) -> RcBytes {
        self.content
            .get(content_id, chunk_index as u32)
            .map(|bytes| RcBytes::from(ByteBuf::from(bytes)))
            .unwrap_or_default()
    }

    /// Frees every chunk belonging to a content group.
    fn delete_content(&mut self, content_id: u64) {
        self.content.delete_group(content_id);
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

    /// Test/helper entry point that hashes the staged chunks itself. The live
    /// sync path hashes incrementally in `execute_operations` and calls
    /// `complete_set_asset_content` directly.
    #[cfg(test)]
    pub fn set_asset_content(&mut self, arg: SetAssetContentArguments) -> Result<(), String> {
        use sha2::Digest;
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

        let mut hasher = sha2::Sha256::new();
        for chunk in content_chunks.iter() {
            hasher.update(chunk);
        }
        let sha256: [u8; 32] = hasher.finalize().into();

        self.complete_set_asset_content(arg, content_chunks, sha256)
    }

    /// Writes an encoding's content into the chunk store and re-certifies the
    /// asset. Replacing an existing encoding frees the old content group first.
    pub fn complete_set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
        content_chunks: Vec<RcBytes>,
        sha256: [u8; 32],
    ) -> Result<(), String> {
        let provided_hash: [u8; 32] = arg
            .sha256
            .into_vec()
            .try_into()
            .map_err(|_| "invalid SHA-256".to_string())?;
        if sha256 != provided_hash {
            return Err("sha256 mismatch".to_string());
        }

        let mut meta = self
            .metadata
            .get(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        // Free the chunks of any encoding we're replacing.
        if let Some(old) = meta.encodings.get(&arg.encoding) {
            self.delete_content(old.content_id);
        }

        // Allocate a fresh content group and write the chunks into it.
        let content_id = self.alloc_content_id();
        let num_chunks = content_chunks.len() as u32;
        for (index, chunk) in content_chunks.iter().enumerate() {
            self.content.insert(content_id, index as u32, chunk);
        }

        meta.encodings.insert(
            arg.encoding,
            EncodingMeta {
                content_id,
                num_chunks,
                sha256,
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
        headers
    }

    /// Removes and recomputes every certified response for one asset from its
    /// metadata. Recompute is cheap: it reads only headers/content_type/sha256,
    /// never content bytes.
    fn recertify_asset(&mut self, key: &AssetKey, meta: &AssetMeta) {
        self.asset_hashes.remove_responses_for_path(key);
        if meta.encodings.is_empty() {
            return;
        }

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
            for status_code in STATUS_CODES_TO_CERTIFY {
                let response_hash = response_hashes[&status_code];
                let hash_path = path.hash_tree_path(
                    &cert_expr,
                    &RequestHash::default(),
                    ResponseHash::from(&response_hash),
                );
                self.asset_hashes.certify_response_precomputed(&hash_path);
            }
        }
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

    // ---- HTTP serving ----

    #[allow(clippy::too_many_arguments)]
    fn build_http_response(
        &self,
        certificate: &[u8],
        path: &str,
        requested_encodings: Vec<Encoding>,
        chunk_index: usize,
        callback: CallbackFunc,
        etags: Vec<Hash>,
    ) -> HttpResponse {
        // Asset at the requested path wins.
        if let Some(meta) = self.metadata.get(&path.to_string()) {
            let (cert_header, _) = self.asset_hashes.witness_to_header(path, certificate);
            if let Some(response) = self.build_asset_response(
                &meta,
                &requested_encodings,
                chunk_index,
                Some(&cert_header),
                &callback,
                &etags,
                None,
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
                chunk_index,
                &callback,
                &etags,
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
        chunk_index: usize,
        certificate_header: Option<&HeaderField>,
        callback: &CallbackFunc,
        etags: &[Hash],
        status_override: Option<u16>,
    ) -> Option<HttpResponse> {
        // Honour the client's listed order first; if it expressed no acceptable
        // encoding, fall back to our preference order (identity-first).
        let encoding = requested_encodings
            .iter()
            .copied()
            .find(|e| meta.encodings.contains_key(e))
            .or_else(|| {
                Encoding::PREFERENCE_ORDER
                    .into_iter()
                    .find(|e| meta.encodings.contains_key(e))
            })?;
        let enc = meta.encodings.get(&encoding)?;
        Some(self.build_ok_http_response(
            meta,
            encoding,
            enc,
            chunk_index,
            certificate_header,
            callback,
            etags,
            status_override,
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
        chunk_index: usize,
        certificate_header: Option<&HeaderField>,
        callback: &CallbackFunc,
        etags: &[Hash],
        status_override: Option<u16>,
    ) -> HttpResponse {
        let mut headers = headers_for(
            &self.effective_headers(meta),
            &meta.content_type,
            encoding,
            &enc.sha256,
        );
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }

        let streaming_strategy = StreamingCallbackToken::create_token(
            enc.content_id,
            enc.num_chunks,
            ByteBuf::from(enc.sha256),
            chunk_index,
        )
        .map(|token| StreamingStrategy::Callback {
            callback: callback.clone(),
            token,
        });

        // The canister-managed `etag` header is already in `headers` (and in the
        // certified set), so both the 200 and the 304 carry it.
        let (status_code, body, streaming_strategy) = if let Some(status) = status_override {
            (
                status,
                self.chunk_bytes(enc.content_id, chunk_index),
                streaming_strategy,
            )
        } else if etags.contains(&enc.sha256) {
            // Conditional request matched: serve the certified 304 — empty body,
            // no streaming. Its response hash is certified alongside the 200.
            (304, RcBytes::default(), None)
        } else {
            (
                200,
                self.chunk_bytes(enc.content_id, chunk_index),
                streaming_strategy,
            )
        };

        HttpResponse {
            status_code,
            headers,
            body,
            upgrade: None,
            streaming_strategy,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_redirect_rule_response(
        &self,
        rule: &RedirectRule,
        entry: &crate::redirect::CertifiedRuleEntry,
        path: &str,
        certificate: &[u8],
        requested_encodings: &[Encoding],
        chunk_index: usize,
        callback: &CallbackFunc,
        etags: &[Hash],
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
                    body: RcBytes::from(ByteBuf::new()),
                    upgrade: None,
                    streaming_strategy: None,
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
                    chunk_index,
                    Some(&cert_header),
                    callback,
                    etags,
                    status_override,
                )
                .unwrap_or_else(|| HttpResponse::build_404(cert_header))
            }
        }
    }

    pub fn http_request(
        &self,
        req: HttpRequest,
        certificate: &[u8],
        callback: CallbackFunc,
    ) -> HttpResponse {
        let mut encodings: Vec<Encoding> = vec![];
        let mut etags: Vec<Hash> = vec![];
        for (name, value) in req.headers.iter() {
            if name.eq_ignore_ascii_case("Accept-Encoding") {
                encodings.extend(Encoding::parse_accept_encoding(value));
            } else if name.eq_ignore_ascii_case("If-None-Match") {
                etags.extend(parse_if_none_match(value));
            }
        }

        let path = match req.url.find('?') {
            Some(i) => &req.url[..i],
            None => &req.url[..],
        };

        match url_decode(path) {
            Ok(path) => self.build_http_response(certificate, &path, encodings, 0, callback, etags),
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
                body: RcBytes::from(ByteBuf::from(format!(
                    "failed to decode path '{path}': {err}"
                ))),
                upgrade: None,
                streaming_strategy: None,
            },
        }
    }

    pub fn http_request_streaming_callback(
        &self,
        StreamingCallbackToken {
            content_id,
            index,
            num_chunks,
            sha256,
        }: StreamingCallbackToken,
    ) -> StreamingCallbackHttpResponse {
        // The token is self-describing, so the callback needs no `metadata.get`
        // / `AssetMeta` decode: it reads the requested chunk straight from the
        // content store and re-derives the next token from the token's own
        // fields. A forged `content_id`/`index` just misses the content store
        // and yields an empty body — the gateway's `sha256` check then rejects
        // the stream, so no uncertified bytes are ever served.
        let chunk_index = index as usize;
        StreamingCallbackHttpResponse {
            body: self.chunk_bytes(content_id, chunk_index),
            token: StreamingCallbackToken::create_token(
                content_id,
                num_chunks,
                sha256,
                chunk_index,
            ),
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
            let cert_expr = certificate_expression_for(&effective_headers, encoding, &enc.sha256);
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
    /// redirect-rule certified entries, and the built-in 404 fallback (the last
    /// two via `on_redirect_rules_change`). The caller publishes `certified_data`
    /// afterwards.
    pub fn post_upgrade_rebuild(&mut self) {
        let keys: Vec<AssetKey> = self.metadata.keys().collect();
        for key in keys {
            if let Some(meta) = self.metadata.get(&key) {
                self.recertify_asset(&key, &meta);
            }
        }
        self.on_redirect_rules_change();
    }
}
