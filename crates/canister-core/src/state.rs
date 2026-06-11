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
    certificate_expression_for, encoding_certification_order, headers_for, response_hashes_for,
    STATUS_CODES_TO_CERTIFY,
};
use crate::certification::{
    response_hash, AssetKey, AssetPath, CertifiedResponses, RequestHash, ResponseHash,
};
use crate::http::{
    CallbackFunc, HeaderField, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
    StreamingCallbackToken, StreamingStrategy,
};
use crate::rc_bytes::RcBytes;
use crate::stable_store::{AssetMeta, AuthorizedSet, ContentChunkKey, EncodingMeta, RedirectRules};
use crate::sync::{Chunk, SyncSession};
use crate::types::*;
use crate::url::url_decode;
use candid::Principal;
use ic_certification::{AsHashTree, Hash};
use ic_representation_independent_hash::Value;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use sha2::Digest;
use std::collections::BTreeMap;
use std::convert::TryInto;

/// Maximum number of items the canister returns from a single paginated query
/// (`get_asset_details`, `get_redirect_rules`). The caller follows the cursor
/// until it sees a short or empty page; it never needs to know this value.
pub(crate) const PAGE_SIZE: usize = 100;

type Mem = VirtualMemory<DefaultMemoryImpl>;

const AUTHORIZED_MEMORY: MemoryId = MemoryId::new(0);
const REDIRECT_RULES_MEMORY: MemoryId = MemoryId::new(1);
const NEXT_SESSION_ID_MEMORY: MemoryId = MemoryId::new(2);
const NEXT_CONTENT_ID_MEMORY: MemoryId = MemoryId::new(3);
const METADATA_MEMORY: MemoryId = MemoryId::new(4);
const CONTENT_MEMORY: MemoryId = MemoryId::new(5);

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
    /// Raw content bytes, one entry per chunk, keyed by `(content_id, index)`.
    content: StableBTreeMap<ContentChunkKey, Vec<u8>, Mem>,

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
    pub(crate) asset_hashes: CertifiedResponses,
    /// Per-rule certified-tree entries, parallel to `settings.redirect_rules`. A
    /// `None` slot means the rule has no certified entry — either because an
    /// asset shadows an exact rule at the same path, or because an alias rule
    /// (200/4xx) points at a target asset that doesn't exist yet.
    pub(crate) rule_certified_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>>,
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
            content: StableBTreeMap::init(mm.get(CONTENT_MEMORY)),
            chunks: Vec::new(),
            sync_session: None,
            asset_hashes: CertifiedResponses::default(),
            rule_certified_entries: Vec::new(),
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
    pub(crate) fn alloc_session_id(&mut self) -> SessionId {
        let id = *self.next_session_id.get();
        self.next_session_id.set(id + 1);
        id
    }

    /// Whether an asset exists at `key`.
    pub(crate) fn contains_asset(&self, key: &AssetKey) -> bool {
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
            .get(&ContentChunkKey::new(content_id, chunk_index as u32))
            .map(|bytes| RcBytes::from(ByteBuf::from(bytes)))
            .unwrap_or_default()
    }

    /// Range-deletes every chunk belonging to a content group.
    fn delete_content(&mut self, content_id: u64) {
        let keys: Vec<ContentChunkKey> = self
            .content
            .keys_range(ContentChunkKey::range(content_id))
            .collect();
        for key in keys {
            self.content.remove(&key);
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

    /// Test/helper entry point that hashes the staged chunks itself. The live
    /// sync path hashes incrementally in `execute_operations` and calls
    /// `complete_set_asset_content` directly.
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

        let mut hasher = sha2::Sha256::new();
        for chunk in content_chunks.iter() {
            hasher.update(chunk);
        }
        let sha256: [u8; 32] = hasher.finalize().into();

        self.complete_set_asset_content(arg, content_chunks, sha256)
    }

    /// Writes an encoding's content into the chunk store and re-certifies the
    /// asset. Replacing an existing encoding frees the old content group first.
    pub(crate) fn complete_set_asset_content(
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
        if let Some(old) = meta.encodings.get(&arg.content_encoding) {
            self.delete_content(old.content_id);
        }

        // Allocate a fresh content group and write the chunks into it.
        let content_id = self.alloc_content_id();
        let num_chunks = content_chunks.len() as u32;
        for (index, chunk) in content_chunks.iter().enumerate() {
            self.content.insert(
                ContentChunkKey::new(content_id, index as u32),
                chunk.to_vec(),
            );
        }

        meta.encodings.insert(
            arg.content_encoding,
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

        if let Some(old) = meta.encodings.remove(&arg.content_encoding) {
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

    /// Removes and recomputes every certified response for one asset from its
    /// metadata. Recompute is cheap: it reads only headers/content_type/sha256,
    /// never content bytes.
    fn recertify_asset(&mut self, key: &AssetKey, meta: &AssetMeta) {
        self.asset_hashes.remove_responses_for_path(key);
        if meta.encodings.is_empty() {
            return;
        }

        let path = AssetPath::from(key.as_str());
        for (enc_name, enc) in &meta.encodings {
            let cert_expr = certificate_expression_for(&meta.headers, enc_name);
            let response_hashes = response_hashes_for(
                &meta.headers,
                &meta.content_type,
                enc_name,
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
                    .map(|(enc_name, enc)| AssetEncodingDetails {
                        content_encoding: enc_name.clone(),
                        sha256: ByteBuf::from(enc.sha256),
                    })
                    .collect();
                encodings.sort_by(|l, r| l.content_encoding.cmp(&r.content_encoding));

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
    pub fn get_redirect_rules(&self, start_index: u64) -> Vec<crate::redirect::RedirectRule> {
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
        requested_encodings: Vec<String>,
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
                path,
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
        requested_encodings: &[String],
        key: &str,
        chunk_index: usize,
        certificate_header: Option<&HeaderField>,
        callback: &CallbackFunc,
        etags: &[Hash],
        status_override: Option<u16>,
    ) -> Option<HttpResponse> {
        let enc_name = requested_encodings
            .iter()
            .find(|e| meta.encodings.contains_key(*e))
            .cloned()
            .or_else(|| {
                encoding_certification_order(meta.encodings.keys())
                    .into_iter()
                    .find(|e| meta.encodings.contains_key(e))
            })?;
        let enc = meta.encodings.get(&enc_name)?;
        Some(self.build_ok_http_response(
            meta,
            &enc_name,
            enc,
            key,
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
        enc_name: &str,
        enc: &EncodingMeta,
        key: &str,
        chunk_index: usize,
        certificate_header: Option<&HeaderField>,
        callback: &CallbackFunc,
        etags: &[Hash],
        status_override: Option<u16>,
    ) -> HttpResponse {
        let mut headers = headers_for(&meta.headers, &meta.content_type, enc_name);
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }

        let streaming_strategy = StreamingCallbackToken::create_token(
            enc_name,
            enc.num_chunks as usize,
            enc.sha256,
            key,
            chunk_index,
        )
        .map(|token| StreamingStrategy::Callback {
            callback: callback.clone(),
            token,
        });

        let (status_code, body) = if let Some(status) = status_override {
            (status, self.chunk_bytes(enc.content_id, chunk_index))
        } else if etags.contains(&enc.sha256) {
            (304, RcBytes::default())
        } else {
            if !headers
                .iter()
                .any(|(header_name, _)| header_name.eq_ignore_ascii_case("etag"))
            {
                headers.push((
                    "etag".to_string(),
                    format!("\"{}\"", hex::encode(enc.sha256)),
                ));
            }
            (200, self.chunk_bytes(enc.content_id, chunk_index))
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
        rule: &crate::redirect::RedirectRule,
        entry: &crate::redirect::CertifiedRuleEntry,
        path: &str,
        certificate: &[u8],
        requested_encodings: &[String],
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
                    path,
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
        let mut encodings = vec![];
        // waiting for https://dfinity.atlassian.net/browse/BOUN-446
        let etags = Vec::new();
        for (name, value) in req.headers.iter() {
            if name.eq_ignore_ascii_case("Accept-Encoding") {
                for v in value.split(',') {
                    encodings.push(v.trim().to_string());
                }
            }
        }

        let path = match req.url.find('?') {
            Some(i) => &req.url[..i],
            None => &req.url[..],
        };

        match url_decode(path) {
            Ok(path) => self.build_http_response(certificate, &path, encodings, 0, callback, etags),
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
            key,
            content_encoding,
            index,
            sha256,
        }: StreamingCallbackToken,
    ) -> Result<StreamingCallbackHttpResponse, String> {
        let meta = self
            .metadata
            .get(&key)
            .ok_or_else(|| "Invalid token on streaming: key not found.".to_string())?;
        let enc = meta
            .encodings
            .get(&content_encoding)
            .ok_or_else(|| "Invalid token on streaming: encoding not found.".to_string())?;

        if sha256 != ByteBuf::from(enc.sha256) {
            return Err("sha256 mismatch".to_string());
        }

        // MAX is good enough. This means a chunk would be above 64-bits, which is impossible...
        let chunk_index = index.0.to_usize().unwrap_or(usize::MAX);

        Ok(StreamingCallbackHttpResponse {
            body: self.chunk_bytes(enc.content_id, chunk_index),
            token: StreamingCallbackToken::create_token(
                &content_encoding,
                enc.num_chunks as usize,
                enc.sha256,
                &key,
                chunk_index,
            ),
        })
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
    pub(crate) fn on_redirect_rules_change(&mut self) {
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
    pub(crate) fn set_redirect_rules(&mut self, rules: Vec<crate::redirect::RedirectRule>) {
        self.redirect_rules.set(RedirectRules(rules));
        self.on_redirect_rules_change();
    }

    fn build_rule_entry(
        &mut self,
        rule: &crate::redirect::RedirectRule,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        if let crate::redirect::RulePattern::Exact(src) = &rule.from {
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
        rule: &crate::redirect::RedirectRule,
        status: u16,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        let target_key = rule.to.clone();
        let meta = self.metadata.get(&target_key)?;
        let location = crate::redirect::tree_location(rule);
        let mut tree_paths = Vec::new();
        for (enc_name, enc) in &meta.encodings {
            let cert_expr = certificate_expression_for(&meta.headers, enc_name);
            let resp_hash = if status == 200 {
                // The encoding's already-certified 200 response hash.
                response_hashes_for(
                    &meta.headers,
                    &meta.content_type,
                    enc_name,
                    &cert_expr,
                    &enc.sha256,
                )[&200]
            } else {
                // 4xx custom error page: re-certify with the override status
                // using the same headers and body the asset would serve at 200.
                let base_headers: Vec<(String, Value)> =
                    headers_for(&meta.headers, &meta.content_type, enc_name)
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
