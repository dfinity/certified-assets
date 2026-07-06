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

use crate::asset::{headers_for, range_headers_for};
use crate::certification::{
    build_ic_certificate_expression_header, AssetKey, AssetPath, HashTreePath,
};
use crate::certifier::Certifier;
use crate::http::{HeaderField, HttpRequest, HttpResponse};
use crate::protection::{ProtectionResponse, ProtectionStatus, TokenInfo};
use crate::stable_store::{AssetMeta, EncodingMeta, TokenMeta};
use crate::store::Store;
use crate::sync::{Chunk, SyncSession};
use crate::url::url_decode;
use candid::Principal;
use ic_certification::Hash;
use ic_stable_structures::DefaultMemoryImpl;
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;

use wire_types::{
    AssetDetails, AssetEncodingDetails, CreateAssetArguments, DeleteAssetArguments, Encoding,
    RedirectRule, SessionId, SetAssetContentArguments, SetAssetHeadersArguments,
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

pub struct State {
    /// Durable state: everything persisted in stable memory. All storage access
    /// funnels through this typed interface — `State` never touches a
    /// `StableCell`/`StableBTreeMap`/`MemoryId` directly. See [`Store`].
    store: Store,

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
    /// witnesses; the mutation paths drive its (re)certification. See
    /// [`Certifier`].
    certifier: Certifier,
    /// Hot-path gate index: `SHA-256(value) -> expires_at`. The per-request gate
    /// hashes the presented cookie and looks it up here — a heap-map read, no
    /// stable access or `TokenMeta` deserialize. Pure derived state (every entry
    /// is reconstructable from the token store, which carries each token's
    /// `token_id` and expiry), so it lives in heap and is rebuilt on upgrade like
    /// the certified tree. Kept one-to-one with the token store; revocation/expiry
    /// are live.
    token_index: HashMap<[u8; 32], u64>,
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
    /// (see [`State::build_alias_rule_entry`]), so the sync op guard rejects 4xx
    /// rules whose target is already multi-chunk.
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

    // ---- HTTP serving ----

    /// The first redirect rule (declaration order) that matches `path` and has a
    /// certified entry, or `None`. This is the shared spine of both request
    /// resolvers — the normal serve path ([`Self::build_http_response`]) and the
    /// access-protection gate ([`Self::serve_unauthenticated`]) — which each do
    /// their own thing with the match (serve it vs. serve a 307 at its location)
    /// but agree on *which* rule wins. A rule without a certified entry (shadowed
    /// by an asset, or an alias to a missing target) is skipped, exactly as
    /// serving requires — the gateway rejects a witness for an uncertified path.
    fn matching_rule(
        &self,
        path: &str,
    ) -> Option<(&RedirectRule, &crate::redirect::CertifiedRuleEntry)> {
        self.store
            .redirect_rules()
            .iter()
            .enumerate()
            .find_map(|(idx, rule)| {
                if !crate::redirect::matches(rule, path) {
                    return None;
                }
                let entry = self.certifier.rule_entry(idx)?;
                Some((rule, entry))
            })
    }

    fn build_http_response(
        &self,
        certificate: &[u8],
        path: &str,
        requested_encodings: Vec<Encoding>,
        etags: Vec<Hash>,
        range_start: Option<usize>,
    ) -> HttpResponse {
        // Asset at the requested path wins. A content-less asset (no encoding to
        // serve) yields `None` here and falls through to the rule scan, so a
        // wildcard rule can still cover it.
        if let Some(meta) = self.store.get_asset(&path.to_string()) {
            let cert_header = self.certifier.witness_to_header(path, certificate);
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

        // Scan redirect rules in declaration order; first certified match wins.
        if let Some((rule, entry)) = self.matching_rule(path) {
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

        let certificate_header = self.certifier.witness_to_header(path, certificate);
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
            &self.certifier.effective_headers(&self.store, meta),
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
            (
                status,
                ByteBuf::from(self.store.read_chunk(enc.content_id, 0)),
            )
        } else if etags.contains(&enc.sha256) {
            // Conditional request matched: serve the certified 304 (empty body).
            (304, ByteBuf::new())
        } else {
            (200, ByteBuf::from(self.store.read_chunk(enc.content_id, 0)))
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
        for (chunk_index, cc) in self.store.chunk_certs_of(enc.content_id) {
            let len = cc.len as usize;
            if start < offset + len {
                target = Some((chunk_index, offset, len));
                break;
            }
            offset += len;
        }
        let (chunk_index, chunk_start, len) = target?;

        let chunk = self.store.read_chunk(enc.content_id, chunk_index);
        let content_range = format!("bytes {}-{}/{}", chunk_start, chunk_start + len - 1, total);
        let mut headers = range_headers_for(
            &self.certifier.effective_headers(&self.store, meta),
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
            self.certifier
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
                let Some(meta) = self.store.get_asset(target_key) else {
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
            self.certifier
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
        if let Some(meta) = self.store.get_asset(&path.to_string()) {
            let resp = if crate::asset::is_html_content_type(&meta.content_type) {
                ProtectionResponse::redirect_to_login(login_page)
            } else {
                ProtectionResponse::unauthorized()
            };
            let location = AssetPath::from(path).asset_hash_path_root();
            return self.serve_protection_response(&resp, path, &location, certificate);
        }
        // 2. Matching redirect rule → a 307 at the rule's location instead of
        //    following the rule (which could leak content). Same rule the serve
        //    path would pick; here we only need that one exists.
        if let Some((rule, _entry)) = self.matching_rule(path) {
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

    // ---- access-protection state management (controller-driven) ----

    /// Removes every certified response under the login page's subtree (redeem
    /// `302`s, the `401`, and the `200` page if synced) and drops all tokens. A
    /// following recertify re-adds the `200` for a still-present asset.
    fn clear_tokens_and_login_responses(&mut self, login_page: &str) {
        // The whole login subtree (redeem 302s, the 401, the 200 page) goes in one
        // shot, so per-token cert removal isn't needed — just empty the store and
        // the (heap) gate index.
        self.certifier.remove_responses_for_path(login_page);
        self.store.clear_tokens();
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
        self.store
            .set_protection_login_page(Some(login_page.clone()));
        self.certifier.recertify_all_assets(&self.store);
        self.on_redirect_rules_change();
        // Enable-first: if the page isn't synced yet, the asset loop didn't touch
        // it, but the redeem endpoint must still work — assert its responses.
        if !self.store.contains_asset(&login_page) {
            self.certifier
                .reassert_login_responses(&self.store, &login_page);
        }
    }

    /// Turns the gate **off** and drops all tokens, restoring a fully public app.
    /// Caller publishes `certified_data` afterwards.
    pub fn disable_protection(&mut self) {
        let Some(login_page) = self.protection_login_page() else {
            return;
        };
        self.store.set_protection_login_page(None);
        self.clear_tokens_and_login_responses(&login_page);
        self.certifier.recertify_all_assets(&self.store);
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
            .certifier
            .certify_protection_response(&location, &ProtectionResponse::redeem_success(&value));
        let token_id = crate::protection::token_id(&value);
        self.token_index.insert(token_id, expires_at);
        self.store.insert_token(
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
        if let Some(meta) = self.store.remove_token(label) {
            self.token_index.remove(&meta.token_id);
            self.certifier
                .remove_response(&HashTreePath(meta.redeem_path));
        }
    }

    /// Drops every token at or past expiry. Run at the start of `issue_token` (the
    /// op that grows the store) to bound growth. The full scan here is over the
    /// rare management map, not the hot gate path.
    fn sweep_expired_tokens(&mut self, now: u64) {
        let expired: Vec<String> = self
            .store
            .iter_tokens()
            .filter_map(|(label, meta)| (meta.expires_at <= now).then_some(label))
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
        self.store
            .iter_tokens()
            .map(|(label, meta)| TokenInfo {
                label,
                expires_at: meta.expires_at,
            })
            .collect()
    }

    /// Whether protection is off, on-and-healthy, or on-but-degraded (login page
    /// asset absent).
    pub fn check_protection_status(&self) -> ProtectionStatus {
        match self.protection_login_page() {
            None => ProtectionStatus::Disabled,
            Some(login_page) => {
                if self.store.contains_asset(&login_page) {
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
