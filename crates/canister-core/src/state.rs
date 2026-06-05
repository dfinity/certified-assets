//! This module contains a pure implementation of the certified assets state machine.
//!
//! NB. This module should not depend on ic_cdk, it contains only pure state transition functions.
//! All the environment (time, certificates, etc.) is passed to the state transition functions
//! as formal arguments. This approach makes it very easy to test the state machine.

use crate::{
    asset::{
        on_asset_change, Asset, AssetDetails, AssetEncoding, AssetEncodingDetails, EncodedAsset,
    },
    batch::{Batch, Chunk, ComputationStatus},
    certification::{AssetKey, CertifiedResponses},
    http::{
        CallbackFunc, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
        StreamingCallbackToken,
    },
    rc_bytes::RcBytes,
    stable::StableState,
    state_hash::StateHashComputation,
    system_context::SystemContext,
    types::*,
    url::url_decode,
};
use candid::{CandidType, Deserialize, Int, Nat, Principal};
use ic_certification::{AsHashTree, Hash};
use num_traits::ToPrimitive;
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::Digest;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CertifiedTree {
    pub certificate: Vec<u8>,
    pub tree: Vec<u8>,
}

#[derive(Default)]
pub struct State {
    pub(crate) assets: HashMap<AssetKey, Asset>,

    pub(crate) chunks: HashMap<ChunkId, Chunk>,
    pub(crate) next_chunk_id: ChunkId,

    pub(crate) batches: HashMap<BatchId, Batch>,
    pub(crate) next_batch_id: BatchId,

    // Principals authorized to sync assets. Canister controllers are always
    // allowed regardless of membership; this set grants the same access to
    // non-controllers. Only controllers can change it.
    pub(crate) authorized: BTreeSet<Principal>,

    pub(crate) asset_hashes: CertifiedResponses,

    pub(crate) redirect_rules: Vec<crate::redirect::RedirectRule>,
    /// Per-rule certified-tree entries, parallel to `redirect_rules`. A
    /// `None` slot means the rule has no certified entry — either because an
    /// asset shadows an exact rule at the same path, or because an alias rule
    /// (200/4xx) points at a target asset that doesn't exist yet.
    pub(crate) rule_certified_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>>,

    pub(crate) state_hash_computation: Option<StateHashComputation>,
    pub(crate) last_state_update_timestamp_ns: u64,
    pub(crate) last_state_hash_timestamp: u64,
}

impl State {
    fn get_asset(&self, key: &AssetKey) -> Result<&Asset, String> {
        self.assets
            .get(key)
            .ok_or_else(|| "asset not found".to_string())
    }

    pub fn authorize(&mut self, principal: Principal) {
        self.authorized.insert(principal);
    }

    pub fn deauthorize(&mut self, principal: &Principal) {
        self.authorized.remove(principal);
    }

    pub fn list_authorized(&self) -> &BTreeSet<Principal> {
        &self.authorized
    }

    pub fn is_authorized(&self, principal: &Principal) -> bool {
        self.authorized.contains(principal)
    }

    pub fn root_hash(&self) -> Hash {
        self.asset_hashes.root_hash()
    }

    pub fn last_state_update_timestamp_ns(&self) -> u64 {
        self.last_state_update_timestamp_ns
    }

    pub fn create_asset(&mut self, arg: CreateAssetArguments) -> Result<(), String> {
        if self.assets.contains_key(&arg.key) {
            return Err("asset already exists".to_string());
        }

        self.assets.insert(
            arg.key,
            Asset {
                content_type: arg.content_type,
                encodings: HashMap::new(),
                max_age: arg.max_age,
                headers: arg.headers,
            },
        );
        Ok(())
    }

    pub fn set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
        system_context: &SystemContext,
    ) -> Result<(), String> {
        if arg.chunk_ids.is_empty() && arg.last_chunk.is_none() {
            return Err("encoding must have at least one chunk or contain last_chunk".to_string());
        }

        let dependent_keys = self.dependent_keys(&arg.key);
        if !self.assets.contains_key(&arg.key) {
            return Err("asset not found".to_string());
        }

        let now = Int::from(system_context.current_timestamp_ns);

        let mut content_chunks = vec![];
        for chunk_id in arg.chunk_ids.iter() {
            let chunk = self.chunks.remove(chunk_id).expect("chunk not found");
            content_chunks.push(chunk.content);
        }
        if let Some(encoding_content) = arg.last_chunk.clone() {
            content_chunks.push(encoding_content.into());
        }

        let mut hasher = sha2::Sha256::new();
        for chunk in content_chunks.iter() {
            hasher.update(chunk);
        }
        let sha256: [u8; 32] = hasher.finalize().into();

        self.complete_set_asset_content(arg, content_chunks, sha256, now, dependent_keys)
    }

    pub(crate) fn complete_set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
        content_chunks: Vec<RcBytes>,
        sha256: [u8; 32],
        now: Int,
        dependent_keys: Vec<AssetKey>,
    ) -> Result<(), String> {
        if let Some(provided_hash) = arg.sha256 {
            let provided_hash: [u8; 32] = provided_hash
                .into_vec()
                .try_into()
                .map_err(|_| "invalid SHA-256".to_string())?;
            if sha256 != provided_hash {
                return Err("sha256 mismatch".to_string());
            }
        }

        let asset = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        let total_length: usize = content_chunks.iter().map(|c| c.len()).sum();
        let enc = AssetEncoding {
            modified: now,
            content_chunks,
            certified: false,
            total_length,
            sha256,
            certificate_expression: None, // set by on_asset_change
            response_hashes: None,        // set by on_asset_change
        };
        asset.encodings.insert(arg.content_encoding, enc);

        on_asset_change(&mut self.asset_hashes, &arg.key, asset, dependent_keys);

        Ok(())
    }

    pub fn unset_asset_content(&mut self, arg: UnsetAssetContentArguments) -> Result<(), String> {
        let dependent_keys = self.dependent_keys(&arg.key);
        let asset = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        if asset.encodings.remove(&arg.content_encoding).is_some() {
            on_asset_change(&mut self.asset_hashes, &arg.key, asset, dependent_keys);
        }

        Ok(())
    }

    pub fn delete_asset(&mut self, arg: DeleteAssetArguments) {
        if self.assets.contains_key(&arg.key) {
            self.asset_hashes.remove_responses_for_path(&arg.key);
            self.assets.remove(&arg.key);
        }
    }

    pub fn clear(&mut self) {
        self.assets.clear();
        self.batches.clear();
        self.chunks.clear();
        self.next_batch_id = Nat::from(1_u8);
        self.next_chunk_id = Nat::from(1_u8);
    }

    pub fn retrieve(&self, key: &AssetKey) -> Result<RcBytes, String> {
        let asset = self.get_asset(key)?;

        let id_enc = asset
            .encodings
            .get("identity")
            .ok_or_else(|| "no identity encoding".to_string())?;

        if id_enc.content_chunks.len() > 1 {
            return Err("Asset too large. Use get() and get_chunk() instead.".to_string());
        }

        Ok(id_enc.content_chunks[0].clone())
    }

    pub fn compute_state_hash(&mut self) -> ComputationStatus<String, (), ()> {
        if self.last_state_hash_timestamp != self.last_state_update_timestamp_ns {
            self.state_hash_computation = None;
            self.last_state_hash_timestamp = self.last_state_update_timestamp_ns;
        }

        if let Some(StateHashComputation::Computed(evidence)) = &self.state_hash_computation {
            return ComputationStatus::Done(hex::encode(evidence.as_slice()));
        }

        let ec = self
            .state_hash_computation
            .take()
            .unwrap_or_else(|| StateHashComputation::new(self));
        let ec = ec.advance(self);
        self.state_hash_computation = Some(ec);
        ComputationStatus::InProgress(())
    }

    pub fn get_state_info(&self) -> StateInfo {
        let state_hash =
            if let Some(StateHashComputation::Computed(evidence)) = &self.state_hash_computation {
                Some(hex::encode(evidence.as_slice()))
            } else {
                None
            };
        StateInfo {
            last_state_update_timestamp: self.last_state_update_timestamp_ns,
            state_hash,
        }
    }

    pub fn list_assets(&self, request: ListRequest) -> Vec<AssetDetails> {
        const PAGE_SIZE: usize = 100;

        let start_idx = request
            .start
            .and_then(|n| {
                let n_u64: u64 = n.0.try_into().ok()?;
                usize::try_from(n_u64).ok()
            })
            .unwrap_or(0);

        let page_size = request
            .length
            .and_then(|n| {
                let n_u64: u64 = n.0.try_into().ok()?;
                let n_usize = usize::try_from(n_u64).ok()?;
                Some(PAGE_SIZE.min(n_usize))
            })
            .unwrap_or(PAGE_SIZE);

        let mut sorted_keys: Vec<_> = self.assets.keys().collect();
        sorted_keys.sort();

        sorted_keys
            .into_iter()
            .skip(start_idx)
            .take(page_size)
            .filter_map(|key| {
                self.assets.get(key).map(|asset| {
                    let mut encodings: Vec<_> = asset
                        .encodings
                        .iter()
                        .map(|(enc_name, enc)| AssetEncodingDetails {
                            content_encoding: enc_name.clone(),
                            sha256: Some(ByteBuf::from(enc.sha256)),
                            length: Nat::from(enc.total_length),
                            modified: enc.modified.clone(),
                        })
                        .collect();
                    encodings.sort_by(|l, r| l.content_encoding.cmp(&r.content_encoding));

                    AssetDetails {
                        key: key.clone(),
                        content_type: asset.content_type.clone(),
                        encodings,
                        max_age: asset.max_age,
                        headers: asset.headers.clone(),
                    }
                })
            })
            .collect()
    }

    pub fn certified_tree(&self, certificate: &[u8]) -> CertifiedTree {
        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        self.asset_hashes
            .as_hash_tree()
            .serialize(&mut serializer)
            .unwrap();

        CertifiedTree {
            certificate: certificate.to_vec(),
            tree: serializer.into_inner(),
        }
    }

    pub fn get(&self, arg: GetArg) -> Result<EncodedAsset, String> {
        let asset = self.get_asset(&arg.key)?;

        for enc in arg.accept_encodings.iter() {
            if let Some(asset_enc) = asset.encodings.get(enc) {
                return Ok(EncodedAsset {
                    content: asset_enc.content_chunks[0].clone(),
                    content_type: asset.content_type.clone(),
                    content_encoding: enc.clone(),
                    total_length: Nat::from(asset_enc.total_length as u64),
                    sha256: Some(ByteBuf::from(asset_enc.sha256)),
                });
            }
        }
        Err("no such encoding".to_string())
    }

    pub fn get_chunk(&self, arg: GetChunkArg) -> Result<RcBytes, String> {
        let asset = self.get_asset(&arg.key)?;

        let enc = asset
            .encodings
            .get(&arg.content_encoding)
            .ok_or_else(|| "no such encoding".to_string())?;

        let expected_hash = arg.sha256.ok_or("sha256 required")?;
        if expected_hash != enc.sha256 {
            return Err("sha256 mismatch".to_string());
        }

        if arg.index >= enc.content_chunks.len() {
            return Err("chunk index out of bounds".to_string());
        }
        let index: usize = arg.index.0.to_usize().unwrap();

        Ok(enc.content_chunks[index].clone())
    }

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
        if let Ok(asset) = self.get_asset(&path.into()) {
            let (cert_header, _) = self.asset_hashes.witness_to_header(path, certificate);
            if let Some(response) = asset.build_http_response_for_encodings(
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
        for (idx, rule) in self.redirect_rules.iter().enumerate() {
            if !rule.matches(path) {
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
                let mut headers = rule.certified_headers();
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
                let Some(asset) = self.assets.get(target_key) else {
                    return HttpResponse::build_404(cert_header);
                };
                let status_override = (*status != 200).then_some(*status);
                asset
                    .build_http_response_for_encodings(
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
        let asset = self
            .get_asset(&key)
            .map_err(|_| "Invalid token on streaming: key not found.".to_string())?;
        let enc = asset
            .encodings
            .get(&content_encoding)
            .ok_or_else(|| "Invalid token on streaming: encoding not found.".to_string())?;

        let expected_hash = sha256.ok_or("sha256 required")?;
        if expected_hash != enc.sha256 {
            return Err("sha256 mismatch".to_string());
        }

        // MAX is good enough. This means a chunk would be above 64-bits, which is impossible...
        let chunk_index = index.0.to_usize().unwrap_or(usize::MAX);

        Ok(StreamingCallbackHttpResponse {
            body: enc.content_chunks[chunk_index].clone(),
            token: StreamingCallbackToken::create_token(
                &content_encoding,
                enc.content_chunks.len(),
                enc.sha256,
                &key,
                chunk_index,
            ),
        })
    }

    pub fn get_asset_properties(&self, key: AssetKey) -> Result<AssetProperties, String> {
        let asset = self
            .assets
            .get(&key)
            .ok_or_else(|| "asset not found".to_string())?;

        Ok(AssetProperties {
            max_age: asset.max_age,
            headers: asset.headers.clone(),
        })
    }

    pub fn set_asset_properties(&mut self, arg: SetAssetPropertiesArguments) -> Result<(), String> {
        let dependent_keys = self.dependent_keys(&arg.key);
        let asset = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        if let Some(headers) = arg.headers {
            asset.headers = headers
        }
        if let Some(max_age) = arg.max_age {
            asset.max_age = max_age
        }

        on_asset_change(&mut self.asset_hashes, &arg.key, asset, dependent_keys);

        Ok(())
    }

    // Returns keys that need to be updated if the supplied key is changed.
    //
    // The built-in aliasing this used to fan out to is gone; nothing pulls
    // sibling keys today. The hook is kept in the signature of
    // `on_asset_change` so a future feature can repopulate it without
    // touching all the call sites.
    pub(crate) fn dependent_keys(&self, _key: &AssetKey) -> Vec<AssetKey> {
        Vec::new()
    }

    pub fn get_redirect_rules(&self) -> Vec<crate::redirect::RedirectRule> {
        self.redirect_rules.clone()
    }

    /// Rebuild the certified-tree entries for `redirect_rules`. Called whenever
    /// the rule list changes (in `commit_batch`) or assets are restored from
    /// stable memory (in `From<StableState>`). Caller must refresh
    /// `certified_data` after this — `commit_batch` already does so via the
    /// `certified_data_set(s.root_hash())` it runs after each batch.
    ///
    /// Status-200 rules borrow each encoding's certificate expression and
    /// response hash from the target asset, so this also has to run after any
    /// asset change that could affect those values.
    pub(crate) fn on_redirect_rules_change(&mut self) {
        for entry in self.rule_certified_entries.drain(..).flatten() {
            for tp in &entry.tree_paths {
                self.asset_hashes.remove_response_precomputed(tp);
            }
        }

        let rules = self.redirect_rules.clone();
        let mut new_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>> =
            Vec::with_capacity(rules.len());
        for rule in &rules {
            new_entries.push(self.build_rule_entry(rule));
        }
        self.rule_certified_entries = new_entries;
    }

    fn build_rule_entry(
        &mut self,
        rule: &crate::redirect::RedirectRule,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        if let crate::redirect::RulePattern::Exact(src) = &rule.from {
            if self.assets.contains_key(src) {
                // Asset at the source path shadows the rule.
                return None;
            }
        }
        match rule.status {
            // 200 rewrites and 4xx custom error pages both borrow body +
            // headers from the target asset (4xx re-certifies with the
            // override status; see `build_alias_rule_entry`).
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
        let target = self.assets.get(&target_key)?;
        let location = rule.tree_location();
        let mut tree_paths = Vec::new();
        for (enc_name, enc) in &target.encodings {
            let Some(expr) = enc.certificate_expression.as_ref() else {
                continue;
            };
            let resp_hash = if status == 200 {
                // Borrow the asset's already-certified 200 response hash.
                let Some(h) = enc.response_hashes.as_ref().and_then(|m| m.get(&200)) else {
                    continue;
                };
                *h
            } else {
                // 4xx custom error page: re-certify with the override status
                // using the same headers and body the asset would serve at 200.
                let base_headers: Vec<(String, ic_representation_independent_hash::Value)> = target
                    .get_headers_for_asset(enc_name)
                    .into_iter()
                    .map(|(k, v)| (k, ic_representation_independent_hash::Value::String(v)))
                    .collect();
                crate::certification::response_hash(&base_headers, status, &enc.sha256).0
            };
            let tp = crate::redirect::alias_tree_path(&location, expr.expression_hash, resp_hash);
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

}

impl From<StableState> for State {
    fn from(stable_state: StableState) -> Self {
        let mut state = Self {
            authorized: stable_state.authorized,
            assets: stable_state
                .stable_assets
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            next_batch_id: stable_state
                .next_batch_id
                .map(BatchId::from)
                .unwrap_or_else(|| Nat::from(1_u8)),
            last_state_update_timestamp_ns: stable_state.last_state_update_timestamp.unwrap_or(0),
            redirect_rules: stable_state.redirect_rules.unwrap_or_default(),
            ..Self::default()
        };

        let assets_keys: Vec<_> = state.assets.keys().cloned().collect();
        for key in assets_keys {
            let dependent_keys = state.dependent_keys(&key);
            if let Some(asset) = state.assets.get_mut(&key) {
                for enc in asset.encodings.values_mut() {
                    enc.certified = false;
                }
                on_asset_change(&mut state.asset_hashes, &key, asset, dependent_keys);
            } else {
                // shouldn't reach this
            }
        }
        state.on_redirect_rules_change();
        state
    }
}
