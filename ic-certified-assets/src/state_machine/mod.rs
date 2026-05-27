//! This module contains a pure implementation of the certified assets state machine.

mod stable;

pub use stable::StableState;

// NB. This module should not depend on ic_cdk, it contains only pure state transition functions.
// All the environment (time, certificates, etc.) is passed to the state transition functions
// as formal arguments.  This approach makes it very easy to test the state machine.
use crate::{
    asset::{
        aliased_by, aliases_of, on_asset_change, Asset, AssetDetails, AssetEncoding,
        AssetEncodingDetails, EncodedAsset, DEFAULT_ALIAS_ENABLED,
    },
    batch::{Batch, Chunk, ComputationStatus},
    certification::{AssetKey, CertifiedResponses, WitnessResult},
    http::{
        CallbackFunc, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
        StreamingCallbackToken, FALLBACK_FILE,
    },
    rc_bytes::RcBytes,
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

#[derive(Clone, Debug, Default)]
pub struct Configuration {
    pub max_batches: Option<u64>,
    pub max_chunks: Option<u64>,
    pub max_bytes: Option<u64>,
}

#[derive(Default)]
pub struct State {
    pub(crate) assets: HashMap<AssetKey, Asset>,
    pub(crate) configuration: Configuration,

    pub(crate) chunks: HashMap<ChunkId, Chunk>,
    pub(crate) next_chunk_id: ChunkId,

    pub(crate) batches: HashMap<BatchId, Batch>,
    pub(crate) next_batch_id: BatchId,

    // permissions
    pub(crate) commit_principals: BTreeSet<Principal>,
    pub(crate) prepare_principals: BTreeSet<Principal>,
    pub(crate) manage_permissions_principals: BTreeSet<Principal>,

    pub(crate) asset_hashes: CertifiedResponses,

    pub(crate) encoded_canister_env: String,

    pub(crate) state_hash_computation: Option<StateHashComputation>,
    pub(crate) last_state_update_timestamp_ns: u64,
    pub(crate) last_state_hash_timestamp: u64,
}

impl State {
    fn get_asset(&self, key: &AssetKey) -> Result<&Asset, String> {
        self.assets
            .get(key)
            .or_else(|| {
                let aliased = aliases_of(key)
                    .into_iter()
                    .find_map(|alias_key| self.assets.get(&alias_key));
                if let Some(asset) = aliased {
                    if asset.is_aliased.unwrap_or(DEFAULT_ALIAS_ENABLED) {
                        aliased
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| "asset not found".to_string())
    }

    pub fn set_permissions(
        &mut self,
        SetPermissions {
            prepare,
            commit,
            manage_permissions,
        }: SetPermissions,
    ) {
        *self.get_mut_permission_list(&Permission::Prepare) = prepare.into_iter().collect();
        *self.get_mut_permission_list(&Permission::Commit) = commit.into_iter().collect();
        *self.get_mut_permission_list(&Permission::ManagePermissions) =
            manage_permissions.into_iter().collect();
    }

    pub fn grant_permission(&mut self, principal: Principal, permission: &Permission) {
        let permitted = self.get_mut_permission_list(permission);
        permitted.insert(principal);
    }

    pub fn revoke_permission(&mut self, principal: Principal, permission: &Permission) {
        let permitted = self.get_mut_permission_list(permission);
        permitted.remove(&principal);
    }

    pub fn list_permitted(&self, permission: &Permission) -> &BTreeSet<Principal> {
        self.get_permission_list(permission)
    }

    pub fn take_ownership(&mut self, controller: Principal) {
        self.commit_principals.clear();
        self.prepare_principals.clear();
        self.manage_permissions_principals.clear();
        self.commit_principals.insert(controller);
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
                is_aliased: arg.enable_aliasing,
                allow_raw_access: arg.allow_raw_access,
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

        on_asset_change(
            &mut self.asset_hashes,
            &arg.key,
            asset,
            dependent_keys,
            Some(&self.encoded_canister_env),
        );

        Ok(())
    }

    pub fn unset_asset_content(&mut self, arg: UnsetAssetContentArguments) -> Result<(), String> {
        let dependent_keys = self.dependent_keys(&arg.key);
        let asset = self
            .assets
            .get_mut(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        if asset.encodings.remove(&arg.content_encoding).is_some() {
            on_asset_change(
                &mut self.asset_hashes,
                &arg.key,
                asset,
                dependent_keys,
                None,
            );
        }

        Ok(())
    }

    pub fn delete_asset(&mut self, arg: DeleteAssetArguments) {
        if self.assets.contains_key(&arg.key) {
            for dependent in self.dependent_keys(&arg.key) {
                self.asset_hashes.remove_responses_for_path(&dependent);
                if dependent == FALLBACK_FILE {
                    self.asset_hashes.remove_fallback_responses();
                }
            }
            self.assets.remove(&arg.key);
        }
        for key in aliases_of(&arg.key) {
            // if an existing file can be aliased to the deleted file it has to become a valid alias again
            if self.assets.contains_key(&key) {
                let dependent_keys = self.dependent_keys(&key);
                if let Some(asset) = self.assets.get_mut(&key) {
                    on_asset_change(&mut self.asset_hashes, &key, asset, dependent_keys, None);
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.assets.clear();
        self.batches.clear();
        self.chunks.clear();
        self.next_batch_id = Nat::from(1_u8);
        self.next_chunk_id = Nat::from(1_u8);
    }

    pub fn has_permission(&self, principal: &Principal, permission: &Permission) -> bool {
        let list = self.get_permission_list(permission);
        list.contains(principal)
    }

    pub fn can(&self, principal: &Principal, permission: &Permission) -> bool {
        self.has_permission(principal, permission)
            || (*permission == Permission::Prepare
                && self.has_permission(principal, &Permission::Commit))
    }

    fn get_permission_list(&self, permission: &Permission) -> &BTreeSet<Principal> {
        match permission {
            Permission::Commit => &self.commit_principals,
            Permission::Prepare => &self.prepare_principals,
            Permission::ManagePermissions => &self.manage_permissions_principals,
        }
    }

    fn get_mut_permission_list(&mut self, permission: &Permission) -> &mut BTreeSet<Principal> {
        match permission {
            Permission::Commit => &mut self.commit_principals,
            Permission::Prepare => &mut self.prepare_principals,
            Permission::ManagePermissions => &mut self.manage_permissions_principals,
        }
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

    pub fn store(&mut self, arg: StoreArg, system_context: &SystemContext) -> Result<(), String> {
        let dependent_keys = self.dependent_keys(&arg.key);
        let asset = self.assets.entry(arg.key.clone()).or_default();
        asset.content_type = arg.content_type;
        asset.is_aliased = arg.aliased;

        let hash = sha2::Sha256::digest(&arg.content).into();
        if let Some(provided_hash) = arg.sha256 {
            if hash != provided_hash.as_ref() {
                return Err("sha256 mismatch".to_string());
            }
        }

        let encoding = asset.encodings.entry(arg.content_encoding).or_default();
        encoding.total_length = arg.content.len();
        encoding.content_chunks = vec![RcBytes::from(arg.content)];
        encoding.modified = Int::from(system_context.current_timestamp_ns);
        encoding.sha256 = hash;

        on_asset_change(
            &mut self.asset_hashes,
            &arg.key,
            asset,
            dependent_keys,
            Some(&self.encoded_canister_env),
        );
        self.last_state_update_timestamp_ns = system_context.current_timestamp_ns;

        Ok(())
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
                        allow_raw_access: asset.allow_raw_access,
                        is_aliased: asset.is_aliased,
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
        req: HttpRequest,
    ) -> HttpResponse {
        if let Ok(asset) = self.get_asset(&path.into()) {
            if !asset.allow_raw_access() && req.is_raw_domain() {
                return req.redirect_from_raw_to_certified_domain();
            }
        } else if let Ok(asset) = self.get_asset(&FALLBACK_FILE.to_string()) {
            if !asset.allow_raw_access() && req.is_raw_domain() {
                return req.redirect_from_raw_to_certified_domain();
            }
        }

        let (certificate_header, witness_result) =
            self.asset_hashes.witness_to_header(path, certificate);

        if witness_result == WitnessResult::FallbackFound {
            if let Ok(asset) = self.get_asset(&FALLBACK_FILE.to_string()) {
                if let Some(response) = asset.build_http_response_for_encodings(
                    &requested_encodings,
                    path,
                    chunk_index,
                    Some(&certificate_header),
                    &callback,
                    &etags,
                ) {
                    return response;
                }
            }
        } else if witness_result == WitnessResult::PathFound {
            if let Ok(asset) = self.get_asset(&path.into()) {
                if !asset.allow_raw_access() && req.is_raw_domain() {
                    return req.redirect_from_raw_to_certified_domain();
                }
                if let Some(response) = asset.build_http_response_for_encodings(
                    &requested_encodings,
                    path,
                    chunk_index,
                    Some(&certificate_header),
                    &callback,
                    &etags,
                ) {
                    return response;
                }
            }
        }
        HttpResponse::build_404(certificate_header)
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
            Ok(path) => {
                self.build_http_response(certificate, &path, encodings, 0, callback, etags, req)
            }
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
            allow_raw_access: asset.allow_raw_access,
            is_aliased: asset.is_aliased,
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
        if let Some(allow_raw_access) = arg.allow_raw_access {
            asset.allow_raw_access = allow_raw_access
        }

        if let Some(is_aliased) = arg.is_aliased {
            asset.is_aliased = is_aliased
        }

        on_asset_change(
            &mut self.asset_hashes,
            &arg.key,
            asset,
            dependent_keys,
            Some(&self.encoded_canister_env),
        );

        Ok(())
    }

    // Returns keys that needs to be updated if the supplied key is changed.
    pub(crate) fn dependent_keys(&self, key: &AssetKey) -> Vec<AssetKey> {
        if self
            .assets
            .get(key)
            .and_then(|asset| asset.is_aliased)
            .unwrap_or(DEFAULT_ALIAS_ENABLED)
        {
            aliased_by(key)
                .into_iter()
                .filter(|k| !self.assets.contains_key(k))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_configuration(&self) -> ConfigurationResponse {
        let max_batches = self.configuration.max_batches;
        let max_chunks = self.configuration.max_chunks;
        let max_bytes = self.configuration.max_bytes;
        ConfigurationResponse {
            max_batches,
            max_chunks,
            max_bytes,
        }
    }

    pub fn configure(&mut self, args: ConfigureArguments) {
        if let Some(max_batches) = args.max_batches {
            self.configuration.max_batches = max_batches;
        }
        if let Some(max_chunks) = args.max_chunks {
            self.configuration.max_chunks = max_chunks;
        }
        if let Some(max_bytes) = args.max_bytes {
            self.configuration.max_bytes = max_bytes;
        }
    }

}

impl From<StableState> for State {
    fn from(stable_state: StableState) -> Self {
        let (commit_principals, prepare_principals, manage_permissions_principals) =
            if let Some(permissions) = stable_state.permissions {
                (
                    permissions.commit,
                    permissions.prepare,
                    permissions.manage_permissions,
                )
            } else {
                (
                    stable_state.authorized.into_iter().collect(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                )
            };
        let mut state = Self {
            commit_principals,
            prepare_principals,
            manage_permissions_principals,
            assets: stable_state
                .stable_assets
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            next_batch_id: stable_state
                .next_batch_id
                .map(BatchId::from)
                .unwrap_or_else(|| Nat::from(1_u8)),
            configuration: stable_state
                .configuration
                .map(Into::into)
                .unwrap_or_default(),
            last_state_update_timestamp_ns: stable_state.last_state_update_timestamp.unwrap_or(0),
            ..Self::default()
        };

        let assets_keys: Vec<_> = state.assets.keys().cloned().collect();
        for key in assets_keys {
            let dependent_keys = state.dependent_keys(&key);
            if let Some(asset) = state.assets.get_mut(&key) {
                for enc in asset.encodings.values_mut() {
                    enc.certified = false;
                }
                // Do not pass the canister env here, because we want to load the assets as they are (with the old cookie value)
                on_asset_change(&mut state.asset_hashes, &key, asset, dependent_keys, None);
            } else {
                // shouldn't reach this
            }
        }
        state
    }
}

