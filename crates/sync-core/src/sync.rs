//! Orchestrates: load assets + `.ic-assets.json5` config, diff against the
//! legacy asset canister, upload chunks, commit batch.
//!
//! Port of `ic-asset`'s sync flow targeting the dfx 0.32.0 `assetstorage`
//! canister (`api_version == 2`), simplified:
//! - synchronous (drives the host's sync `canister-call` import),
//! - no proposal mode,
//! - no redirect rules / `_headers` / `_redirects` (the legacy canister has no
//!   `SetRedirectRules`); per-asset metadata comes from `.ic-assets.json5`.

use candid::{Nat, Principal};
use mime::Mime;
use std::collections::HashMap;

use crate::canister::{
    api_version, commit_batch, create_batch, create_chunks, get_asset_properties,
    grant_permission_via_proxy, list_assets, list_permitted, AssetDetails, AssetProperties,
    BatchOperationKind, CanisterCall, CommitBatchArguments, CreateAssetArguments,
    DeleteAssetArguments, Permission, SetAssetContentArguments, SetAssetPropertiesArguments,
    UnsetAssetContentArguments,
};
use crate::config::{AssetConfig, HeadersConfig};
use crate::content::{encoders_for, Content, Encoder};
use crate::scan::AssetSource;

// Stay safely under the canister's ingress message limit (~2 MB).
const MAX_CHUNK_SIZE: usize = 1_900_000;

struct ProjectAssetEncoding {
    chunk_ids: Vec<Nat>,
    sha256: Vec<u8>,
    already_in_place: bool,
    // Encoded bytes held until upload; empty when already_in_place or after upload.
    data: Vec<u8>,
}

struct ProjectAsset {
    source: AssetSource,
    media_type: Mime,
    encodings: HashMap<String, ProjectAssetEncoding>,
}

impl ProjectAsset {
    fn config(&self) -> &AssetConfig {
        &self.source.config
    }
}

/// Ensures the signing identity has `Commit` permission on the assets canister.
///
/// Called only in proxy mode. Queries the current `Commit` permission list and,
/// if the identity is absent, routes a `grant_permission` call through the proxy
/// canister. The proxy is the controller of the assets canister and can therefore
/// authorise the grant even without holding `ManagePermissions` explicitly.
fn ensure_commit_permission<C: CanisterCall>(
    canister: &C,
    identity_principal: &str,
) -> Result<(), String> {
    let principal = Principal::from_text(identity_principal)
        .map_err(|e| format!("invalid identity principal '{identity_principal}': {e}"))?;

    let permitted = list_permitted(canister, Permission::Commit)?;
    if permitted.contains(&principal) {
        println!("proxy mode: identity already has Commit permission");
        return Ok(());
    }

    println!("proxy mode: granting Commit permission to {identity_principal} via proxy");
    grant_permission_via_proxy(canister, principal, Permission::Commit)?;
    println!("proxy mode: Commit permission granted");
    Ok(())
}

pub fn sync<C: CanisterCall>(
    canister: &C,
    dirs: &[String],
    identity_principal: &str,
    proxy_canister_id: Option<&str>,
) -> Result<String, String> {
    if dirs.is_empty() {
        return Err("assets sync plugin: expected at least one input directory, got 0".to_string());
    }

    if proxy_canister_id.is_some() {
        ensure_commit_permission(canister, identity_principal)?;
    }

    let version = api_version(canister)?;
    if version < 2 {
        return Err(format!(
            "assets canister api_version is {version}; this plugin requires V2 (dfx 0.32.0 assetstorage)"
        ));
    }
    println!("api_version: {version}");

    let sources = crate::scan::scan(dirs)?;
    println!("found {} file(s) from {:?}", sources.len(), dirs);

    let canister_assets: HashMap<String, AssetDetails> = list_assets(canister)?
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();
    println!("canister currently has {} asset(s)", canister_assets.len());

    // Phase 1: compute metadata only — no batch created yet.
    let mut project_assets: HashMap<String, ProjectAsset> = HashMap::new();
    for source in sources {
        let asset = prepare_asset(source, &canister_assets)?;
        project_assets.insert(asset.source.key.clone(), asset);
    }

    // Fetch properties only for assets that will survive this sync (present in
    // both maps with matching content_type). Keys not in the project will be
    // deleted; keys with content_type drift will be deleted and recreated with
    // properties set via CreateAssetArguments. Either way, their current
    // properties don't influence the batch.
    let mut canister_asset_properties: HashMap<String, AssetProperties> = HashMap::new();
    for (key, ca) in &canister_assets {
        if let Some(pa) = project_assets.get(key) {
            if pa.media_type.to_string() == ca.content_type {
                let props = get_asset_properties(canister, key)?;
                canister_asset_properties.insert(key.clone(), props);
            }
        }
    }

    if build_operations(
        &project_assets,
        &canister_assets,
        &canister_asset_properties,
    )
    .is_empty()
    {
        println!("canister is up to date, nothing to commit");
        return Ok(format!(
            "{} asset(s) already up to date",
            project_assets.len()
        ));
    }

    // Phase 2: create batch and upload chunks for encodings not already in place.
    let batch_id = create_batch(canister)?;
    println!("created batch {batch_id}");

    pack_and_upload_chunks(canister, &batch_id, &mut project_assets)?;

    let operations = build_operations(
        &project_assets,
        &canister_assets,
        &canister_asset_properties,
    );
    println!("committing {} operation(s)", operations.len());

    commit_in_stages(canister, batch_id, operations)?;

    Ok(format!(
        "synced {} asset(s) to canister",
        project_assets.len()
    ))
}

fn prepare_asset(
    source: AssetSource,
    canister_assets: &HashMap<String, AssetDetails>,
) -> Result<ProjectAsset, String> {
    let content = Content::load(&source.path)?;

    // Per-asset `encodings` override from `.ic-assets.json5`, else the default
    // gzip-for-text policy. When identity is not in the list, `force_encoding`
    // keeps the alternate encoding even if it doesn't shrink the bytes (mirrors
    // ic-asset's plumbing).
    let encoders: Vec<Encoder> = source
        .config
        .encodings
        .clone()
        .unwrap_or_else(|| encoders_for(&content.media_type));
    let force_encoding = !encoders.contains(&Encoder::Identity);

    let mut encodings: HashMap<String, ProjectAssetEncoding> = HashMap::new();
    for encoder in encoders {
        let encoded = content.encode(encoder)?;
        // Identity is always uploaded. Alternate encodings only get uploaded if
        // they save bytes vs. identity, unless forced (no identity to compare).
        if encoder != Encoder::Identity
            && !force_encoding
            && encoded.data.len() >= content.data.len()
        {
            continue;
        }
        let name = encoder.name().to_string();
        let sha256 = encoded.sha256();
        let already_in_place = is_already_in_place(
            &source.key,
            &content.media_type,
            &name,
            &sha256,
            canister_assets,
        );

        if already_in_place {
            println!(
                "  {}{} ({} bytes) sha {} already in place",
                source.key,
                encoding_suffix(&name),
                encoded.data.len(),
                hex::encode(&sha256)
            );
        }

        encodings.insert(
            name,
            ProjectAssetEncoding {
                chunk_ids: Vec::new(),
                sha256,
                already_in_place,
                data: if already_in_place {
                    Vec::new()
                } else {
                    encoded.data
                },
            },
        );
    }

    Ok(ProjectAsset {
        media_type: content.media_type,
        source,
        encodings,
    })
}

fn is_already_in_place(
    key: &str,
    media_type: &Mime,
    encoding: &str,
    sha256: &[u8],
    canister_assets: &HashMap<String, AssetDetails>,
) -> bool {
    let Some(canister_asset) = canister_assets.get(key) else {
        return false;
    };
    if canister_asset.content_type != media_type.to_string() {
        return false;
    }
    canister_asset
        .encodings
        .iter()
        .find(|d| d.content_encoding == encoding)
        .and_then(|d| d.sha256.as_deref())
        .is_some_and(|s| s == sha256)
}

fn encoding_suffix(encoding: &str) -> String {
    if encoding == "identity" {
        String::new()
    } else {
        format!(" ({encoding})")
    }
}

/// Sorted `Vec` view of a `HeadersConfig` for the canister wire type. A
/// `BTreeMap` already iterates in key order, so this is sorted by header name.
fn headers_to_vec(h: HeadersConfig) -> Vec<(String, String)> {
    h.into_iter().collect()
}

/// The legacy canister injects a `Set-Cookie: ic_env=...` header into every
/// HTML asset's stored headers on each asset change (see ic-certified-assets'
/// `add_ic_env_cookie`, driven by icp-cli's env-var step). The canister
/// re-adds it automatically, so the plugin must not treat it as drift or try to
/// own it. Normalises a canister/project headers value for comparison by
/// dropping that cookie, sorting, and collapsing an empty map to `None`.
fn normalize_headers(headers: Option<Vec<(String, String)>>) -> Option<Vec<(String, String)>> {
    let mut v: Vec<(String, String)> = headers
        .unwrap_or_default()
        .into_iter()
        .filter(|(k, val)| !(k.eq_ignore_ascii_case("Set-Cookie") && val.starts_with("ic_env=")))
        .collect();
    v.sort();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Pack-and-upload pass: collect every chunk from every not-yet-uploaded
/// encoding across all assets, then ship them in `create_chunks` calls of up
/// to `MAX_CHUNK_SIZE` total bytes each.
///
/// Routing is by `(asset_key, encoding, chunk_index)`: each `PendingChunk`
/// remembers where its eventual canister id should land in
/// `enc.chunk_ids[chunk_index]`.
fn pack_and_upload_chunks<C: CanisterCall>(
    canister: &C,
    batch_id: &Nat,
    project_assets: &mut HashMap<String, ProjectAsset>,
) -> Result<(), String> {
    struct PendingChunk {
        asset_key: String,
        encoding: String,
        chunk_index: usize,
        data: Vec<u8>,
    }

    let mut pending: Vec<PendingChunk> = Vec::new();
    for asset in project_assets.values_mut() {
        let key = asset.source.key.clone();
        for (encoding_name, enc) in &mut asset.encodings {
            if enc.already_in_place {
                continue;
            }
            let data = std::mem::take(&mut enc.data);
            // Slice into MAX_CHUNK_SIZE-sized pieces. An empty encoding still
            // needs one zero-byte chunk so SetAssetContent has a chunk_id.
            let chunks: Vec<Vec<u8>> = if data.is_empty() {
                vec![Vec::new()]
            } else {
                data.chunks(MAX_CHUNK_SIZE).map(|c| c.to_vec()).collect()
            };
            enc.chunk_ids = vec![Nat::from(0u32); chunks.len()];
            for (i, chunk) in chunks.into_iter().enumerate() {
                pending.push(PendingChunk {
                    asset_key: key.clone(),
                    encoding: encoding_name.clone(),
                    chunk_index: i,
                    data: chunk,
                });
            }
        }
    }

    if pending.is_empty() {
        return Ok(());
    }

    // First-fit-decreasing: sort descending, then in each pass take every
    // chunk that still fits under MAX_CHUNK_SIZE.
    pending.sort_by_key(|b| std::cmp::Reverse(b.data.len()));

    let total_chunks = pending.len();
    let mut total_calls = 0usize;
    let mut total_bytes = 0u64;

    while !pending.is_empty() {
        let mut batch: Vec<PendingChunk> = Vec::new();
        let mut leftovers: Vec<PendingChunk> = Vec::new();
        let mut batch_size = 0usize;
        for chunk in std::mem::take(&mut pending) {
            if batch_size + chunk.data.len() <= MAX_CHUNK_SIZE {
                batch_size += chunk.data.len();
                batch.push(chunk);
            } else {
                leftovers.push(chunk);
            }
        }
        pending = leftovers;

        let chunk_refs: Vec<&[u8]> = batch.iter().map(|p| p.data.as_slice()).collect();
        let ids = create_chunks(canister, batch_id, &chunk_refs)?;
        if ids.len() != batch.len() {
            return Err(format!(
                "create_chunks returned {} ids for {} chunks",
                ids.len(),
                batch.len()
            ));
        }
        total_calls += 1;
        total_bytes += batch_size as u64;

        for (p, id) in batch.into_iter().zip(ids) {
            let asset = project_assets
                .get_mut(&p.asset_key)
                .expect("asset present (collected above)");
            let enc = asset
                .encodings
                .get_mut(&p.encoding)
                .expect("encoding present (collected above)");
            enc.chunk_ids[p.chunk_index] = id;
        }
    }

    println!("uploaded {total_chunks} chunk(s) in {total_calls} call(s) ({total_bytes} bytes)");
    Ok(())
}

/// Commits `operations` to the canister, splitting them across multiple
/// `commit_batch` ingress calls when a single payload would exceed the IC's
/// 2 MiB per-message ingress limit on application subnets.
///
/// Intermediate calls use `batch_id = 0` as a placeholder; the canister's
/// `commit_batch` consumes the `chunk_ids` referenced by `SetAssetContent` ops
/// and only removes the real `batch_id` entry at the end. The trailing call
/// uses the real `batch_id` with empty operations purely to release that entry.
fn commit_in_stages<C: CanisterCall>(
    canister: &C,
    batch_id: Nat,
    operations: Vec<BatchOperationKind>,
) -> Result<(), String> {
    let groups = create_commit_batches(operations);
    if groups.len() <= 1 {
        let ops = groups.into_iter().next().unwrap_or_default();
        return commit_batch(
            canister,
            CommitBatchArguments {
                batch_id,
                operations: ops,
            },
        );
    }
    let total = groups.len();
    for (i, ops) in groups.into_iter().enumerate() {
        println!(
            "committing group {}/{} ({} operation(s))",
            i + 1,
            total,
            ops.len()
        );
        commit_batch(
            canister,
            CommitBatchArguments {
                batch_id: Nat::from(0u32),
                operations: ops,
            },
        )?;
    }
    // Empty-ops commit on the real batch_id: the canister removes the batch entry.
    commit_batch(
        canister,
        CommitBatchArguments {
            batch_id,
            operations: vec![],
        },
    )
}

/// Splits `operations` into groups, each small enough that a single
/// `commit_batch` ingress call stays under the IC's 2 MiB per-message limit.
/// Budgets per group: 500 operations and 1.5 MiB of inlined header bytes.
fn create_commit_batches(operations: Vec<BatchOperationKind>) -> Vec<Vec<BatchOperationKind>> {
    const MAX_OPERATIONS_PER_GROUP: usize = 500;
    const MAX_HEADER_BYTES_PER_GROUP: usize = 1_500_000;

    let mut groups: Vec<Vec<BatchOperationKind>> = Vec::new();
    let mut current: Vec<BatchOperationKind> = Vec::new();
    let mut header_bytes: usize = 0;

    for op in operations {
        let op_header_bytes = header_bytes_of(&op);
        let would_overflow = current.len() >= MAX_OPERATIONS_PER_GROUP
            || header_bytes + op_header_bytes > MAX_HEADER_BYTES_PER_GROUP;
        if would_overflow && !current.is_empty() {
            groups.push(std::mem::take(&mut current));
            header_bytes = 0;
        }
        current.push(op);
        header_bytes += op_header_bytes;
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

/// Returns the total byte size of header name/value pairs inlined in `op`,
/// or 0 for op kinds that carry no header data.
fn header_bytes_of(op: &BatchOperationKind) -> usize {
    fn sum(headers: &[(String, String)]) -> usize {
        headers.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
    match op {
        BatchOperationKind::CreateAsset(a) => a.headers.as_deref().map_or(0, sum),
        BatchOperationKind::SetAssetProperties(a) => {
            a.headers.as_ref().and_then(|h| h.as_deref()).map_or(0, sum)
        }
        BatchOperationKind::Clear(_)
        | BatchOperationKind::DeleteAsset(_)
        | BatchOperationKind::UnsetAssetContent(_)
        | BatchOperationKind::SetAssetContent(_) => 0,
    }
}

fn build_operations(
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    canister_asset_properties: &HashMap<String, AssetProperties>,
) -> Vec<BatchOperationKind> {
    let mut ops = Vec::new();
    let mut canister_assets = canister_assets.clone();

    // 1. Delete obsolete assets, or assets whose content_type no longer matches.
    let mut to_remove = Vec::new();
    for (key, ca) in &canister_assets {
        let project = project_assets.get(key);
        let should_delete = match project {
            None => true,
            Some(pa) => pa.media_type.to_string() != ca.content_type,
        };
        if should_delete {
            ops.push(BatchOperationKind::DeleteAsset(DeleteAssetArguments {
                key: key.clone(),
            }));
            to_remove.push(key.clone());
        }
    }
    for k in to_remove {
        canister_assets.remove(&k);
    }

    // 2. Create new assets. Per-asset metadata comes from `.ic-assets.json5`.
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            let config = pa.config();
            let max_age = config.cache.as_ref().and_then(|c| c.max_age);
            let headers = config.combined_headers().map(headers_to_vec);
            ops.push(BatchOperationKind::CreateAsset(CreateAssetArguments {
                key: key.clone(),
                content_type: pa.media_type.to_string(),
                max_age,
                headers,
                enable_aliasing: config.enable_aliasing,
                allow_raw_access: config.allow_raw_access,
            }));
        }
    }

    // 3. Unset encodings that exist on the canister but not in the project.
    for (key, ca) in &canister_assets {
        if let Some(pa) = project_assets.get(key) {
            for enc in &ca.encodings {
                if !pa.encodings.contains_key(&enc.content_encoding) {
                    ops.push(BatchOperationKind::UnsetAssetContent(
                        UnsetAssetContentArguments {
                            key: key.clone(),
                            content_encoding: enc.content_encoding.clone(),
                        },
                    ));
                }
            }
        }
    }

    // 4. Set content for every encoding that wasn't already in place.
    for (key, pa) in project_assets {
        for (encoding, enc) in &pa.encodings {
            if enc.already_in_place {
                continue;
            }
            ops.push(BatchOperationKind::SetAssetContent(
                SetAssetContentArguments {
                    key: key.clone(),
                    content_encoding: encoding.clone(),
                    chunk_ids: enc.chunk_ids.clone(),
                    last_chunk: None,
                    sha256: Some(enc.sha256.clone()),
                },
            ));
        }
    }

    // 5. Update properties for assets that already exist on the canister and
    //    whose properties drifted from the project config.
    update_properties(
        &mut ops,
        project_assets,
        &canister_assets,
        canister_asset_properties,
    );

    ops
}

/// For each asset that already exists on the canister, reset any per-asset
/// properties (`max_age`, `headers`, `allow_raw_access`, `is_aliased`) that
/// drifted from the `.ic-assets.json5` config. Newly-created assets get the
/// same values via `CreateAssetArguments`, so we don't emit `SetAssetProperties`
/// for them. Mirrors `ic-asset`'s `update_properties`.
///
/// `canister_assets` is the post-deletion view: keys removed in step 1 are
/// absent, so we skip emitting a redundant op for a key being recreated.
fn update_properties(
    ops: &mut Vec<BatchOperationKind>,
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    canister_asset_properties: &HashMap<String, AssetProperties>,
) {
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            continue;
        }
        let Some(canister_props) = canister_asset_properties.get(key) else {
            continue;
        };
        let config = pa.config();

        let max_age = {
            let project = config.cache.as_ref().and_then(|c| c.max_age);
            (project != canister_props.max_age).then_some(project)
        };

        let headers = {
            let project = normalize_headers(config.combined_headers().map(headers_to_vec));
            let canister = normalize_headers(canister_props.headers.clone());
            (project != canister).then_some(project)
        };

        let is_aliased = {
            let project = config.enable_aliasing;
            (project != canister_props.is_aliased).then_some(project)
        };

        let allow_raw_access = {
            let project = config.allow_raw_access;
            (project != canister_props.allow_raw_access).then_some(project)
        };

        if max_age.is_some()
            || headers.is_some()
            || is_aliased.is_some()
            || allow_raw_access.is_some()
        {
            ops.push(BatchOperationKind::SetAssetProperties(
                SetAssetPropertiesArguments {
                    key: key.clone(),
                    max_age,
                    headers,
                    allow_raw_access,
                    is_aliased,
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister::{
        AssetDetails, AssetEncodingDetails, BatchOperationKind, CallType, CanisterCall,
    };
    use crate::config::{AssetConfig, CacheConfig};
    use candid::{CandidType, Nat, Principal};
    use serde::de::DeserializeOwned;
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::path::PathBuf;

    // Mirrors the private CreateChunksResponse — same field name produces the same Candid encoding.
    #[derive(CandidType)]
    struct MockChunksResponse {
        chunk_ids: Vec<Nat>,
    }

    // Counts each `create_chunks` call, returns one fresh id per chunk in the
    // request, and records the batch sizes the packer produced.
    struct ChunkBatchRecorder {
        next_id: Cell<u64>,
        batches: RefCell<Vec<usize>>, // chunks-per-batch
    }

    impl ChunkBatchRecorder {
        fn new() -> Self {
            Self {
                next_id: Cell::new(0),
                batches: RefCell::new(Vec::new()),
            }
        }
    }

    // Mirror of CreateChunksRequest so the mock can introspect arg.content.len().
    #[derive(CandidType, serde::Deserialize)]
    struct ChunksReqMirror {
        #[allow(dead_code)]
        batch_id: Nat,
        content: Vec<serde_bytes::ByteBuf>,
    }

    impl CanisterCall for ChunkBatchRecorder {
        fn call<A, R>(&self, method: &str, arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "create_chunks");
            let bytes = candid::encode_one(&arg).map_err(|e| e.to_string())?;
            let req: ChunksReqMirror = candid::decode_one(&bytes).map_err(|e| e.to_string())?;
            let n = req.content.len();
            self.batches.borrow_mut().push(n);
            let start = self.next_id.get();
            self.next_id.set(start + n as u64);
            let ids: Vec<Nat> = (0..n as u64).map(|i| Nat::from(start + i)).collect();
            let reply = candid::encode_one(MockChunksResponse { chunk_ids: ids })
                .map_err(|e| e.to_string())?;
            candid::decode_one(&reply).map_err(|e| e.to_string())
        }
    }

    fn mk_source(key: &str) -> AssetSource {
        AssetSource {
            path: PathBuf::from(key.trim_start_matches('/')),
            key: key.to_string(),
            config: AssetConfig::default(),
        }
    }

    fn mk_pending_asset(key: &str, encoding: &str, data: Vec<u8>) -> (String, ProjectAsset) {
        let mut enc_map = HashMap::new();
        enc_map.insert(
            encoding.to_string(),
            ProjectAssetEncoding {
                chunk_ids: Vec::new(),
                sha256: vec![0; 32],
                already_in_place: false,
                data,
            },
        );
        (
            key.to_string(),
            ProjectAsset {
                source: mk_source(key),
                media_type: "application/octet-stream".parse().unwrap(),
                encodings: enc_map,
            },
        )
    }

    #[test]
    fn pack_uploads_one_full_chunk_per_call() {
        let mut assets = HashMap::from([mk_pending_asset(
            "/f",
            "identity",
            vec![0u8; MAX_CHUNK_SIZE],
        )]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert_eq!(*mock.batches.borrow(), vec![1]);
        assert_eq!(assets["/f"].encodings["identity"].chunk_ids.len(), 1);
    }

    #[test]
    fn pack_splits_oversized_encoding_into_max_chunks() {
        let mut assets = HashMap::from([mk_pending_asset(
            "/big",
            "identity",
            vec![0u8; MAX_CHUNK_SIZE * 3 + 1],
        )]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert_eq!(*mock.batches.borrow(), vec![1, 1, 1, 1]);
        assert_eq!(assets["/big"].encodings["identity"].chunk_ids.len(), 4);
    }

    #[test]
    fn pack_collapses_many_small_chunks_into_one_call() {
        let mut assets: HashMap<String, ProjectAsset> = (0..100)
            .map(|i| mk_pending_asset(&format!("/f{i}"), "identity", vec![0u8; 1024]))
            .collect();
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert_eq!(*mock.batches.borrow(), vec![100]);
    }

    #[test]
    fn pack_routes_chunk_ids_to_correct_encoding_slot() {
        let mut assets = HashMap::from([
            mk_pending_asset("/a", "identity", vec![0u8; MAX_CHUNK_SIZE + 100]), // 2 chunks
            mk_pending_asset("/b", "identity", vec![0u8; 500]),                  // 1 chunk
        ]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        let a_ids = &assets["/a"].encodings["identity"].chunk_ids;
        let b_ids = &assets["/b"].encodings["identity"].chunk_ids;
        assert_eq!(a_ids.len(), 2);
        assert_eq!(b_ids.len(), 1);
        let mut all: Vec<String> = a_ids
            .iter()
            .chain(b_ids.iter())
            .map(|n| n.to_string())
            .collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 3, "ids must be distinct");
    }

    #[test]
    fn pack_empty_encoding_still_gets_one_chunk_id() {
        let mut assets = HashMap::from([mk_pending_asset("/empty", "identity", vec![])]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert_eq!(assets["/empty"].encodings["identity"].chunk_ids.len(), 1);
    }

    #[test]
    fn pack_skips_already_in_place_encodings() {
        let (k, mut pa) = mk_pending_asset("/skip", "identity", vec![0u8; 100]);
        pa.encodings.get_mut("identity").unwrap().already_in_place = true;
        pa.encodings.get_mut("identity").unwrap().data = Vec::new();
        let mut assets = HashMap::from([(k, pa)]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert!(mock.batches.borrow().is_empty());
    }

    // ── commit_batch splitting ──────────────────────────────────────────────

    fn create_asset_with_headers(key: &str, hdr_bytes: usize) -> BatchOperationKind {
        let name = "X-Pad".to_string();
        let value = "a".repeat(hdr_bytes.saturating_sub(name.len()));
        BatchOperationKind::CreateAsset(CreateAssetArguments {
            key: key.to_string(),
            content_type: "text/plain".to_string(),
            max_age: None,
            headers: Some(vec![(name, value)]),
            enable_aliasing: None,
            allow_raw_access: Some(true),
        })
    }

    fn set_content_op(key: &str) -> BatchOperationKind {
        BatchOperationKind::SetAssetContent(SetAssetContentArguments {
            key: key.to_string(),
            content_encoding: "identity".to_string(),
            chunk_ids: vec![Nat::from(0u32)],
            last_chunk: None,
            sha256: Some(vec![0u8; 32]),
        })
    }

    #[test]
    fn header_bytes_of_counts_create_asset_headers() {
        let op = create_asset_with_headers("/k", 1000);
        assert_eq!(header_bytes_of(&op), 1000);
    }

    #[test]
    fn header_bytes_of_counts_set_asset_properties_headers() {
        let op = BatchOperationKind::SetAssetProperties(SetAssetPropertiesArguments {
            key: "/k".to_string(),
            max_age: None,
            headers: Some(Some(vec![("X-A".into(), "1".into())])), // 4 bytes
            allow_raw_access: None,
            is_aliased: None,
        });
        assert_eq!(header_bytes_of(&op), 4);
    }

    #[test]
    fn header_bytes_of_returns_zero_for_headerless_kinds() {
        assert_eq!(header_bytes_of(&set_content_op("/k")), 0);
        assert_eq!(
            header_bytes_of(&BatchOperationKind::DeleteAsset(DeleteAssetArguments {
                key: "/k".to_string(),
            })),
            0
        );
    }

    #[test]
    fn create_commit_batches_splits_at_500_ops() {
        let ops: Vec<BatchOperationKind> = (0..1200)
            .map(|i| set_content_op(&format!("/f{i}")))
            .collect();
        let groups = create_commit_batches(ops);
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![500, 500, 200]
        );
    }

    #[test]
    fn create_commit_batches_splits_at_header_budget() {
        let ops: Vec<BatchOperationKind> = (0..4)
            .map(|i| create_asset_with_headers(&format!("/f{i}"), 500_000))
            .collect();
        let groups = create_commit_batches(ops);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 3);
        assert_eq!(groups[1].len(), 1);
    }

    // Records every commit_batch call's (batch_id, op_count).
    struct CommitRecorder {
        calls: RefCell<Vec<(Nat, usize)>>,
    }

    impl CommitRecorder {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    #[derive(CandidType, serde::Deserialize)]
    struct CommitArgsMirror {
        batch_id: Nat,
        operations: Vec<candid::Reserved>,
    }

    impl CanisterCall for CommitRecorder {
        fn call<A, R>(&self, method: &str, arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "commit_batch");
            let bytes = candid::encode_one(&arg).map_err(|e| e.to_string())?;
            let req: CommitArgsMirror = candid::decode_one(&bytes).map_err(|e| e.to_string())?;
            self.calls
                .borrow_mut()
                .push((req.batch_id, req.operations.len()));
            let reply = candid::encode_one(()).map_err(|e| e.to_string())?;
            candid::decode_one(&reply).map_err(|e| e.to_string())
        }
    }

    #[test]
    fn commit_in_stages_single_group_uses_real_batch_id() {
        let ops: Vec<BatchOperationKind> =
            (0..10).map(|i| set_content_op(&format!("/f{i}"))).collect();
        let mock = CommitRecorder::new();
        commit_in_stages(&mock, Nat::from(42u32), ops).unwrap();
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (Nat::from(42u32), 10));
    }

    #[test]
    fn commit_in_stages_multi_group_uses_placeholder_then_real_cleanup() {
        let ops: Vec<BatchOperationKind> = (0..1200)
            .map(|i| set_content_op(&format!("/f{i}")))
            .collect();
        let mock = CommitRecorder::new();
        commit_in_stages(&mock, Nat::from(42u32), ops).unwrap();
        let calls = mock.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                (Nat::from(0u32), 500),
                (Nat::from(0u32), 500),
                (Nat::from(0u32), 200),
                (Nat::from(42u32), 0),
            ]
        );
    }

    // ── build_operations ────────────────────────────────────────────────────

    fn mk_project_asset(
        key: &str,
        media_type: &str,
        encodings: &[(&str, Vec<u8>, bool)],
    ) -> (String, ProjectAsset) {
        mk_project_asset_cfg(key, media_type, encodings, AssetConfig::default())
    }

    fn mk_project_asset_cfg(
        key: &str,
        media_type: &str,
        encodings: &[(&str, Vec<u8>, bool)],
        config: AssetConfig,
    ) -> (String, ProjectAsset) {
        let mime: mime::Mime = media_type.parse().expect("valid MIME");
        let mut enc_map = HashMap::new();
        for (name, sha, already_in_place) in encodings {
            let chunk_ids = if *already_in_place {
                vec![]
            } else {
                vec![Nat::from(1u32)]
            };
            enc_map.insert(
                name.to_string(),
                ProjectAssetEncoding {
                    chunk_ids,
                    sha256: sha.clone(),
                    already_in_place: *already_in_place,
                    data: vec![],
                },
            );
        }
        let mut source = mk_source(key);
        source.config = config;
        (
            key.to_string(),
            ProjectAsset {
                source,
                media_type: mime,
                encodings: enc_map,
            },
        )
    }

    fn mk_canister_asset(
        key: &str,
        content_type: &str,
        encodings: &[(&str, Option<Vec<u8>>)],
    ) -> (String, AssetDetails) {
        let encs = encodings
            .iter()
            .map(|(enc, sha)| AssetEncodingDetails {
                content_encoding: enc.to_string(),
                sha256: sha.clone(),
            })
            .collect();
        (
            key.to_string(),
            AssetDetails {
                key: key.to_string(),
                encodings: encs,
                content_type: content_type.to_string(),
            },
        )
    }

    fn count_op(ops: &[BatchOperationKind], kind: &str) -> usize {
        ops.iter()
            .filter(|op| {
                matches!(
                    (op, kind),
                    (BatchOperationKind::DeleteAsset(_), "DeleteAsset")
                        | (BatchOperationKind::CreateAsset(_), "CreateAsset")
                        | (BatchOperationKind::SetAssetContent(_), "SetAssetContent")
                        | (
                            BatchOperationKind::UnsetAssetContent(_),
                            "UnsetAssetContent"
                        )
                )
            })
            .count()
    }

    fn create_op(ops: &[BatchOperationKind]) -> &CreateAssetArguments {
        ops.iter()
            .find_map(|op| match op {
                BatchOperationKind::CreateAsset(a) => Some(a),
                _ => None,
            })
            .expect("CreateAsset op")
    }

    fn set_props_ops(
        ops: &[BatchOperationKind],
    ) -> std::collections::BTreeMap<&str, &SetAssetPropertiesArguments> {
        ops.iter()
            .filter_map(|op| match op {
                BatchOperationKind::SetAssetProperties(a) => Some((a.key.as_str(), a)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn new_asset_emits_create_and_set() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new());
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn unchanged_asset_emits_no_ops() {
        let sha = vec![1u8, 2, 3];
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", sha.clone(), true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(sha))],
        )]);
        assert!(build_operations(&project, &canister, &HashMap::new()).is_empty());
    }

    #[test]
    fn updated_asset_emits_set_no_create() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![4, 5, 6], false)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let ops = build_operations(&project, &canister, &HashMap::new());
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 0);
        assert_eq!(count_op(&ops, "DeleteAsset"), 0);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn deleted_asset_emits_delete() {
        let canister = HashMap::from([mk_canister_asset(
            "/old.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let ops = build_operations(&HashMap::new(), &canister, &HashMap::new());
        assert_eq!(count_op(&ops, "DeleteAsset"), 1);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn content_type_mismatch_emits_delete_create_set() {
        let project = HashMap::from([mk_project_asset(
            "/file",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/file",
            "application/octet-stream",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let ops = build_operations(&project, &canister, &HashMap::new());
        assert_eq!(count_op(&ops, "DeleteAsset"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn stale_encoding_emits_unset() {
        let sha = vec![1u8, 2, 3];
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", sha.clone(), true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(sha)), ("gzip", Some(vec![9, 8, 7]))],
        )]);
        let ops = build_operations(&project, &canister, &HashMap::new());
        assert_eq!(count_op(&ops, "UnsetAssetContent"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 0);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn empty_project_deletes_all_canister_assets() {
        let canister = HashMap::from([
            mk_canister_asset("/a.html", "text/html", &[("identity", Some(vec![1]))]),
            mk_canister_asset(
                "/b.js",
                "application/javascript",
                &[("identity", Some(vec![2]))],
            ),
        ]);
        let ops = build_operations(&HashMap::new(), &canister, &HashMap::new());
        assert_eq!(count_op(&ops, "DeleteAsset"), 2);
        assert_eq!(ops.len(), 2);
    }

    // ── config-driven create / properties ───────────────────────────────────

    fn config_with(
        max_age: Option<u64>,
        headers: Option<&[(&str, &str)]>,
        enable_aliasing: Option<bool>,
        allow_raw_access: Option<bool>,
    ) -> AssetConfig {
        AssetConfig {
            cache: max_age.map(|m| CacheConfig { max_age: Some(m) }),
            headers: headers.map(|hs| {
                hs.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>()
            }),
            enable_aliasing,
            allow_raw_access,
            ..AssetConfig::default()
        }
    }

    #[test]
    fn create_asset_args_use_defaults() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new());
        let create = create_op(&ops);
        assert_eq!(create.max_age, None);
        assert!(create.headers.is_none());
        assert_eq!(create.enable_aliasing, None);
        assert_eq!(create.allow_raw_access, Some(true));
    }

    #[test]
    fn create_asset_args_carry_config() {
        let config = config_with(
            Some(99),
            Some(&[("X-Frame-Options", "DENY")]),
            Some(true),
            Some(false),
        );
        let project = HashMap::from([mk_project_asset_cfg(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
            config,
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new());
        let create = create_op(&ops);
        assert_eq!(create.max_age, Some(99));
        assert_eq!(
            create.headers,
            Some(vec![("X-Frame-Options".into(), "DENY".into())])
        );
        assert_eq!(create.enable_aliasing, Some(true));
        assert_eq!(create.allow_raw_access, Some(false));
    }

    #[test]
    fn create_asset_args_inject_security_policy_headers() {
        let config = AssetConfig {
            security_policy: Some(crate::security_policy::SecurityPolicy::Standard),
            ..AssetConfig::default()
        };
        let project = HashMap::from([mk_project_asset_cfg(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
            config,
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new());
        let create = create_op(&ops);
        let headers = create.headers.as_ref().expect("policy headers");
        assert!(headers.iter().any(|(k, _)| k == "Content-Security-Policy"));
    }

    #[test]
    fn update_properties_emits_nothing_when_canister_matches_defaults() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: None,
                allow_raw_access: Some(true),
                is_aliased: None,
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props);
        assert!(set_props_ops(&ops).is_empty());
    }

    #[test]
    fn update_properties_sets_aliasing_and_headers() {
        let config = config_with(
            None,
            Some(&[("X-Frame-Options", "DENY")]),
            Some(true),
            Some(true),
        );
        let project = HashMap::from([mk_project_asset_cfg(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
            config,
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: None,
                allow_raw_access: Some(true),
                is_aliased: Some(false),
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props);
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        let op = by_key["/index.html"];
        assert_eq!(
            op.headers,
            Some(Some(vec![("X-Frame-Options".into(), "DENY".into())]))
        );
        assert_eq!(op.is_aliased, Some(Some(true)));
        // allow_raw_access matches (both Some(true)) → not set; max_age matches → not set.
        assert_eq!(op.allow_raw_access, None);
        assert_eq!(op.max_age, None);
    }

    #[test]
    fn update_properties_clears_canister_headers_and_max_age() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: Some(60),
                headers: Some(vec![("X-Frame-Options".into(), "DENY".into())]),
                allow_raw_access: Some(true),
                is_aliased: None,
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props);
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert_eq!(by_key["/index.html"].max_age, Some(None));
        assert_eq!(by_key["/index.html"].headers, Some(None));
    }

    #[test]
    fn update_properties_ignores_canister_injected_env_cookie() {
        // The legacy canister injects `Set-Cookie: ic_env=...` into HTML assets'
        // headers. A project with no header config must not see this as drift,
        // otherwise every sync would emit a (futile) clear op.
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: Some(vec![(
                    "Set-Cookie".into(),
                    "ic_env=deadbeef; SameSite=Lax".into(),
                )]),
                allow_raw_access: Some(true),
                is_aliased: None,
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props);
        assert!(
            set_props_ops(&ops).is_empty(),
            "the canister-injected ic_env cookie must not count as header drift"
        );
    }

    #[test]
    fn update_properties_keeps_config_headers_alongside_env_cookie() {
        // Project defines X-Custom; canister stores X-Custom plus the injected
        // ic_env cookie. After stripping the cookie the two match → no op.
        let config = config_with(None, Some(&[("X-Custom", "yes")]), None, Some(true));
        let project = HashMap::from([mk_project_asset_cfg(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
            config,
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: Some(vec![
                    ("Set-Cookie".into(), "ic_env=abc; SameSite=Lax".into()),
                    ("X-Custom".into(), "yes".into()),
                ]),
                allow_raw_access: Some(true),
                is_aliased: None,
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props);
        assert!(set_props_ops(&ops).is_empty());
    }

    #[test]
    fn update_properties_skips_assets_being_recreated_due_to_content_type_drift() {
        let project = HashMap::from([mk_project_asset(
            "/file",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/file",
            "application/octet-stream",
            &[("identity", Some(vec![1, 2, 3]))],
        )]);
        let canister_props = HashMap::from([(
            "/file".to_string(),
            AssetProperties {
                max_age: Some(60),
                headers: None,
                allow_raw_access: Some(true),
                is_aliased: None,
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props);
        assert_eq!(count_op(&ops, "DeleteAsset"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert!(set_props_ops(&ops).is_empty());
    }

    // ── prepare_asset ────────────────────────────────────────────────────────

    #[test]
    fn prepare_asset_skips_gzip_when_not_smaller() {
        use std::io::Write;
        let mut f = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
        f.write_all(&(0u8..=255u8).collect::<Vec<u8>>()).unwrap();
        let mut source = mk_source("/test.txt");
        source.path = f.path().to_path_buf();
        let asset = prepare_asset(source, &HashMap::new()).unwrap();
        assert!(asset.encodings.contains_key("identity"));
        assert!(!asset.encodings.contains_key("gzip"));
    }

    #[test]
    fn prepare_asset_honors_config_encodings() {
        use std::io::Write;
        // A .wasm file defaults to identity-only, but config forces gzip too.
        let mut f = tempfile::Builder::new().suffix(".wasm").tempfile().unwrap();
        f.write_all(b"hello hello hello hello hello hello".repeat(10).as_ref())
            .unwrap();
        let mut source = mk_source("/mod.wasm");
        source.path = f.path().to_path_buf();
        source.config.encodings = Some(vec![Encoder::Identity, Encoder::Gzip]);
        let asset = prepare_asset(source, &HashMap::new()).unwrap();
        assert!(asset.encodings.contains_key("identity"));
        assert!(asset.encodings.contains_key("gzip"));
    }

    // ── authorization ────────────────────────────────────────────────────────

    struct PermissionMock {
        permitted: Vec<Principal>,
        grant_calls: RefCell<Vec<bool>>,
    }

    impl PermissionMock {
        fn new(permitted: Vec<Principal>) -> Self {
            Self {
                permitted,
                grant_calls: RefCell::new(vec![]),
            }
        }
    }

    impl CanisterCall for PermissionMock {
        fn call<A, R>(&self, method: &str, _arg: A, _: CallType, direct: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            match method {
                "list_permitted" => {
                    let bytes =
                        candid::encode_one(self.permitted.clone()).map_err(|e| e.to_string())?;
                    candid::decode_one(&bytes).map_err(|e| e.to_string())
                }
                "grant_permission" => {
                    self.grant_calls.borrow_mut().push(direct);
                    let bytes = candid::encode_one(()).map_err(|e| e.to_string())?;
                    candid::decode_one(&bytes).map_err(|e| e.to_string())
                }
                _ => panic!("unexpected method: {method}"),
            }
        }
    }

    type MockQueue = RefCell<HashMap<String, VecDeque<Result<Vec<u8>, String>>>>;

    struct SyncMock {
        queue: MockQueue,
    }

    impl SyncMock {
        fn new() -> Self {
            Self {
                queue: RefCell::new(HashMap::new()),
            }
        }

        fn push_ok<R: CandidType>(&self, method: &str, value: R) {
            self.queue
                .borrow_mut()
                .entry(method.to_string())
                .or_default()
                .push_back(Ok(candid::encode_one(value).unwrap()));
        }

        fn push_err(&self, method: &str, err: &str) {
            self.queue
                .borrow_mut()
                .entry(method.to_string())
                .or_default()
                .push_back(Err(err.to_string()));
        }
    }

    impl CanisterCall for SyncMock {
        fn call<A, R>(&self, method: &str, _arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            let response = self
                .queue
                .borrow_mut()
                .entry(method.to_string())
                .or_default()
                .pop_front()
                .unwrap_or_else(|| panic!("no programmed response for '{method}'"));
            match response {
                Ok(bytes) => candid::decode_one(&bytes).map_err(|e| e.to_string()),
                Err(e) => Err(e),
            }
        }
    }

    #[derive(CandidType)]
    struct CreateBatchOk {
        batch_id: Nat,
    }

    #[test]
    fn ensure_commit_permission_grants_via_proxy_when_absent() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(vec![]);
        ensure_commit_permission(&mock, &identity.to_text()).unwrap();
        assert_eq!(*mock.grant_calls.borrow(), vec![false]);
    }

    #[test]
    fn ensure_commit_permission_skips_grant_when_already_permitted() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(vec![identity]);
        ensure_commit_permission(&mock, &identity.to_text()).unwrap();
        assert!(mock.grant_calls.borrow().is_empty());
    }

    #[test]
    fn sync_rejects_zero_input_dirs() {
        let mock = SyncMock::new();
        let err = sync(&mock, &[], &Principal::anonymous().to_text(), None).unwrap_err();
        assert!(err.contains("at least one input directory"), "got: {err}");
    }

    #[test]
    fn sync_short_circuits_when_config_only_matches_canister() {
        // The canister already stores the headers a `.ic-assets.json5`-only
        // project would resolve. The "nothing to commit" short-circuit triggers.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"hello").unwrap();
        std::fs::write(
            dir.path().join(".ic-assets.json5"),
            br#"[{ "match": "*", "headers": { "X-Frame-Options": "DENY" } }]"#,
        )
        .unwrap();

        use sha2::Digest;
        let identity_sha = sha2::Sha256::digest(b"hello").to_vec();

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        mock.push_ok(
            "list",
            vec![AssetDetails {
                key: "/notes.txt".to_string(),
                content_type: "text/plain".to_string(),
                encodings: vec![AssetEncodingDetails {
                    content_encoding: "identity".to_string(),
                    sha256: Some(identity_sha),
                }],
            }],
        );
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_ok(
            "get_asset_properties",
            AssetProperties {
                max_age: None,
                headers: Some(vec![("X-Frame-Options".into(), "DENY".into())]),
                allow_raw_access: Some(true),
                is_aliased: None,
            },
        );

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        // No create_batch / commit_batch programmed — would panic if reached.
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    #[test]
    fn sync_uploads_new_asset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_ok(
            "create_batch",
            CreateBatchOk {
                batch_id: Nat::from(1u32),
            },
        );
        mock.push_ok(
            "create_chunks",
            MockChunksResponse {
                chunk_ids: vec![Nat::from(0u32)],
            },
        );
        mock.push_ok("commit_batch", ());

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    #[test]
    fn sync_propagates_permission_error_from_create_batch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_err("create_batch", "Caller does not have Commit permission");

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        let err = result.unwrap_err();
        assert!(err.contains("Commit permission"), "got: {err}");
    }
}
