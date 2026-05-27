//! Orchestrates: load assets, diff against canister, upload chunks, commit batch.
//!
//! V2-only port of `ic-asset`'s `sync` flow, simplified:
//! - synchronous (drives the host's sync `canister-call` import)
//! - uploads one chunk per `create_chunks` call (no client-side batching)
//! - no proposal mode

use candid::{Nat, Principal};
use mime::Mime;
use std::collections::HashMap;

use crate::canister::{
    api_version, commit_batch, create_batch, create_chunks, get_asset_properties,
    get_redirect_rules, grant_permission_via_proxy, list_assets, list_permitted, AssetDetails,
    AssetProperties, BatchOperationKind, CanisterCall, CommitBatchArguments, CreateAssetArguments,
    DeleteAssetArguments, Permission, RedirectRule, SetAssetContentArguments,
    SetAssetPropertiesArguments, SetRedirectRulesArguments, UnsetAssetContentArguments,
};
use crate::content::{encoders_for, Content, Encoder};
use crate::redirects::{self, REDIRECTS_FILENAME};
use crate::scan::AssetSource;
use std::path::Path;

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
    // The assets plugin owns the URL space of its canister: every key starts at
    // `/`, `_redirects` lives at the project root, and the canister has no
    // notion of "merge two trees together". Multiple input directories would
    // produce ambiguous redirect-file precedence and quietly hide key
    // collisions, so the contract is exactly one directory.
    let dir = match dirs {
        [d] => d,
        _ => {
            return Err(format!(
                "assets sync plugin: expected exactly one input directory, got {}",
                dirs.len()
            ))
        }
    };

    if let Some(_proxy) = proxy_canister_id {
        ensure_commit_permission(canister, identity_principal)?;
    }

    let version = api_version(canister)?;
    if version < 2 {
        return Err(format!(
            "assets canister api_version is {version}; this plugin requires V2"
        ));
    }
    println!("api_version: {version}");

    let sources = crate::scan::scan(dirs)?;
    println!("found {} file(s) from {:?}", sources.len(), dirs);

    let project_rules = load_redirect_rules(dir)?;
    println!(
        "parsed {} redirect rule(s) from _redirects",
        project_rules.len()
    );

    let canister_assets: HashMap<String, AssetDetails> = list_assets(canister)?
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();
    println!("canister currently has {} asset(s)", canister_assets.len());

    let canister_rules = get_redirect_rules(canister)?;
    println!(
        "canister currently has {} redirect rule(s)",
        canister_rules.len()
    );

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
        &project_rules,
        &canister_rules,
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

    for asset in project_assets.values_mut() {
        let key = asset.source.key.clone();
        for (encoding_name, enc) in &mut asset.encodings {
            if !enc.already_in_place {
                let data = std::mem::take(&mut enc.data);
                enc.chunk_ids = upload_chunks(canister, &batch_id, &key, encoding_name, &data)?;
            }
        }
    }

    let operations = build_operations(
        &project_assets,
        &canister_assets,
        &canister_asset_properties,
        &project_rules,
        &canister_rules,
    );
    println!("committing {} operation(s)", operations.len());

    commit_batch(
        canister,
        CommitBatchArguments {
            batch_id,
            operations,
        },
    )?;

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
    // gzip for text/* and js/html, identity for everything else.
    let encoders: Vec<Encoder> = encoders_for(&content.media_type);

    let mut encodings: HashMap<String, ProjectAssetEncoding> = HashMap::new();
    for encoder in encoders {
        let encoded = content.encode(encoder)?;
        // Identity is always uploaded. Alternate encodings only get uploaded if
        // they save bytes vs. identity.
        if encoder != Encoder::Identity && encoded.data.len() >= content.data.len() {
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

fn upload_chunks<C: CanisterCall>(
    canister: &C,
    batch_id: &Nat,
    key: &str,
    encoding: &str,
    data: &[u8],
) -> Result<Vec<Nat>, String> {
    if data.is_empty() {
        let ids = create_chunks(canister, batch_id, &[&[]])?;
        println!("  {key}{} 1/1 (0 bytes)", encoding_suffix(encoding));
        return Ok(ids);
    }
    let total = data.len().div_ceil(MAX_CHUNK_SIZE);
    let mut ids = Vec::with_capacity(total);
    for (i, chunk) in data.chunks(MAX_CHUNK_SIZE).enumerate() {
        let mut got = create_chunks(canister, batch_id, &[chunk])?;
        let id = got
            .pop()
            .ok_or_else(|| "create_chunks returned no chunk id".to_string())?;
        println!(
            "  {key}{} {}/{} ({} bytes)",
            encoding_suffix(encoding),
            i + 1,
            total,
            chunk.len()
        );
        ids.push(id);
    }
    Ok(ids)
}

fn encoding_suffix(encoding: &str) -> String {
    if encoding == "identity" {
        String::new()
    } else {
        format!(" ({encoding})")
    }
}

fn build_operations(
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    canister_asset_properties: &HashMap<String, AssetProperties>,
    project_rules: &[RedirectRule],
    canister_rules: &[RedirectRule],
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

    // 2. Create new assets (those not present after deletions). Per-asset
    //    properties (max_age, headers, allow_raw_access) come from defaults
    //    only — no project-side config source exists yet.
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            ops.push(BatchOperationKind::CreateAsset(CreateAssetArguments {
                key: key.clone(),
                content_type: pa.media_type.to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: Some(true),
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

    // 6. Replace-all the canister's redirect rules when they differ from the
    //    parsed `_redirects`. Comparison is order-sensitive — rules are
    //    matched in declaration order at request time, so reordering is a
    //    semantic change.
    if project_rules != canister_rules {
        ops.push(BatchOperationKind::SetRedirectRules(
            SetRedirectRulesArguments {
                rules: project_rules.to_vec(),
            },
        ));
    }

    ops
}

/// Reads `_redirects` from the project's input directory, if present. A
/// missing file is treated as "no rules"; parse errors carry the file's
/// path and 1-based line number so users can fix issues without a canister
/// round-trip.
fn load_redirect_rules(dir: &str) -> Result<Vec<RedirectRule>, String> {
    let path = Path::new(dir).join(REDIRECTS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    redirects::parse(&content).map_err(|e| format!("{}: {e}", path.display()))
}

// For each asset that already exists on the canister, reset any per-asset
// properties (`max_age`, `headers`, `allow_raw_access`) that drifted from the
// plugin's defaults. Newly-created assets get the same defaults via
// `CreateAssetArguments`, so we don't emit `SetAssetProperties` for them.
//
// `canister_assets` is the post-deletion view: keys removed in step 1 (missing
// from the project, or content_type drift forcing delete-then-create) are
// absent. Skipping those keys here avoids emitting a redundant
// `SetAssetProperties` op for an asset whose properties are already being set
// by `CreateAssetArguments` in this same batch.
fn update_properties(
    ops: &mut Vec<BatchOperationKind>,
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    canister_asset_properties: &HashMap<String, AssetProperties>,
) {
    for key in project_assets.keys() {
        if !canister_assets.contains_key(key) {
            continue;
        }
        let Some(canister_props) = canister_asset_properties.get(key) else {
            continue;
        };

        let max_age = canister_props.max_age.is_some().then_some(None);

        // The canister auto-injects `Set-Cookie: ic_env=…` on HTML assets via
        // `on_asset_change`; that header is runtime-managed, not project-managed,
        // so ignore it when checking for drift.
        let canister_has_user_headers = canister_props
            .headers
            .as_ref()
            .is_some_and(|h| h.keys().any(|k| !k.eq_ignore_ascii_case("set-cookie")));
        let headers = canister_has_user_headers.then_some(None);

        let allow_raw_access =
            (canister_props.allow_raw_access != Some(true)).then_some(Some(true));

        if max_age.is_some() || headers.is_some() || allow_raw_access.is_some() {
            ops.push(BatchOperationKind::SetAssetProperties(
                SetAssetPropertiesArguments {
                    key: key.clone(),
                    max_age,
                    headers,
                    allow_raw_access,
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
    use candid::{CandidType, Nat, Principal};
    use serde::de::DeserializeOwned;
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::path::PathBuf;

    // Mirrors the private CreateChunksResponse — same field name produces the same Candid encoding.
    #[derive(CandidType)]
    struct MockChunksResponse {
        chunk_ids: Vec<Nat>,
    }

    struct ChunkCounter(Cell<u32>);

    impl CanisterCall for ChunkCounter {
        fn call<A, R>(&self, method: &str, _arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "create_chunks");
            let id = self.0.get();
            self.0.set(id + 1);
            let bytes = candid::encode_one(MockChunksResponse {
                chunk_ids: vec![Nat::from(id)],
            })
            .map_err(|e| e.to_string())?;
            candid::decode_one(&bytes).map_err(|e| e.to_string())
        }
    }

    #[test]
    fn upload_chunks_empty_data_creates_one_chunk() {
        let mock = ChunkCounter(Cell::new(0));
        let ids = upload_chunks(&mock, &Nat::from(1u32), "/f", "identity", &[]).unwrap();
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn upload_chunks_small_data_creates_one_chunk() {
        let mock = ChunkCounter(Cell::new(0));
        let ids = upload_chunks(&mock, &Nat::from(1u32), "/f", "identity", &[0u8; 100]).unwrap();
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn upload_chunks_at_boundary_creates_one_chunk() {
        let mock = ChunkCounter(Cell::new(0));
        let ids = upload_chunks(
            &mock,
            &Nat::from(1u32),
            "/f",
            "identity",
            &[0u8; MAX_CHUNK_SIZE],
        )
        .unwrap();
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn upload_chunks_one_over_boundary_creates_two_chunks() {
        let mock = ChunkCounter(Cell::new(0));
        let ids = upload_chunks(
            &mock,
            &Nat::from(1u32),
            "/f",
            "identity",
            &[0u8; MAX_CHUNK_SIZE + 1],
        )
        .unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn upload_chunks_double_boundary_creates_two_chunks() {
        let mock = ChunkCounter(Cell::new(0));
        let ids = upload_chunks(
            &mock,
            &Nat::from(1u32),
            "/f",
            "identity",
            &[0u8; MAX_CHUNK_SIZE * 2],
        )
        .unwrap();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn upload_chunks_returns_sequential_ids() {
        let mock = ChunkCounter(Cell::new(7));
        // MAX_CHUNK_SIZE * 3 + 1 → div_ceil = 4 chunks.
        let ids = upload_chunks(
            &mock,
            &Nat::from(1u32),
            "/f",
            "identity",
            &[0u8; MAX_CHUNK_SIZE * 3 + 1],
        )
        .unwrap();
        assert_eq!(
            ids,
            vec![
                Nat::from(7u32),
                Nat::from(8u32),
                Nat::from(9u32),
                Nat::from(10u32),
            ]
        );
    }

    fn mk_project_asset(
        key: &str,
        media_type: &str,
        encodings: &[(&str, Vec<u8>, bool)],
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
        (
            key.to_string(),
            ProjectAsset {
                source: AssetSource {
                    path: PathBuf::from(key.trim_start_matches('/')),
                    key: key.to_string(),
                },
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

    #[test]
    fn new_asset_emits_create_and_set() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[]);
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
        assert!(build_operations(&project, &canister, &HashMap::new(), &[], &[]).is_empty());
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[]);
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
        let ops = build_operations(&HashMap::new(), &canister, &HashMap::new(), &[], &[]);
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[]);
        assert_eq!(count_op(&ops, "DeleteAsset"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn stale_encoding_emits_unset() {
        let sha = vec![1u8, 2, 3];
        // Project has only identity (already in place); gzip is stale on canister.
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[]);
        assert_eq!(count_op(&ops, "UnsetAssetContent"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 0);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn new_encoding_emits_set_content() {
        let identity_sha = vec![1u8, 2, 3];
        // Project gains a gzip encoding; identity is already in place.
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[
                ("identity", identity_sha.clone(), true),
                ("gzip", vec![9, 8, 7], false),
            ],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", Some(identity_sha))],
        )]);
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[]);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 0);
        assert_eq!(count_op(&ops, "UnsetAssetContent"), 0);
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
        let ops = build_operations(&HashMap::new(), &canister, &HashMap::new(), &[], &[]);
        assert_eq!(count_op(&ops, "DeleteAsset"), 2);
        assert_eq!(ops.len(), 2);
    }

    // ── redirect-rule diff ──────────────────────────────────────────────────

    fn mk_rule(from: crate::canister::RulePattern, to: &str, status: u16) -> RedirectRule {
        RedirectRule {
            from,
            to: to.to_string(),
            status,
            headers: None,
        }
    }

    fn set_rules_op(ops: &[BatchOperationKind]) -> Option<&[RedirectRule]> {
        ops.iter().find_map(|op| match op {
            BatchOperationKind::SetRedirectRules(args) => Some(args.rules.as_slice()),
            _ => None,
        })
    }

    #[test]
    fn rule_only_edit_emits_set_redirect_rules() {
        // No asset changes, but the project has a new rule the canister
        // doesn't — sync must emit the rules op.
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
        let project_rules = vec![mk_rule(
            crate::canister::RulePattern::Exact("/old".into()),
            "/new",
            301,
        )];
        let ops = build_operations(&project, &canister, &HashMap::new(), &project_rules, &[]);
        let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert_eq!(rules, project_rules.as_slice());
        // No asset-side ops should have been emitted.
        assert_eq!(count_op(&ops, "CreateAsset"), 0);
        assert_eq!(count_op(&ops, "SetAssetContent"), 0);
        assert_eq!(count_op(&ops, "DeleteAsset"), 0);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn redirects_file_removed_emits_empty_vec_op() {
        // Canister has rules, project no longer does — sync emits an
        // explicit empty-vec op so the canister clears its ruleset.
        let canister_rules = vec![mk_rule(
            crate::canister::RulePattern::Exact("/old".into()),
            "/new",
            301,
        )];
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &[],
            &canister_rules,
        );
        let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert!(rules.is_empty(), "expected empty-vec replace-all op");
    }

    #[test]
    fn unchanged_rules_emit_no_op() {
        // Same rules on both sides — no SetRedirectRules op emitted.
        let rules = vec![mk_rule(
            crate::canister::RulePattern::Subtree("/blog/".into()),
            "/blog/index.html",
            200,
        )];
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &rules,
            &rules,
        );
        assert!(
            set_rules_op(&ops).is_none(),
            "no SetRedirectRules op expected when rules match"
        );
        assert!(ops.is_empty());
    }

    #[test]
    fn reordered_rules_emit_op() {
        // Order matters semantically — first matching rule wins at request
        // time. A swap is a real change even with identical entries.
        let a = mk_rule(crate::canister::RulePattern::Exact("/a".into()), "/x", 301);
        let b = mk_rule(crate::canister::RulePattern::Exact("/b".into()), "/y", 301);
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &[a.clone(), b.clone()],
            &[b, a],
        );
        assert!(
            set_rules_op(&ops).is_some(),
            "rule reorder must emit a replace-all op"
        );
    }

    #[test]
    fn sync_short_circuits_when_redirects_file_only_matches_canister() {
        // Drive sync() end-to-end with a _redirects file that matches what
        // the canister already has. The "nothing to commit" short-circuit
        // must trigger, with no create_batch / commit_batch calls.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("_redirects"), b"/old /new 301\n").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_ok(
            "get_redirect_rules",
            vec![mk_rule(
                crate::canister::RulePattern::Exact("/old".into()),
                "/new",
                301,
            )],
        );

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        // No create_batch / commit_batch programmed — if sync reached them
        // SyncMock would panic with "no programmed response".
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    // Mirrors the private `CreateBatchResponse` in canister.rs — same field
    // name gives the same Candid encoding, so the test mock can decode it.
    #[derive(CandidType)]
    struct CreateBatchOk {
        batch_id: Nat,
    }

    #[test]
    fn sync_emits_rules_op_when_redirects_file_only_changed() {
        // _redirects has a rule; canister has none. The asset list is also
        // empty so no asset ops are produced — the only operation must be
        // SetRedirectRules, exercising the early "nothing to commit" check.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("_redirects"), b"/old /new 301\n").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());
        mock.push_ok(
            "create_batch",
            CreateBatchOk {
                batch_id: Nat::from(1u32),
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

    // prepare_asset itself skips gzip when the compressed output is not smaller
    // than the identity bytes. All 256 distinct byte values are maximally
    // incompressible: gzip's ~18-byte header alone exceeds the savings.
    #[test]
    fn prepare_asset_skips_gzip_when_not_smaller() {
        use std::io::Write;
        let mut f = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
        f.write_all(&(0u8..=255u8).collect::<Vec<u8>>()).unwrap();
        let source = AssetSource {
            path: f.path().to_path_buf(),
            key: "/test.txt".to_string(),
        };
        let asset = prepare_asset(source, &HashMap::new()).unwrap();
        assert!(
            asset.encodings.contains_key("identity"),
            "identity must be present"
        );
        assert!(
            !asset.encodings.contains_key("gzip"),
            "gzip must be absent when not smaller"
        );
    }

    // When gzip output is not smaller than identity, prepare_asset skips it, so
    // build_operations sees only the identity encoding and emits no gzip op.
    #[test]
    fn gzip_absent_from_project_emits_no_gzip_op() {
        let project = HashMap::from([mk_project_asset(
            "/tiny.txt",
            "text/plain",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[]);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert!(!ops.iter().any(|op| matches!(
            op,
            BatchOperationKind::SetAssetContent(a) if a.content_encoding == "gzip"
        )));
    }

    #[test]
    fn create_asset_args_use_defaults() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[]);
        let create_op = ops
            .iter()
            .find_map(|op| {
                if let BatchOperationKind::CreateAsset(a) = op {
                    Some(a)
                } else {
                    None
                }
            })
            .expect("CreateAsset op");

        assert_eq!(create_op.max_age, None);
        assert!(create_op.headers.is_none());
        assert_eq!(create_op.allow_raw_access, Some(true));
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
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props, &[], &[]);
        assert!(
            set_props_ops(&ops).is_empty(),
            "no SetAssetProperties op when canister already matches defaults"
        );
    }

    #[test]
    fn update_properties_clears_max_age_when_canister_has_it() {
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
                headers: None,
                allow_raw_access: Some(true),
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props, &[], &[]);
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        // canister has Some(60), defaults are None — the op must explicitly
        // request clearing (the inner None means "set to null on the canister").
        assert_eq!(by_key["/index.html"].max_age, Some(None));
    }

    #[test]
    fn update_properties_clears_canister_headers() {
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
        let mut canister_headers = HashMap::new();
        canister_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: Some(canister_headers),
                allow_raw_access: Some(true),
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props, &[], &[]);
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        // The inner None clears the headers map on the canister.
        assert_eq!(by_key["/index.html"].headers, Some(None));
    }

    #[test]
    fn update_properties_ignores_canister_managed_set_cookie() {
        // The canister auto-injects `Set-Cookie: ic_env=…` on HTML assets via
        // `on_asset_change`. Without filtering, a no-op re-sync of an HTML
        // asset would emit drift every time.
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
        let mut canister_headers = HashMap::new();
        canister_headers.insert(
            "Set-Cookie".to_string(),
            "ic_env=ic%5Froot%5Fkey%3D; SameSite=Lax".to_string(),
        );
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: Some(canister_headers),
                allow_raw_access: Some(true),
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props, &[], &[]);
        assert!(
            set_props_ops(&ops).is_empty(),
            "Set-Cookie is canister-managed and must not trigger drift",
        );
    }

    #[test]
    fn update_properties_skips_assets_being_recreated_due_to_content_type_drift() {
        // Asset on canister has a different content_type → step 1 deletes it
        // and step 2 recreates it with default properties. update_properties
        // must not emit a redundant SetAssetProperties op for that key, even
        // if canister_asset_properties still contains pre-deletion data.
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
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props, &[], &[]);
        assert_eq!(count_op(&ops, "DeleteAsset"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert!(
            set_props_ops(&ops).is_empty(),
            "no SetAssetProperties op when the asset is being recreated in the same batch"
        );
    }

    #[test]
    fn update_properties_skips_assets_not_on_canister() {
        // Asset is new to the canister — properties get set via CreateAsset,
        // not SetAssetProperties.
        let project = HashMap::from([mk_project_asset(
            "/new.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[]);
        assert!(set_props_ops(&ops).is_empty());
    }

    // ---- Authorization tests ----

    // Mock for ensure_commit_permission: handles list_permitted and grant_permission only.
    struct PermissionMock {
        permitted: Vec<Principal>,
        // Tracks the `direct` flag for each grant_permission call.
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

    // General-purpose scripted mock: pre-programs per-method response queues.
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

    // Proxy mode: identity absent from Commit list → grant_permission called via proxy.
    #[test]
    fn ensure_commit_permission_grants_via_proxy_when_absent() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(vec![]);
        ensure_commit_permission(&mock, &identity.to_text()).unwrap();
        // grant_permission must be called exactly once with direct=false (routed via proxy).
        assert_eq!(*mock.grant_calls.borrow(), vec![false]);
    }

    // Proxy mode: identity already in Commit list → grant_permission not called.
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
        assert!(
            err.contains("expected exactly one input directory"),
            "got: {err}"
        );
    }

    #[test]
    fn sync_rejects_multiple_input_dirs() {
        let mock = SyncMock::new();
        let err = sync(
            &mock,
            &["dist-a".to_string(), "dist-b".to_string()],
            &Principal::anonymous().to_text(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("got 2"), "got: {err}");
    }

    // Direct mode: canister rejects create_batch with a permission error → sync propagates it.
    #[test]
    fn sync_propagates_permission_error_from_create_batch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        // Empty canister → build_operations will produce work → create_batch is called.
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());
        mock.push_err("create_batch", "Caller does not have Commit permission");

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );

        let err = result.unwrap_err();
        assert!(
            err.contains("Commit permission"),
            "expected permission error, got: {err}"
        );
    }
}
