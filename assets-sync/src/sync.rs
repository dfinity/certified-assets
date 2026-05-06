//! Orchestrates: load assets, diff against canister, upload chunks, commit batch.
//!
//! V2-only port of `ic-asset`'s `sync` flow, simplified:
//! - synchronous (drives the host's sync `canister-call` import)
//! - uses `create_chunk` (one-chunk-per-call) — no batched `create_chunks`
//! - no `.ic-assets.json5` configs; new assets created with default properties
//! - no proposal mode; no security policy

use candid::{Nat, Principal};
use mime::Mime;
use std::collections::HashMap;

use crate::canister::{
    api_version, commit_batch, create_batch, create_chunk, grant_permission_via_proxy, list_assets,
    list_permitted, AssetDetails, BatchOperationKind, CanisterCall, CommitBatchArguments,
    CreateAssetArguments, DeleteAssetArguments, Permission, SetAssetContentArguments,
    UnsetAssetContentArguments,
};
use crate::content::{encoders_for, Content, Encoder};
use crate::scan::AssetSource;

// Stay safely under the canister's ingress message limit (~2 MB).
const MAX_CHUNK_SIZE: usize = 1_900_000;

struct ProjectAssetEncoding {
    chunk_ids: Vec<Nat>,
    sha256: Vec<u8>,
    already_in_place: bool,
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

    let canister_assets: HashMap<String, AssetDetails> = list_assets(canister)?
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();
    println!("canister currently has {} asset(s)", canister_assets.len());

    let batch_id = create_batch(canister)?;
    println!("created batch {batch_id}");

    let mut project_assets: HashMap<String, ProjectAsset> = HashMap::new();
    for source in sources {
        let asset = prepare_asset(canister, source, &canister_assets, &batch_id)?;
        project_assets.insert(asset.source.key.clone(), asset);
    }

    let operations = build_operations(&project_assets, &canister_assets);
    if operations.is_empty() {
        println!("canister is up to date, nothing to commit");
        return Ok(format!(
            "{} asset(s) already up to date",
            project_assets.len()
        ));
    }
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

fn prepare_asset<C: CanisterCall>(
    canister: &C,
    source: AssetSource,
    canister_assets: &HashMap<String, AssetDetails>,
    batch_id: &Nat,
) -> Result<ProjectAsset, String> {
    let content = Content::load(&source.path)?;
    let encoders = encoders_for(&content.media_type);
    // The identity encoding is always uploaded if it's in the encoders list.
    // Other encodings are only uploaded if they save bytes vs. identity.
    // If identity is absent, force the alternate encoding through.
    let force_encoding = !encoders.contains(&Encoder::Identity);

    let mut encodings: HashMap<String, ProjectAssetEncoding> = HashMap::new();
    for encoder in encoders {
        let encoded = content.encode(encoder)?;
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

        let chunk_ids = if already_in_place {
            println!(
                "  {}{} ({} bytes) sha {} already in place",
                source.key,
                encoding_suffix(&name),
                encoded.data.len(),
                hex::encode(&sha256)
            );
            Vec::new()
        } else {
            upload_chunks(canister, batch_id, &source.key, &name, &encoded.data)?
        };

        encodings.insert(
            name,
            ProjectAssetEncoding {
                chunk_ids,
                sha256,
                already_in_place,
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
        let id = create_chunk(canister, batch_id, &[])?;
        println!("  {key}{} 1/1 (0 bytes)", encoding_suffix(encoding));
        return Ok(vec![id]);
    }
    let total = data.len().div_ceil(MAX_CHUNK_SIZE);
    let mut ids = Vec::with_capacity(total);
    for (i, chunk) in data.chunks(MAX_CHUNK_SIZE).enumerate() {
        let id = create_chunk(canister, batch_id, chunk)?;
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

    // 2. Create new assets (those not present after deletions).
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            ops.push(BatchOperationKind::CreateAsset(CreateAssetArguments {
                key: key.clone(),
                content_type: pa.media_type.to_string(),
                max_age: None,
                headers: None,
                enable_aliasing: None,
                allow_raw_access: None,
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

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister::{AssetDetails, AssetEncodingDetails, BatchOperationKind};
    use candid::Nat;
    use std::collections::HashMap;
    use std::path::PathBuf;

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
        let ops = build_operations(&project, &HashMap::new());
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
        assert!(build_operations(&project, &canister).is_empty());
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
        let ops = build_operations(&project, &canister);
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
        let ops = build_operations(&HashMap::new(), &canister);
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
        let ops = build_operations(&project, &canister);
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
        let ops = build_operations(&project, &canister);
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
        let ops = build_operations(&project, &canister);
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
        let ops = build_operations(&HashMap::new(), &canister);
        assert_eq!(count_op(&ops, "DeleteAsset"), 2);
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn everything_in_sync_returns_empty() {
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
        assert!(build_operations(&project, &canister).is_empty());
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
        let ops = build_operations(&project, &HashMap::new());
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert!(!ops.iter().any(|op| matches!(
            op,
            BatchOperationKind::SetAssetContent(a) if a.content_encoding == "gzip"
        )));
    }
}
