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

use crate::call;
use crate::content::{default_encoders, Content, ContentEncoder};
use crate::gather::AssetDescriptor;
use crate::types::{
    AssetDetails, BatchOperationKind, CommitBatchArguments, CreateAssetArguments,
    DeleteAssetArguments, Permission, SetAssetContentArguments, UnsetAssetContentArguments,
};

// Stay safely under the canister's ingress message limit (~2 MB).
const MAX_CHUNK_SIZE: usize = 1_900_000;

struct ProjectAssetEncoding {
    chunk_ids: Vec<Nat>,
    sha256: Vec<u8>,
    already_in_place: bool,
}

struct ProjectAsset {
    descriptor: AssetDescriptor,
    media_type: Mime,
    encodings: HashMap<String, ProjectAssetEncoding>,
}

/// Ensures the signing identity has `Commit` permission on the assets canister.
///
/// Called only in proxy mode. Queries the current `Commit` permission list and,
/// if the identity is absent, routes a `grant_permission` call through the proxy
/// canister. The proxy is the controller of the assets canister and can therefore
/// authorise the grant even without holding `ManagePermissions` explicitly.
fn ensure_commit_permission(identity_principal: &str) -> Result<(), String> {
    let principal = Principal::from_text(identity_principal)
        .map_err(|e| format!("invalid identity principal '{identity_principal}': {e}"))?;

    let permitted = call::list_permitted(Permission::Commit)?;
    if permitted.contains(&principal) {
        println!("proxy mode: identity already has Commit permission");
        return Ok(());
    }

    println!("proxy mode: granting Commit permission to {identity_principal} via proxy");
    call::grant_permission_via_proxy(principal, Permission::Commit)?;
    println!("proxy mode: Commit permission granted");
    Ok(())
}

pub fn run(
    dirs: &[String],
    identity_principal: &str,
    proxy_canister_id: Option<&str>,
) -> Result<String, String> {
    if let Some(_proxy) = proxy_canister_id {
        ensure_commit_permission(identity_principal)?;
    }

    let version = call::api_version()?;
    if version < 2 {
        return Err(format!(
            "assets canister api_version is {version}; this plugin requires V2"
        ));
    }
    println!("api_version: {version}");

    let descriptors = crate::gather::gather(dirs)?;
    println!("gathered {} file(s) from {:?}", descriptors.len(), dirs);

    let canister_assets: HashMap<String, AssetDetails> = call::list_assets()?
        .into_iter()
        .map(|d| (d.key.clone(), d))
        .collect();
    println!("canister currently has {} asset(s)", canister_assets.len());

    let batch_id = call::create_batch()?;
    println!("created batch {batch_id}");

    let mut project_assets: HashMap<String, ProjectAsset> = HashMap::new();
    for descriptor in descriptors {
        let asset = make_project_asset(descriptor, &canister_assets, &batch_id)?;
        project_assets.insert(asset.descriptor.key.clone(), asset);
    }

    let operations = assemble_operations(&project_assets, &canister_assets);
    println!("committing {} operation(s)", operations.len());

    call::commit_batch(CommitBatchArguments {
        batch_id,
        operations,
    })?;

    Ok(format!(
        "synced {} asset(s) to canister",
        project_assets.len()
    ))
}

fn make_project_asset(
    descriptor: AssetDescriptor,
    canister_assets: &HashMap<String, AssetDetails>,
    batch_id: &Nat,
) -> Result<ProjectAsset, String> {
    let content = Content::load(&descriptor.source)?;
    let encoders = default_encoders(&content.media_type);
    // The identity encoding is always uploaded if it's in the encoders list.
    // Other encodings are only uploaded if they save bytes vs. identity.
    // If identity is absent, force the alternate encoding through.
    let force_encoding = !encoders.contains(&ContentEncoder::Identity);

    let mut encodings: HashMap<String, ProjectAssetEncoding> = HashMap::new();
    for encoder in encoders {
        let encoded = content.encode(encoder)?;
        if encoder != ContentEncoder::Identity
            && !force_encoding
            && encoded.data.len() >= content.data.len()
        {
            continue;
        }
        let name = encoder.name().to_string();
        let sha256 = encoded.sha256();
        let already_in_place = is_already_in_place(
            &descriptor.key,
            &content.media_type,
            &name,
            &sha256,
            canister_assets,
        );

        let chunk_ids = if already_in_place {
            println!(
                "  {}{} ({} bytes) sha {} already in place",
                descriptor.key,
                encoding_suffix(&name),
                encoded.data.len(),
                hex::encode(&sha256)
            );
            Vec::new()
        } else {
            upload_chunks(batch_id, &descriptor.key, &name, &encoded.data)?
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
        descriptor,
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

fn upload_chunks(
    batch_id: &Nat,
    key: &str,
    encoding: &str,
    data: &[u8],
) -> Result<Vec<Nat>, String> {
    if data.is_empty() {
        let id = call::create_chunk(batch_id, &[])?;
        println!("  {key}{} 1/1 (0 bytes)", encoding_suffix(encoding));
        return Ok(vec![id]);
    }
    let total = data.len().div_ceil(MAX_CHUNK_SIZE);
    let mut ids = Vec::with_capacity(total);
    for (i, chunk) in data.chunks(MAX_CHUNK_SIZE).enumerate() {
        let id = call::create_chunk(batch_id, chunk)?;
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

fn assemble_operations(
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
