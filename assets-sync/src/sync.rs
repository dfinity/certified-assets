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
use crate::headers::{self, HeaderRule, HEADERS_FILENAME};
use crate::html_handling;
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
    files: &[(String, String)],
    identity_principal: &str,
    proxy_canister_id: Option<&str>,
) -> Result<String, String> {
    let asset_config = crate::asset_config::AssetConfig::from_files(files)?;
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

    // Synthesised CF `auto-trailing-slash` rules first, then the user's
    // `_redirects`. The canister matches rules in declaration order, so this
    // makes the html-handling defaults win at the exact paths they cover and
    // lets user rules catch what's left (e.g. a SPA-style `/* /404.html 404`
    // catch-all only fires for paths the html_handling defaults don't claim).
    //
    // The reason synth must come first is also a certification correctness
    // requirement: if a user subtree rule like `/*` is declared before the
    // synthesised Exact rules, the user rule wins at request time and the
    // canister returns a wildcard expression path (`["http_expr", "<*>"]`),
    // while the synthesised Exact entries (e.g. `["http_expr", "index", "<$>"]`)
    // still sit in the certified tree. The HTTP gateway's verifier then
    // rejects the response with "wildcard expression path provided, but a
    // potential exact expression path exists in the tree" and returns 503.
    // Putting synth first keeps responses on the Exact path whenever an Exact
    // entry exists.
    //
    // Synthesis is keyed off the scanned asset keys; nothing in the project
    // has uploaded yet, so this is the authoritative HTML set.
    let user_rules = load_redirect_rules(dir)?;
    println!(
        "parsed {} redirect rule(s) from _redirects",
        user_rules.len()
    );

    let asset_keys: Vec<String> = sources.iter().map(|s| s.key.clone()).collect();
    let synthesised = html_handling::synthesize(&asset_keys);
    if !synthesised.is_empty() {
        println!(
            "synthesised {} html-handling rule(s) for {} html asset(s)",
            synthesised.len(),
            asset_keys.iter().filter(|k| k.ends_with(".html")).count(),
        );
    }
    let mut project_rules = synthesised;
    project_rules.extend(user_rules);

    let project_header_rules = load_header_rules(dir)?;
    println!(
        "parsed {} header rule(s) from _headers",
        project_header_rules.len()
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
        let asset = prepare_asset(source, &asset_config, &canister_assets)?;
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
        &project_header_rules,
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
        &project_rules,
        &canister_rules,
        &project_header_rules,
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
    asset_config: &crate::asset_config::AssetConfig,
    canister_assets: &HashMap<String, AssetDetails>,
) -> Result<ProjectAsset, String> {
    let mut content = Content::load(&source.path)?;
    // Apply per-glob content-type override from `assets.toml` before deciding
    // encoders or computing the asset's stored media type. This is what makes
    // a `.did` file declared as `text/plain` pick up gzip compression and
    // surface the correct `Content-Type` from the canister's certified
    // response — see ASSETS-TOML.md "Downstream effects".
    if let Some(override_mime) = asset_config.content_type_for(&source.key) {
        content.media_type = override_mime;
    }
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

fn encoding_suffix(encoding: &str) -> String {
    if encoding == "identity" {
        String::new()
    } else {
        format!(" ({encoding})")
    }
}

/// Pack-and-upload pass: collect every chunk from every not-yet-uploaded
/// encoding across all assets, then ship them in `create_chunks` calls of up
/// to `MAX_CHUNK_SIZE` total bytes each.
///
/// This is where the wall-clock win lives versus the old "one chunk per call"
/// pattern: a project of 100 small files used to make 100 round-trips; now
/// they ride in a single call (≈1.9 MB budget).
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
    // chunk that still fits under MAX_CHUNK_SIZE. Anything that doesn't fit
    // stays in `pending` for the next pass.
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

fn build_operations(
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    canister_asset_properties: &HashMap<String, AssetProperties>,
    project_rules: &[RedirectRule],
    canister_rules: &[RedirectRule],
    project_header_rules: &[HeaderRule],
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
    //    headers come from resolving the project's `_headers` rules against
    //    each new key; max_age and allow_raw_access fall back to defaults.
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            let resolved = headers::resolve(key, project_header_rules);
            ops.push(BatchOperationKind::CreateAsset(CreateAssetArguments {
                key: key.clone(),
                content_type: pa.media_type.to_string(),
                max_age: None,
                headers: (!resolved.is_empty()).then_some(resolved),
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
        project_header_rules,
    );

    // 6. Replace-all the canister's redirect rules when they differ from the
    //    parsed `_redirects`. Comparison is order-sensitive — rules are
    //    matched in declaration order at request time, so reordering is a
    //    semantic change.
    //
    //    3xx rules synthesize their response (no target asset), so the
    //    canister has no headers to inherit from. Populate `RedirectRule.headers`
    //    by resolving `_headers` against the rule's `from` pattern. 200/4xx
    //    rules borrow headers from their target asset, so no plumbing here.
    let project_rules_with_headers: Vec<RedirectRule> = project_rules
        .iter()
        .map(|rule| {
            let mut rule = rule.clone();
            if is_3xx(rule.status) {
                let key = redirect_pattern_to_key(&rule.from);
                let resolved = headers::resolve(&key, project_header_rules);
                if !resolved.is_empty() {
                    rule.headers = Some(resolved);
                }
            }
            rule
        })
        .collect();
    if project_rules_with_headers != canister_rules {
        ops.push(BatchOperationKind::SetRedirectRules(
            SetRedirectRulesArguments {
                rules: project_rules_with_headers,
            },
        ));
    }

    ops
}

fn is_3xx(status: u16) -> bool {
    (300..400).contains(&status)
}

/// Returns a path-like key suitable for running the header resolver against a
/// redirect rule's `from`. Exact patterns yield the path itself; subtree
/// patterns yield the prefix, so only header rules that subsume the subtree
/// (the same or a broader subtree) match — narrower or unrelated patterns are
/// rejected by the resolver's `starts_with` check.
fn redirect_pattern_to_key(pattern: &crate::canister::RulePattern) -> String {
    match pattern {
        crate::canister::RulePattern::Exact(p) => p.clone(),
        crate::canister::RulePattern::Subtree(prefix) => prefix.clone(),
    }
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
// project config. Newly-created assets get the same values via
// `CreateAssetArguments`, so we don't emit `SetAssetProperties` for them.
//
// Headers are resolved from `_headers` per-key; everything else falls back to
// plugin defaults (None / Some(true)).
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
    project_header_rules: &[HeaderRule],
) {
    for key in project_assets.keys() {
        if !canister_assets.contains_key(key) {
            continue;
        }
        let Some(canister_props) = canister_asset_properties.get(key) else {
            continue;
        };

        let max_age = canister_props.max_age.is_some().then_some(None);

        let resolved = headers::resolve(key, project_header_rules);
        let expected_headers = (!resolved.is_empty()).then_some(resolved);
        let headers = if canister_props.headers != expected_headers {
            Some(expected_headers)
        } else {
            None
        };

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

/// Reads `_headers` from the project's input directory, if present. A missing
/// file is treated as "no rules"; parse errors carry the file's path and
/// 1-based line number so users can fix issues without a canister round-trip.
fn load_header_rules(dir: &str) -> Result<Vec<HeaderRule>, String> {
    let path = Path::new(dir).join(HEADERS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    headers::parse(&content).map_err(|e| format!("{}: {e}", path.display()))
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

    // Counts each `create_chunks` call, returns one fresh id per chunk in the
    // request, and records the batch sizes the packer produced. Used to verify
    // that `pack_and_upload_chunks` collapses many small chunks into single
    // calls and assigns canister ids to the right encoding slots.
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
                source: AssetSource {
                    path: PathBuf::from(key.trim_start_matches('/')),
                    key: key.to_string(),
                },
                media_type: "application/octet-stream".parse().unwrap(),
                encodings: enc_map,
            },
        )
    }

    #[test]
    fn pack_uploads_one_full_chunk_per_call() {
        // A single MAX-sized encoding ships in one call carrying one chunk.
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
        // MAX*3 + 1 bytes → 4 chunks: three at MAX, one at 1 byte. Each MAX
        // chunk fills its own call; the trailing 1-byte chunk gets its own
        // call too because nothing else is left to share with it.
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
        // 100 × 1KB chunks fit comfortably under MAX_CHUNK_SIZE (~1.9 MB) →
        // one call carrying all 100 chunks. This is the optimisation.
        let mut assets: HashMap<String, ProjectAsset> = (0..100)
            .map(|i| mk_pending_asset(&format!("/f{i}"), "identity", vec![0u8; 1024]))
            .collect();
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert_eq!(*mock.batches.borrow(), vec![100]);
    }

    #[test]
    fn pack_packs_full_chunk_alone_then_packs_remaining_smalls() {
        // One MAX-sized asset + many tiny assets. FFD puts the MAX chunk in
        // its own call (nothing else fits), then packs the small chunks
        // together.
        let mut assets: HashMap<String, ProjectAsset> = HashMap::new();
        assets.extend([mk_pending_asset(
            "/big",
            "identity",
            vec![0u8; MAX_CHUNK_SIZE],
        )]);
        for i in 0..10 {
            assets.extend([mk_pending_asset(
                &format!("/tiny{i}"),
                "identity",
                vec![0u8; 1024],
            )]);
        }
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        // Two calls total: one for the big chunk, one for the ten tinies.
        let batches = mock.batches.borrow().clone();
        assert_eq!(batches.len(), 2);
        assert!(batches.contains(&1)); // big chunk on its own
        assert!(batches.contains(&10)); // 10 tinies packed together
    }

    #[test]
    fn pack_routes_chunk_ids_to_correct_encoding_slot() {
        // Two assets, multi-chunk each. After upload, every encoding's
        // chunk_ids vec must be filled (no default zeros remaining) and
        // ids must be distinct.
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
        let mut all: Vec<&Nat> = a_ids.iter().chain(b_ids.iter()).collect();
        all.sort_by(|x, y| {
            // Nat doesn't impl Ord; compare textually.
            x.to_string().cmp(&y.to_string())
        });
        all.dedup();
        assert_eq!(all.len(), 3, "ids must be distinct");
    }

    #[test]
    fn pack_empty_encoding_still_gets_one_chunk_id() {
        // A zero-byte encoding still needs a chunk_id so SetAssetContent
        // has something to reference.
        let mut assets = HashMap::from([mk_pending_asset("/empty", "identity", vec![])]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert_eq!(assets["/empty"].encodings["identity"].chunk_ids.len(), 1);
    }

    #[test]
    fn pack_skips_already_in_place_encodings() {
        // Nothing to upload → no calls made.
        let (k, mut pa) = mk_pending_asset("/skip", "identity", vec![0u8; 100]);
        pa.encodings.get_mut("identity").unwrap().already_in_place = true;
        pa.encodings.get_mut("identity").unwrap().data = Vec::new();
        let mut assets = HashMap::from([(k, pa)]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, &Nat::from(1u32), &mut assets).unwrap();
        assert!(mock.batches.borrow().is_empty());
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
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[], &[]);
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
        assert!(build_operations(&project, &canister, &HashMap::new(), &[], &[], &[]).is_empty());
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&HashMap::new(), &canister, &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&project, &canister, &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&HashMap::new(), &canister, &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(
            &project,
            &canister,
            &HashMap::new(),
            &project_rules,
            &[],
            &[],
        );
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
            &[],
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
            &[],
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
            &[],
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
            &[],
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
            &[],
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
        let asset = prepare_asset(
            source,
            &crate::asset_config::AssetConfig::empty(),
            &HashMap::new(),
        )
        .unwrap();
        assert!(
            asset.encodings.contains_key("identity"),
            "identity must be present"
        );
        assert!(
            !asset.encodings.contains_key("gzip"),
            "gzip must be absent when not smaller"
        );
    }

    // assets.toml content-type override drives both the stored media type
    // and the encoder selection. Without the override, a `.did` file is
    // `application/octet-stream` (mime_guess has no entry) and gets only the
    // identity encoding; with the override to `text/plain`, encoders_for
    // selects gzip too.
    #[test]
    fn asset_config_content_type_override_applies_to_prepare_asset() {
        use crate::asset_config::AssetConfig;
        use std::io::Write;

        // Highly compressible content so gzip is genuinely smaller and gets
        // kept by prepare_asset's "skip if not smaller" check.
        let mut f = tempfile::Builder::new().suffix(".did").tempfile().unwrap();
        f.write_all(
            b"service : { greet : (text) -> (text); }\n"
                .repeat(100)
                .as_ref(),
        )
        .unwrap();
        let mk_source = || AssetSource {
            path: f.path().to_path_buf(),
            key: "/ic.did".to_string(),
        };

        // No override: mime_guess returns octet-stream, gzip is not selected.
        let without = prepare_asset(mk_source(), &AssetConfig::empty(), &HashMap::new()).unwrap();
        assert_eq!(without.media_type.to_string(), "application/octet-stream");
        assert!(!without.encodings.contains_key("gzip"));

        // With override to text/plain, both the media type and the encoder
        // pick change.
        let files = vec![(
            "assets.toml".to_string(),
            r#"
[[asset]]
match = "/*.did"
content_type = "text/plain; charset=utf-8"
"#
            .to_string(),
        )];
        let config = AssetConfig::from_files(&files).unwrap();
        let with = prepare_asset(mk_source(), &config, &HashMap::new()).unwrap();
        assert_eq!(with.media_type.to_string(), "text/plain; charset=utf-8");
        assert!(
            with.encodings.contains_key("gzip"),
            "gzip should be selected for text/* override"
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
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[], &[]);
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
        let ops = build_operations(&project, &canister, &canister_props, &[], &[], &[]);
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
        let ops = build_operations(&project, &canister, &canister_props, &[], &[], &[]);
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
        let canister_headers = vec![("X-Frame-Options".to_string(), "DENY".to_string())];
        let canister_props = HashMap::from([(
            "/index.html".to_string(),
            AssetProperties {
                max_age: None,
                headers: Some(canister_headers),
                allow_raw_access: Some(true),
            },
        )]);
        let ops = build_operations(&project, &canister, &canister_props, &[], &[], &[]);
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        // The inner None clears the headers map on the canister.
        assert_eq!(by_key["/index.html"].headers, Some(None));
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
        let ops = build_operations(&project, &canister, &canister_props, &[], &[], &[]);
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
        let ops = build_operations(&project, &HashMap::new(), &HashMap::new(), &[], &[], &[]);
        assert!(set_props_ops(&ops).is_empty());
    }

    // ── _headers integration ───────────────────────────────────────────────

    fn mk_header_rule(pattern_src: &str, headers: &[(&str, &str)]) -> HeaderRule {
        HeaderRule {
            pattern: crate::glob::parse(pattern_src).unwrap(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn create_asset_args_carry_resolved_headers() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let header_rules = vec![mk_header_rule("/*", &[("X-Frame-Options", "DENY")])];
        let ops = build_operations(
            &project,
            &HashMap::new(),
            &HashMap::new(),
            &[],
            &[],
            &header_rules,
        );
        let create_op = ops
            .iter()
            .find_map(|op| match op {
                BatchOperationKind::CreateAsset(a) => Some(a),
                _ => None,
            })
            .expect("CreateAsset op");
        assert_eq!(
            create_op.headers,
            Some(vec![("X-Frame-Options".into(), "DENY".into())])
        );
    }

    #[test]
    fn create_asset_args_omit_headers_when_no_rules_match() {
        let project = HashMap::from([mk_project_asset(
            "/public.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let header_rules = vec![mk_header_rule("/private", &[("X-Frame-Options", "DENY")])];
        let ops = build_operations(
            &project,
            &HashMap::new(),
            &HashMap::new(),
            &[],
            &[],
            &header_rules,
        );
        let create_op = ops
            .iter()
            .find_map(|op| match op {
                BatchOperationKind::CreateAsset(a) => Some(a),
                _ => None,
            })
            .expect("CreateAsset op");
        assert!(create_op.headers.is_none());
    }

    #[test]
    fn update_properties_sets_headers_when_canister_missing_them() {
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
        let header_rules = vec![mk_header_rule("/*", &[("X-Frame-Options", "DENY")])];
        let ops = build_operations(
            &project,
            &canister,
            &canister_props,
            &[],
            &[],
            &header_rules,
        );
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert_eq!(
            by_key["/index.html"].headers,
            Some(Some(vec![("X-Frame-Options".into(), "DENY".into())]))
        );
    }

    #[test]
    fn update_properties_clears_headers_when_no_rules_match() {
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
                headers: Some(vec![("X-Frame-Options".into(), "DENY".into())]),
                allow_raw_access: Some(true),
            },
        )]);
        // No header rules — canister-stored headers should be cleared.
        let ops = build_operations(&project, &canister, &canister_props, &[], &[], &[]);
        let by_key = set_props_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert_eq!(by_key["/index.html"].headers, Some(None));
    }

    #[test]
    fn three_xx_redirect_rule_carries_resolved_headers() {
        // 3xx rules synthesize their response; populate `headers` from any
        // `_headers` rule whose pattern matches the redirect's `from`.
        let header_rules = vec![mk_header_rule("/*", &[("X-Robots-Tag", "noindex")])];
        let project_rules = vec![mk_rule(
            crate::canister::RulePattern::Exact("/old".into()),
            "/new",
            301,
        )];
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &project_rules,
            &[],
            &header_rules,
        );
        let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].headers,
            Some(vec![("X-Robots-Tag".into(), "noindex".into())])
        );
    }

    #[test]
    fn non_3xx_redirect_rule_does_not_carry_resolved_headers() {
        // 200 / 4xx rules inherit headers from their target asset, so the
        // plugin must leave `RedirectRule.headers` as `None` even when a
        // matching `_headers` rule exists.
        let header_rules = vec![mk_header_rule("/*", &[("X-Robots-Tag", "noindex")])];
        for status in [200u16, 404, 410] {
            let project_rules = vec![mk_rule(
                crate::canister::RulePattern::Exact("/old".into()),
                "/target.html",
                status,
            )];
            let ops = build_operations(
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                &project_rules,
                &[],
                &header_rules,
            );
            let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
            assert_eq!(rules.len(), 1);
            assert!(
                rules[0].headers.is_none(),
                "status {status}: expected no headers on non-3xx rule"
            );
        }
    }

    #[test]
    fn three_xx_redirect_rule_omits_headers_when_no_match() {
        let header_rules = vec![mk_header_rule("/other", &[("X-Foo", "bar")])];
        let project_rules = vec![mk_rule(
            crate::canister::RulePattern::Exact("/old".into()),
            "/new",
            301,
        )];
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &project_rules,
            &[],
            &header_rules,
        );
        let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert!(rules[0].headers.is_none());
    }

    #[test]
    fn redirect_rules_match_when_headers_populated_matches_canister() {
        // Canister stores the same rule (with the resolved 3xx headers) — no
        // SetRedirectRules op should be emitted.
        let header_rules = vec![mk_header_rule("/*", &[("X-Robots-Tag", "noindex")])];
        let project_rules = vec![mk_rule(
            crate::canister::RulePattern::Exact("/old".into()),
            "/new",
            301,
        )];
        let canister_rules = vec![RedirectRule {
            from: crate::canister::RulePattern::Exact("/old".into()),
            to: "/new".to_string(),
            status: 301,
            headers: Some(vec![("X-Robots-Tag".into(), "noindex".into())]),
        }];
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &project_rules,
            &canister_rules,
            &header_rules,
        );
        assert!(
            set_rules_op(&ops).is_none(),
            "no SetRedirectRules op when rules with headers match canister-stored"
        );
    }

    #[test]
    fn update_properties_no_op_when_canister_headers_match_resolved() {
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
                headers: Some(vec![("X-Frame-Options".into(), "DENY".into())]),
                allow_raw_access: Some(true),
            },
        )]);
        let header_rules = vec![mk_header_rule("/*", &[("X-Frame-Options", "DENY")])];
        let ops = build_operations(
            &project,
            &canister,
            &canister_props,
            &[],
            &[],
            &header_rules,
        );
        assert!(
            set_props_ops(&ops).is_empty(),
            "no SetAssetProperties op when resolved headers byte-match canister-stored"
        );
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
        let err = sync(&mock, &[], &[], &Principal::anonymous().to_text(), None).unwrap_err();
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
            &[],
            &Principal::anonymous().to_text(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("got 2"), "got: {err}");
    }

    #[test]
    fn sync_short_circuits_when_headers_file_only_matches_canister() {
        // The canister already stores the headers a `_headers`-only project
        // would resolve. The "nothing to commit" short-circuit must trigger.
        // The asset is `.txt`, not `.html`, so the auto-synthesised
        // html-handling rules don't get in the way of the comparison.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"hello").unwrap();
        std::fs::write(
            dir.path().join("_headers"),
            b"/*\n  X-Frame-Options: DENY\n",
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
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());
        mock.push_ok(
            "get_asset_properties",
            AssetProperties {
                max_age: None,
                headers: Some(vec![("X-Frame-Options".into(), "DENY".into())]),
                allow_raw_access: Some(true),
            },
        );

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &[],
            &Principal::anonymous().to_text(),
            None,
        );
        // No create_batch / commit_batch programmed — would panic if reached.
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    // ── html-handling auto-synthesis ────────────────────────────────────────

    #[test]
    fn sync_synthesises_html_handling_rules_when_html_present() {
        // No `_redirects` file; an `index.html` asset alone should produce
        // exactly the three rules from `html_handling::synthesize` (the root
        // index variant: /, /index, /index.html). The canister has empty
        // rules and no asset, so the batch contains both the asset upload
        // and a SetRedirectRules op.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

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
            &[],
            &Principal::anonymous().to_text(),
            None,
        );
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    #[test]
    fn synthesised_rules_win_over_user_rule_at_same_from() {
        // Synthesised rules are emitted **before** the user's `_redirects` —
        // synth must come first so html-handling Exact rules don't get
        // shadowed by a broader user subtree (e.g. `/*` catch-all), which
        // would otherwise make the gateway verifier reject responses on
        // those paths (wildcard expr_path vs. exact entry in the tree).
        //
        // The cost: if the user happens to declare a rule at the exact same
        // `from` as something synthesis produces, the synthesised rule wins.
        // To override an HTML asset's default html_handling, remove the
        // source `.html` and use a non-HTML asset key instead.
        let user_rules = redirects::parse("/index /elsewhere 301\n").unwrap();
        let synthesised = crate::html_handling::synthesize(&["/index.html".to_string()]);

        let mut combined = synthesised;
        combined.extend(user_rules);

        // First rule matching `/index` is the synthesised 307 -> /.
        let first_at_index = combined
            .iter()
            .find(|r| matches!(&r.from, crate::canister::RulePattern::Exact(p) if p == "/index"))
            .expect("a rule at /index");
        assert_eq!(first_at_index.status, 307);
        assert_eq!(first_at_index.to, "/");
    }

    #[test]
    fn user_subtree_falls_through_to_paths_synth_doesnt_cover() {
        // The motivating fix: a user `/*` 404 catch-all must NOT shadow the
        // synthesised Exact rules — otherwise the cert tree carries Exact
        // entries that the response (served on the `<*>` subtree witness)
        // doesn't use, and the gateway verifier returns 503.
        //
        // With synth first, the catch-all only fires for paths nothing else
        // claims. We verify the rule order: synthesised /index Exact comes
        // before the user's /* Subtree.
        let user_rules = redirects::parse("/* /404.html 404\n").unwrap();
        let synthesised = crate::html_handling::synthesize(&["/index.html".to_string()]);

        let mut combined = synthesised;
        combined.extend(user_rules);

        let index_pos = combined
            .iter()
            .position(
                |r| matches!(&r.from, crate::canister::RulePattern::Exact(p) if p == "/index"),
            )
            .expect("a rule at /index");
        let catchall_pos = combined
            .iter()
            .position(|r| matches!(&r.from, crate::canister::RulePattern::Subtree(p) if p == "/"))
            .expect("the /* catch-all");
        assert!(
            index_pos < catchall_pos,
            "synth Exact must precede user Subtree /*; got index@{index_pos}, /*@{catchall_pos}"
        );
    }

    #[test]
    fn sync_short_circuits_when_synthesised_rules_match_canister() {
        // The canister already stores the rules synthesis would produce.
        // No SetRedirectRules op should be emitted, and with the asset
        // already up to date the sync should short-circuit before
        // create_batch.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        use sha2::Digest;
        let identity_sha = sha2::Sha256::digest(b"<html></html>").to_vec();

        let canister_rules = crate::html_handling::synthesize(&["/index.html".to_string()]);

        let mock = SyncMock::new();
        mock.push_ok("api_version", 2u16);
        mock.push_ok(
            "list",
            vec![AssetDetails {
                key: "/index.html".to_string(),
                content_type: "text/html".to_string(),
                encodings: vec![AssetEncodingDetails {
                    content_encoding: "identity".to_string(),
                    sha256: Some(identity_sha),
                }],
            }],
        );
        mock.push_ok("list", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", canister_rules);
        mock.push_ok(
            "get_asset_properties",
            AssetProperties {
                max_age: None,
                headers: None,
                allow_raw_access: Some(true),
            },
        );

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &[],
            &Principal::anonymous().to_text(),
            None,
        );
        // No create_batch / commit_batch programmed — would panic if reached.
        assert!(result.is_ok(), "expected success, got: {result:?}");
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
            &[],
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
