//! Orchestrates: load assets, diff against canister, upload chunks, commit batch.
//!
//! V2-only port of `ic-asset`'s `sync` flow, simplified:
//! - synchronous (drives the host's sync `canister-call` import)
//! - no proposal mode

use candid::Principal;
use mime::Mime;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::canister::{
    authorize_via_proxy, can_sync, execute_operations, list_all_assets, list_all_redirect_rules,
    start_sync, upload_chunks, version, CanisterCall,
};
use crate::content::{encoders_for, Content};
use crate::headers::{self, HeaderRule, HEADERS_FILENAME};
use crate::html_handling;
use crate::not_found;
use crate::redirects::{self, REDIRECTS_FILENAME};
use crate::scan::AssetSource;
use std::path::{Path, PathBuf};
use wire_types::{
    AssetDetails, CreateAssetArguments, DeleteAssetArguments, Encoding, ExecuteOperationsArguments,
    Operation, RedirectRule, RulePattern, SetAssetContentArguments, SetAssetHeadersArguments,
    SetRedirectRulesArguments, UnsetAssetContentArguments,
};

// Stay safely under the canister's ingress message limit (~2 MB).
const MAX_CHUNK_SIZE: usize = 1_900_000;

struct ProjectAssetEncoding {
    chunk_ids: Vec<u64>,
    sha256: Vec<u8>,
    // SHA-256 of each chunk, parallel to `chunk_ids`. Computed while slicing the
    // encoded bytes in `pack_and_upload_chunks` and sent to the canister, which
    // trusts it for multi-chunk 206 range certification (see
    // `SetAssetContentArguments`). Empty until the chunks are packed.
    chunk_sha256: Vec<Vec<u8>>,
    already_in_place: bool,
    // Encoded bytes held until upload; empty when already_in_place or after upload.
    data: Vec<u8>,
}

struct ProjectAsset {
    source: AssetSource,
    media_type: Mime,
    encodings: HashMap<Encoding, ProjectAssetEncoding>,
}

impl ProjectAsset {
    /// Whether any encoding will be stored as more than one chunk. Only
    /// encodings staged for upload carry their bytes here; an encoding already
    /// in place on the canister has its `data` cleared, so this under-reports
    /// for unchanged assets — the canister's `SetRedirectRules` guard backstops
    /// that case. Used to reject 4xx error-page rules whose target is too large
    /// to serve as a single inline body (see [`validate_error_page_targets`]).
    fn is_multichunk(&self) -> bool {
        self.encodings
            .values()
            .any(|e| e.data.len() > MAX_CHUNK_SIZE)
    }
}

/// Rejects 404/410 rules whose target asset will be multi-chunk. A custom error
/// page is served as a single inline body with the override status (the gateway
/// only reassembles 206 chunks into a *200*), so a target larger than one chunk
/// can't carry it — the canister would fall back to its built-in 404 and the
/// response would fail certification. Catching it here points the user at the
/// offending `_redirects` rule before any sync starts.
fn validate_error_page_targets(
    rules: &[RedirectRule],
    project_assets: &HashMap<String, ProjectAsset>,
) -> Result<(), String> {
    for rule in rules {
        if !matches!(rule.status, 404 | 410) {
            continue;
        }
        if project_assets
            .get(&rule.to)
            .is_some_and(ProjectAsset::is_multichunk)
        {
            let from = match &rule.from {
                RulePattern::Exact(p) | RulePattern::Subtree(p) => p,
            };
            return Err(format!(
                "_redirects: rule `{} {} {}` points to a multi-chunk asset; \
                 404/410 error pages must be small enough to serve as a single \
                 chunk (< {} bytes). Shrink `{}`, or use a 3xx redirect instead.",
                from, rule.to, rule.status, MAX_CHUNK_SIZE, rule.to
            ));
        }
    }
    Ok(())
}

/// Ensures the signing identity can sync assets, before any expensive scanning
/// or diffing work happens — so an unauthorized run fails fast instead of after
/// reading and encoding the whole project.
///
/// Asks the canister whether the identity may sync (`can_sync`, which is true
/// for authorized principals *and* controllers):
/// - If it can, returns immediately.
/// - In proxy mode, routes an `authorize` call through the proxy canister (the
///   proxy is the canister's controller and the only caller allowed to change
///   the authorized set), then the identity can sync directly.
/// - In direct mode, there is no controller to grant through, so this fails
///   fast.
fn ensure_can_sync<C: CanisterCall>(
    canister: &C,
    identity_principal: &str,
    proxy_mode: bool,
) -> Result<(), String> {
    if can_sync(canister)? {
        return Ok(());
    }

    if proxy_mode {
        let principal = Principal::from_text(identity_principal)
            .map_err(|e| format!("invalid identity principal '{identity_principal}': {e}"))?;
        println!("proxy mode: authorizing {identity_principal} via proxy");
        authorize_via_proxy(canister, principal)?;
        println!("proxy mode: identity authorized");
        Ok(())
    } else {
        Err(format!(
            "identity {identity_principal} is not authorized to sync assets on this canister; \
             a controller must authorize it (or deploy with --proxy to authorize it automatically)"
        ))
    }
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

    // Check authorization before any scanning or diffing so an unauthorized
    // run fails fast rather than after reading and encoding the whole project.
    ensure_can_sync(canister, identity_principal, proxy_canister_id.is_some())?;

    // The canister and this plugin ship as one bundle and are upgraded as a
    // locked pair, so refuse to sync unless the canister reports our exact
    // version — most often a mismatch means the canister wasn't re-installed
    // after the recipe was bumped. When they differ, the semver tells the user
    // both which side is stale and, when the canister is the stale one, whether
    // the fix is an in-place upgrade (non-breaking) or a reinstall (breaking).
    let canister_version = version(canister)?;
    let plugin_version = wire_types::VERSION;
    if canister_version != plugin_version {
        let hint = if canister_version < plugin_version {
            if plugin_version.upgrade_compatible_with(canister_version) {
                "the canister is behind this plugin (non-breaking): upgrade it in place with `icp canister install --mode upgrade` — state is preserved — then re-run sync"
            } else {
                "the canister is behind this plugin (breaking): reinstall it with `icp canister install --mode reinstall`, which wipes its state, then re-run sync to re-upload all assets and redirect rules"
            }
        } else {
            "the canister is newer than this plugin — update your tooling so the plugin matches, then re-run sync"
        };
        return Err(format!(
            "assets canister version mismatch: canister is {canister_version}, this plugin is {plugin_version}; {hint}",
        ));
    }
    println!("version: {canister_version}");

    let sources = crate::scan::scan(dir)?;
    println!("found {} file(s) from {dir}", sources.len());

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

    let mut asset_keys: Vec<String> = sources.iter().map(|s| s.key.clone()).collect();

    // 404 fallback convention (root-only). The canister has no built-in 404, so
    // guarantee the root `<*>` slot is always backed by a real rule: append a
    // `/* /404.html 404` catch-all, injecting a branded default `/404.html`
    // asset when the project ships none. Skipped entirely when the user already
    // declares a root `/*` rule (their rule — e.g. a SPA `/* … 200` — covers
    // the whole path space and must win). See `not_found`.
    let not_found_plan = not_found::plan(&asset_keys, &user_rules);
    if not_found_plan.inject_branded_asset {
        // Add the key before html-handling synthesis so the branded page picks
        // up the same `/404` clean-URL rules a user-supplied `404.html` would.
        asset_keys.push(not_found::ROOT_404_KEY.to_string());
    }

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
    if not_found_plan.append_catchall {
        if not_found_plan.inject_branded_asset {
            println!(
                "no root {} found — injecting a default certified 404 page",
                not_found::ROOT_404_KEY
            );
        }
        // Lowest priority: only fires for paths no asset or earlier rule claims.
        project_rules.push(not_found::catchall_rule());
    }

    let project_header_rules = load_header_rules(dir)?;
    println!(
        "parsed {} header rule(s) from _headers",
        project_header_rules.len()
    );

    let canister_assets: HashMap<String, AssetDetails> = list_all_assets(canister)?;
    println!("canister currently has {} asset(s)", canister_assets.len());

    let canister_rules = list_all_redirect_rules(canister)?;
    println!(
        "canister currently has {} redirect rule(s)",
        canister_rules.len()
    );

    // Phase 1: compute metadata only — no batch created yet.
    let mut project_assets: HashMap<String, ProjectAsset> = HashMap::new();
    for source in sources {
        let asset = prepare_asset(source, &project_header_rules, &canister_assets)?;
        project_assets.insert(asset.source.key.clone(), asset);
    }
    if not_found_plan.inject_branded_asset {
        let asset = prepare_branded_404(&canister_assets)?;
        project_assets.insert(asset.source.key.clone(), asset);
    }

    // Reject oversized 4xx error-page targets before starting a sync.
    validate_error_page_targets(&project_rules, &project_assets)?;

    if build_operations(
        &project_assets,
        &canister_assets,
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

    // Phase 2: start a sync and upload chunks for encodings not already in place.
    let session_id = start_sync(canister)?;
    println!("started sync session {session_id}");

    pack_and_upload_chunks(canister, session_id, &mut project_assets)?;

    let operations = build_operations(
        &project_assets,
        &canister_assets,
        &project_rules,
        &canister_rules,
        &project_header_rules,
    );
    println!("executing {} operation(s)", operations.len());

    execute_in_stages(canister, session_id, operations)?;

    Ok(format!(
        "synced {} asset(s) to canister",
        project_assets.len()
    ))
}

fn prepare_asset(
    source: AssetSource,
    header_rules: &[HeaderRule],
    canister_assets: &HashMap<String, AssetDetails>,
) -> Result<ProjectAsset, String> {
    let mut content = Content::load(&source.path)?;
    // Apply per-glob `Content-Type` override from `_headers` before deciding
    // encoders or computing the asset's stored media type. Routing through
    // `content.media_type` is what makes a `.did` file declared as
    // `text/plain` pick up gzip compression and surface the correct
    // `Content-Type` from the canister's certified response.
    if let Some(override_mime) = headers::content_type_for(&source.key, header_rules) {
        content.media_type = override_mime;
    }
    prepare_content_asset(source, content, canister_assets)
}

/// Builds the in-memory branded `/404.html` asset injected when a project ships
/// no root `404.html` (see `not_found`). Treated like any other HTML asset —
/// it gets the same encoders and html-handling rules — but its bytes come from
/// a constant instead of disk, and `_headers` content-type overrides are not
/// applied (the default page is always `text/html`).
fn prepare_branded_404(
    canister_assets: &HashMap<String, AssetDetails>,
) -> Result<ProjectAsset, String> {
    let source = AssetSource {
        // Never read from disk — content is supplied inline below. Kept only so
        // the key flows through the normal asset path; not used for I/O.
        path: PathBuf::from(not_found::ROOT_404_KEY),
        key: not_found::ROOT_404_KEY.to_string(),
    };
    let content = Content {
        data: not_found::DEFAULT_404_HTML.as_bytes().to_vec(),
        media_type: mime_guess::from_path(not_found::ROOT_404_KEY)
            .first()
            .unwrap_or(mime::TEXT_HTML),
    };
    prepare_content_asset(source, content, canister_assets)
}

/// Shared tail of `prepare_asset`: pick encoders for `content`, encode each,
/// and record which encodings the canister already holds.
fn prepare_content_asset(
    source: AssetSource,
    content: Content,
    canister_assets: &HashMap<String, AssetDetails>,
) -> Result<ProjectAsset, String> {
    // Brotli + gzip for compressible types, identity for everything else.
    let encoders: Vec<Encoding> = encoders_for(&content.media_type);

    let mut encodings: HashMap<Encoding, ProjectAssetEncoding> = HashMap::new();
    for encoding in encoders {
        let encoded = content.encode(encoding)?;
        // Identity is always uploaded. A compressed encoding is only kept if it
        // actually saves bytes vs. identity — otherwise storing it just wastes
        // canister space (e.g. a tiny file where the gzip/brotli framing alone
        // exceeds the savings).
        if !encoding.is_identity() && encoded.data.len() >= content.data.len() {
            continue;
        }
        let sha256 = encoded.sha256();
        let already_in_place = is_already_in_place(
            &source.key,
            &content.media_type,
            encoding,
            &sha256,
            canister_assets,
        );

        if already_in_place {
            println!(
                "  {}{} ({} bytes) sha {} already in place",
                source.key,
                encoding_suffix(encoding),
                encoded.data.len(),
                hex::encode(&sha256)
            );
        }

        encodings.insert(
            encoding,
            ProjectAssetEncoding {
                chunk_ids: Vec::new(),
                sha256,
                chunk_sha256: Vec::new(),
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
    encoding: Encoding,
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
        .find(|d| d.encoding == encoding)
        .is_some_and(|d| d.sha256.as_ref() == sha256)
}

fn encoding_suffix(encoding: Encoding) -> String {
    if encoding.is_identity() {
        String::new()
    } else {
        format!(" ({})", encoding.label())
    }
}

/// Pack-and-upload pass: collect every chunk from every not-yet-uploaded
/// encoding across all assets, then ship them in `upload_chunks` calls of up
/// to `MAX_CHUNK_SIZE` total bytes each.
///
/// This is where the wall-clock win lives versus the old "one chunk per call"
/// pattern: a project of 100 small files used to make 100 round-trips; now
/// they ride in a single call (≈1.9 MB budget).
///
/// Chunk ids are not returned over the wire. The canister numbers staged chunks
/// 0, 1, 2, … per sync in the order it receives them, so we assign the same ids
/// here as we hand each chunk off. This only holds because uploads are issued
/// one call at a time, in order — if this loop is ever parallelized, the
/// canister must echo the ids back again (see `upload_chunks` / `UploadChunksArguments`).
///
/// Routing is by `(asset_key, encoding, chunk_index)`: each `PendingChunk`
/// remembers where its inferred id should land in `enc.chunk_ids[chunk_index]`.
fn pack_and_upload_chunks<C: CanisterCall>(
    canister: &C,
    session_id: u64,
    project_assets: &mut HashMap<String, ProjectAsset>,
) -> Result<(), String> {
    struct PendingChunk {
        asset_key: String,
        encoding: Encoding,
        chunk_index: usize,
        data: Vec<u8>,
    }

    let mut pending: Vec<PendingChunk> = Vec::new();
    for asset in project_assets.values_mut() {
        let key = asset.source.key.clone();
        for (&encoding, enc) in &mut asset.encodings {
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
            // Hash each chunk here, on the client, so the canister never has to:
            // it trusts these for multi-chunk 206 range certification.
            enc.chunk_sha256 = chunks
                .iter()
                .map(|c| Sha256::digest(c).to_vec())
                .collect();
            enc.chunk_ids = vec![0u64; chunks.len()];
            for (i, chunk) in chunks.into_iter().enumerate() {
                pending.push(PendingChunk {
                    asset_key: key.clone(),
                    encoding,
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
    // The canister assigns ids 0, 1, 2, … across the whole sync in the order it
    // receives chunks. We send batches sequentially and, within each batch, in
    // `content` order — so mirroring that running counter here yields the same
    // ids the canister will, without a wire round-trip.
    let mut next_id: u64 = 0;

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

        // Move each chunk's bytes into the request; the post-call loop below
        // only needs the routing fields (asset_key/encoding/chunk_index), not
        // the data. Candid copies the bytes on encode either way, so this is a
        // move, not an extra copy.
        let content: Vec<ByteBuf> = batch
            .iter_mut()
            .map(|p| ByteBuf::from(std::mem::take(&mut p.data)))
            .collect();
        upload_chunks(canister, session_id, content)?;
        total_calls += 1;
        total_bytes += batch_size as u64;

        // Assign ids in the same order the bytes were placed in `content`, so
        // they match the canister's arrival-order numbering.
        for p in &batch {
            let asset = project_assets
                .get_mut(&p.asset_key)
                .expect("asset present (collected above)");
            let enc = asset
                .encodings
                .get_mut(&p.encoding)
                .expect("encoding present (collected above)");
            enc.chunk_ids[p.chunk_index] = next_id;
            next_id += 1;
        }
    }

    println!("uploaded {total_chunks} chunk(s) in {total_calls} call(s) ({total_bytes} bytes)");
    Ok(())
}

/// Applies `operations` to the canister, splitting them across multiple
/// `execute_operations` ingress calls when a single payload would exceed the
/// IC's 2 MiB per-message ingress limit on application subnets
/// (`MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET` in `dfinity/ic`). The local
/// replica's HTTP boundary accepts up to 4 MiB, but mainnet app subnets cap
/// the inner ingress message at 2 MiB — so we target the tighter limit.
///
/// Every call carries the real `session_id`; the canister rejects any that
/// don't match the active sync. The last group is flagged `is_final`, which
/// tells the canister to finalize the sync (release the lock and drop staged
/// chunks) once its operations are applied. Earlier groups leave the sync
/// open. Staged chunks survive between calls because the canister only drops
/// them on sync start/finish, not between `execute_operations` calls.
///
/// Trade-off: splitting forfeits cross-call atomicity. A failure mid-deploy
/// leaves the canister with the operations from previously successful calls
/// applied; the next sync run diffs against the canister and resumes from
/// there.
fn execute_in_stages<C: CanisterCall>(
    canister: &C,
    session_id: u64,
    operations: Vec<Operation>,
) -> Result<(), String> {
    let groups = split_operation_groups(operations);
    // The caller only reaches this with a non-empty diff, so there is always at
    // least one group. Guard anyway: we hold a session and must release it.
    if groups.is_empty() {
        return execute_operations(
            canister,
            ExecuteOperationsArguments {
                session_id,
                operations: vec![],
                is_final: true,
            },
        );
    }
    let total = groups.len();
    for (i, ops) in groups.into_iter().enumerate() {
        let is_final = i + 1 == total;
        if total > 1 {
            println!(
                "executing group {}/{} ({} operation(s))",
                i + 1,
                total,
                ops.len()
            );
        }
        execute_operations(
            canister,
            ExecuteOperationsArguments {
                session_id,
                operations: ops,
                is_final,
            },
        )?;
    }
    Ok(())
}

/// Splits `operations` into groups, each small enough that a single
/// `execute_operations` ingress call stays under the IC's 2 MiB per-message
/// limit on application subnets. Greedy in declaration order: walks
/// operations once, starting a new group whenever the running totals
/// would exceed either budget.
///
/// Budgets per group:
/// - **500 operations** — bounds the certified-tree work each
///   `execute_operations` does and limits the blast radius of a mid-deploy
///   failure.
/// - **1.5 MiB of inlined header bytes** — leaves ~500 KiB of headroom
///   under the 2 MiB ingress cap for fixed per-op overhead (keys,
///   chunk_ids, sha256s, variant tags, request envelope). Header bytes
///   are the only variable-sized per-op field and are where real-world
///   overruns come from — a multi-kilobyte `Content-Security-Policy`
///   from `_headers` gets attached to every asset's `CreateAsset` and
///   to every 3xx rule inside `SetRedirectRules`.
///
/// An operation whose own header size exceeds the budget gets a group
/// to itself — better to ship it alone than to drop it on the floor.
fn split_operation_groups(operations: Vec<Operation>) -> Vec<Vec<Operation>> {
    const MAX_OPERATIONS_PER_GROUP: usize = 500;
    const MAX_HEADER_BYTES_PER_GROUP: usize = 1_500_000;

    let mut groups: Vec<Vec<Operation>> = Vec::new();
    let mut current: Vec<Operation> = Vec::new();
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
///
/// Kinds with inlined headers:
/// - `CreateAsset` — the per-key resolution of `_headers`.
/// - `SetAssetHeaders` — same, when headers drift.
/// - `SetRedirectRules` — each 3xx rule inlines its resolved headers
///   (3xx rules synthesise their own response, so there's no target
///   asset to inherit headers from). Summed across all rules.
fn header_bytes_of(op: &Operation) -> usize {
    fn sum(headers: &[(String, String)]) -> usize {
        headers.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
    match op {
        Operation::CreateAsset(a) => sum(&a.headers),
        Operation::SetAssetHeaders(a) => sum(&a.headers),
        Operation::SetRedirectRules(a) => a.rules.iter().map(|r| sum(&r.headers)).sum(),
        Operation::DeleteAsset(_)
        | Operation::UnsetAssetContent(_)
        | Operation::SetAssetContent(_) => 0,
    }
}

fn build_operations(
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    project_rules: &[RedirectRule],
    canister_rules: &[RedirectRule],
    project_header_rules: &[HeaderRule],
) -> Vec<Operation> {
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
            ops.push(Operation::DeleteAsset(DeleteAssetArguments {
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
    //    each new key.
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            ops.push(Operation::CreateAsset(CreateAssetArguments {
                key: key.clone(),
                content_type: pa.media_type.to_string(),
                headers: headers::resolve(key, project_header_rules),
            }));
        }
    }

    // 3. Unset encodings that exist on the canister but not in the project.
    for (key, ca) in &canister_assets {
        if let Some(pa) = project_assets.get(key) {
            for enc in &ca.encodings {
                if !pa.encodings.contains_key(&enc.encoding) {
                    ops.push(Operation::UnsetAssetContent(UnsetAssetContentArguments {
                        key: key.clone(),
                        encoding: enc.encoding,
                    }));
                }
            }
        }
    }

    // 4. Set content for every encoding that wasn't already in place.
    for (key, pa) in project_assets {
        for (&encoding, enc) in &pa.encodings {
            if enc.already_in_place {
                continue;
            }
            ops.push(Operation::SetAssetContent(SetAssetContentArguments {
                key: key.clone(),
                encoding,
                chunk_ids: enc.chunk_ids.clone(),
                sha256: ByteBuf::from(enc.sha256.clone()),
                chunk_sha256: enc
                    .chunk_sha256
                    .iter()
                    .map(|h| ByteBuf::from(h.clone()))
                    .collect(),
            }));
        }
    }

    // 5. Update headers for assets that already exist on the canister and
    //    whose headers drifted from the project config.
    update_headers(
        &mut ops,
        project_assets,
        &canister_assets,
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
    let project_rules_with_headers = resolve_3xx_rule_headers(project_rules, project_header_rules);
    if project_rules_with_headers != canister_rules {
        ops.push(Operation::SetRedirectRules(SetRedirectRulesArguments {
            rules: project_rules_with_headers,
        }));
    }

    ops
}

fn is_3xx(status: u16) -> bool {
    (300..400).contains(&status)
}

/// Inlines `_headers` into the `headers` of every 3xx rule by resolving them
/// against the rule's `from` pattern — 3xx rules synthesize their own response
/// and have no target asset to inherit headers from. 200/4xx rules borrow
/// headers from their target asset, so they pass through untouched. This is the
/// canonical form the canister stores, so a re-sync diffs cleanly against it.
fn resolve_3xx_rule_headers(
    rules: &[RedirectRule],
    header_rules: &[HeaderRule],
) -> Vec<RedirectRule> {
    rules
        .iter()
        .map(|rule| {
            let mut rule = rule.clone();
            if is_3xx(rule.status) {
                let key = redirect_pattern_to_key(&rule.from);
                rule.headers = headers::resolve(&key, header_rules);
            }
            rule
        })
        .collect()
}

/// Returns a path-like key suitable for running the header resolver against a
/// redirect rule's `from`. Exact patterns yield the path itself; subtree
/// patterns yield the prefix, so only header rules that subsume the subtree
/// (the same or a broader subtree) match — narrower or unrelated patterns are
/// rejected by the resolver's `starts_with` check.
fn redirect_pattern_to_key(pattern: &RulePattern) -> String {
    match pattern {
        RulePattern::Exact(p) => p.clone(),
        RulePattern::Subtree(prefix) => prefix.clone(),
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

// For each asset that already exists on the canister, reset its `headers` when
// they drifted from the project config. Newly-created assets get the same
// values via `CreateAssetArguments`, so we don't emit `SetAssetHeaders` for
// them.
//
// Headers are resolved from `_headers` per-key.
//
// `canister_assets` is the post-deletion view: keys removed in step 1 (missing
// from the project, or content_type drift forcing delete-then-create) are
// absent. Skipping those keys here avoids emitting a redundant
// `SetAssetHeaders` op for an asset whose headers are already being set
// by `CreateAssetArguments` in this same batch.
fn update_headers(
    ops: &mut Vec<Operation>,
    project_assets: &HashMap<String, ProjectAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
    project_header_rules: &[HeaderRule],
) {
    for key in project_assets.keys() {
        // Only surviving assets reach here: `canister_assets` has already had
        // deletions (obsolete keys, content_type drift) removed. Headers come
        // straight from the `list` projection.
        let Some(canister_asset) = canister_assets.get(key) else {
            continue;
        };

        let resolved = headers::resolve(key, project_header_rules);

        if canister_asset.headers != resolved {
            ops.push(Operation::SetAssetHeaders(SetAssetHeadersArguments {
                key: key.clone(),
                headers: resolved,
            }));
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
    use crate::{CallType, CanisterCall};
    use candid::{CandidType, Principal};
    use serde::de::DeserializeOwned;
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::path::PathBuf;
    use wire_types::{AssetDetails, AssetEncodingDetails, Operation};

    /// The canister-side state a finished sync leaves for the injected branded
    /// `/404.html`: its `AssetDetails` (content_type + per-encoding shas) derived
    /// from the same `prepare_branded_404` the sync path runs, with headers
    /// resolved from `header_rules` exactly as `build_operations` would. Lets the
    /// short-circuit tests assert "a second sync of a 404-augmented project is a
    /// no-op" without hard-coding the branded page's bytes.
    fn branded_404_canister_asset(header_rules: &[HeaderRule]) -> AssetDetails {
        let asset = prepare_branded_404(&HashMap::new()).expect("prepare branded 404");
        let mut encodings: Vec<AssetEncodingDetails> = asset
            .encodings
            .iter()
            .map(|(name, enc)| AssetEncodingDetails {
                encoding: *name,
                sha256: serde_bytes::ByteBuf::from(enc.sha256.clone()),
            })
            .collect();
        encodings.sort_by_key(|a| a.encoding);
        AssetDetails {
            key: not_found::ROOT_404_KEY.to_string(),
            content_type: asset.media_type.to_string(),
            encodings,
            headers: headers::resolve(not_found::ROOT_404_KEY, header_rules),
        }
    }

    // Records the batch sizes the packer produced (chunks per `upload_chunks`
    // call). Used to verify that `pack_and_upload_chunks` collapses many small
    // chunks into single calls and assigns ids to the right encoding slots. The
    // call returns unit; the plugin infers ids locally, so the mock doesn't.
    struct ChunkBatchRecorder {
        batches: RefCell<Vec<usize>>, // chunks-per-batch
    }

    impl ChunkBatchRecorder {
        fn new() -> Self {
            Self {
                batches: RefCell::new(Vec::new()),
            }
        }
    }

    // Mirror of UploadChunksArguments so the mock can introspect arg.chunks.len().
    #[derive(CandidType, serde::Deserialize)]
    struct ChunksReqMirror {
        #[allow(dead_code)]
        session_id: u64,
        chunks: Vec<serde_bytes::ByteBuf>,
    }

    impl CanisterCall for ChunkBatchRecorder {
        fn call<A, R>(&self, method: &str, arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "upload_chunks");
            let bytes = candid::encode_one(&arg).map_err(|e| e.to_string())?;
            let req: ChunksReqMirror = candid::decode_one(&bytes).map_err(|e| e.to_string())?;
            self.batches.borrow_mut().push(req.chunks.len());
            let reply = candid::encode_one(()).map_err(|e| e.to_string())?;
            candid::decode_one(&reply).map_err(|e| e.to_string())
        }
    }

    fn mk_pending_asset(key: &str, encoding: &str, data: Vec<u8>) -> (String, ProjectAsset) {
        let mut enc_map = HashMap::new();
        enc_map.insert(
            Encoding::from_token(encoding).expect("supported test encoding"),
            ProjectAssetEncoding {
                chunk_ids: Vec::new(),
                sha256: vec![0; 32],
                chunk_sha256: Vec::new(),
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

    fn err_page_rule(from: &str, to: &str, status: u16) -> RedirectRule {
        RedirectRule {
            from: RulePattern::Exact(from.to_string()),
            to: to.to_string(),
            status,
            headers: vec![],
        }
    }

    #[test]
    fn validate_rejects_4xx_rule_to_multichunk_target() {
        let assets = HashMap::from([mk_pending_asset(
            "/404.html",
            "identity",
            vec![0u8; MAX_CHUNK_SIZE + 1], // 2 chunks
        )]);
        for status in [404, 410] {
            let rules = vec![err_page_rule("/missing", "/404.html", status)];
            let err = validate_error_page_targets(&rules, &assets).unwrap_err();
            assert!(err.contains("multi-chunk asset"), "got: {err}");
            assert!(err.contains("/404.html"), "got: {err}");
        }
    }

    #[test]
    fn validate_accepts_4xx_rule_to_single_chunk_target() {
        let assets = HashMap::from([mk_pending_asset(
            "/404.html",
            "identity",
            vec![0u8; MAX_CHUNK_SIZE], // exactly 1 chunk
        )]);
        let rules = vec![err_page_rule("/missing", "/404.html", 404)];
        validate_error_page_targets(&rules, &assets).unwrap();
    }

    #[test]
    fn validate_ignores_non_4xx_rules_to_multichunk_target() {
        // A 200 rewrite to a multi-chunk target is fine (served as N×206).
        let assets = HashMap::from([mk_pending_asset(
            "/large.bin",
            "identity",
            vec![0u8; MAX_CHUNK_SIZE + 1],
        )]);
        let rules = vec![err_page_rule("/landing", "/large.bin", 200)];
        validate_error_page_targets(&rules, &assets).unwrap();
    }

    #[test]
    fn validate_ignores_4xx_rule_to_absent_target() {
        // Target not in the project (doesn't exist yet) → the plugin can't size
        // it; the canister guard backstops it. No error here.
        let assets: HashMap<String, ProjectAsset> = HashMap::new();
        let rules = vec![err_page_rule("/missing", "/404.html", 404)];
        validate_error_page_targets(&rules, &assets).unwrap();
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
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        assert_eq!(*mock.batches.borrow(), vec![1]);
        assert_eq!(
            assets["/f"].encodings[&Encoding::Identity].chunk_ids.len(),
            1
        );
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
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        assert_eq!(*mock.batches.borrow(), vec![1, 1, 1, 1]);
        assert_eq!(
            assets["/big"].encodings[&Encoding::Identity]
                .chunk_ids
                .len(),
            4
        );
    }

    #[test]
    fn pack_computes_per_chunk_sha256_matching_each_slice() {
        // Two full chunks plus a partial third, with position-dependent bytes so
        // a misaligned, duplicated, or whole-asset hash would be caught.
        let data: Vec<u8> = (0..MAX_CHUNK_SIZE * 2 + 7).map(|i| i as u8).collect();
        let mut assets = HashMap::from([mk_pending_asset("/big", "identity", data.clone())]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();

        let enc = &assets["/big"].encodings[&Encoding::Identity];
        let expected: Vec<Vec<u8>> = data
            .chunks(MAX_CHUNK_SIZE)
            .map(|c| Sha256::digest(c).to_vec())
            .collect();
        assert_eq!(enc.chunk_sha256, expected);
        // One hash per chunk id, in the same order.
        assert_eq!(enc.chunk_sha256.len(), enc.chunk_ids.len());
    }

    #[test]
    fn pack_empty_encoding_hashes_its_single_empty_chunk() {
        let mut assets = HashMap::from([mk_pending_asset("/empty", "identity", vec![])]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        let enc = &assets["/empty"].encodings[&Encoding::Identity];
        assert_eq!(enc.chunk_sha256, vec![Sha256::digest(b"").to_vec()]);
    }

    #[test]
    fn pack_collapses_many_small_chunks_into_one_call() {
        // 100 × 1KB chunks fit comfortably under MAX_CHUNK_SIZE (~1.9 MB) →
        // one call carrying all 100 chunks. This is the optimisation.
        let mut assets: HashMap<String, ProjectAsset> = (0..100)
            .map(|i| mk_pending_asset(&format!("/f{i}"), "identity", vec![0u8; 1024]))
            .collect();
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
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
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
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
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        let a_ids = &assets["/a"].encodings[&Encoding::Identity].chunk_ids;
        let b_ids = &assets["/b"].encodings[&Encoding::Identity].chunk_ids;
        assert_eq!(a_ids.len(), 2);
        assert_eq!(b_ids.len(), 1);
        let mut all: Vec<u64> = a_ids.iter().chain(b_ids.iter()).copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 3, "ids must be distinct");
    }

    #[test]
    fn pack_empty_encoding_still_gets_one_chunk_id() {
        // A zero-byte encoding still needs a chunk_id so SetAssetContent
        // has something to reference.
        let mut assets = HashMap::from([mk_pending_asset("/empty", "identity", vec![])]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        assert_eq!(
            assets["/empty"].encodings[&Encoding::Identity]
                .chunk_ids
                .len(),
            1
        );
    }

    #[test]
    fn pack_skips_already_in_place_encodings() {
        // Nothing to upload → no calls made.
        let (k, mut pa) = mk_pending_asset("/skip", "identity", vec![0u8; 100]);
        pa.encodings
            .get_mut(&Encoding::Identity)
            .unwrap()
            .already_in_place = true;
        pa.encodings.get_mut(&Encoding::Identity).unwrap().data = Vec::new();
        let mut assets = HashMap::from([(k, pa)]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        assert!(mock.batches.borrow().is_empty());
    }

    // ── execute_operations splitting ──────────────────────────────────────────────

    fn create_asset_with_headers(key: &str, hdr_bytes: usize) -> Operation {
        // One header whose name+value bytes sum to `hdr_bytes`.
        let name = "X-Pad".to_string();
        let value = "a".repeat(hdr_bytes.saturating_sub(name.len()));
        Operation::CreateAsset(CreateAssetArguments {
            key: key.to_string(),
            content_type: "text/plain".to_string(),
            headers: vec![(name, value)],
        })
    }

    fn set_content_op(key: &str) -> Operation {
        Operation::SetAssetContent(SetAssetContentArguments {
            key: key.to_string(),
            encoding: Encoding::Identity,
            chunk_ids: vec![0u64],
            sha256: serde_bytes::ByteBuf::from(vec![0u8; 32]),
            chunk_sha256: vec![serde_bytes::ByteBuf::from(vec![0u8; 32])],
        })
    }

    #[test]
    fn header_bytes_of_counts_create_asset_headers() {
        let op = create_asset_with_headers("/k", 1000);
        assert_eq!(header_bytes_of(&op), 1000);
    }

    #[test]
    fn header_bytes_of_returns_zero_for_headerless_kinds() {
        assert_eq!(header_bytes_of(&set_content_op("/k")), 0);
        assert_eq!(
            header_bytes_of(&Operation::DeleteAsset(DeleteAssetArguments {
                key: "/k".to_string(),
            })),
            0
        );
        assert_eq!(
            header_bytes_of(&Operation::UnsetAssetContent(UnsetAssetContentArguments {
                key: "/k".to_string(),
                encoding: Encoding::Identity,
            })),
            0
        );
    }

    #[test]
    fn header_bytes_of_sums_redirect_rule_headers() {
        // SetRedirectRules: only 3xx rules carry inlined headers; sum across rules.
        let rules = vec![
            RedirectRule {
                from: RulePattern::Exact("/a".into()),
                to: "/b".into(),
                status: 301,
                headers: vec![("X-A".into(), "1".into())], // 4 bytes
            },
            RedirectRule {
                from: RulePattern::Exact("/c".into()),
                to: "/d".into(),
                status: 200,
                headers: vec![],
            },
            RedirectRule {
                from: RulePattern::Exact("/e".into()),
                to: "/f".into(),
                status: 307,
                headers: vec![("X-B".into(), "22".into())], // 5 bytes
            },
        ];
        let op = Operation::SetRedirectRules(SetRedirectRulesArguments { rules });
        assert_eq!(header_bytes_of(&op), 9);
    }

    #[test]
    fn split_operation_groups_empty_input_returns_empty() {
        assert!(split_operation_groups(vec![]).is_empty());
    }

    #[test]
    fn split_operation_groups_small_input_stays_single_group() {
        // 100 small ops with tiny headers → fits both budgets in one group.
        let ops: Vec<Operation> = (0..100)
            .map(|i| create_asset_with_headers(&format!("/f{i}"), 10))
            .collect();
        let groups = split_operation_groups(ops);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 100);
    }

    #[test]
    fn split_operation_groups_splits_at_500_ops() {
        // 1200 headerless ops should split into 500/500/200 — three groups
        // driven purely by the operation-count cap.
        let ops: Vec<Operation> = (0..1200)
            .map(|i| set_content_op(&format!("/f{i}")))
            .collect();
        let groups = split_operation_groups(ops);
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![500, 500, 200]
        );
    }

    #[test]
    fn split_operation_groups_splits_at_header_budget() {
        // 4 ops × 500 KB headers = 2 MB > 1.5 MB cap. Split happens before
        // the 500-op cap could kick in.
        let ops: Vec<Operation> = (0..4)
            .map(|i| create_asset_with_headers(&format!("/f{i}"), 500_000))
            .collect();
        let groups = split_operation_groups(ops);
        // 3 ops × 500 KB = 1.5 MB fits exactly; the 4th would push over → split.
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 3);
        assert_eq!(groups[1].len(), 1);
    }

    #[test]
    fn split_operation_groups_oversized_op_gets_own_group() {
        // One op alone exceeds the header budget. The greedy loop must still
        // emit it (in its own group) rather than skip it.
        let ops = vec![
            create_asset_with_headers("/small", 10),
            create_asset_with_headers("/huge", 2_000_000),
            create_asset_with_headers("/small2", 10),
        ];
        let groups = split_operation_groups(ops);
        // First group flushes when /huge would overflow it → [/small], then
        // /huge alone (oversized but emitted), then /small2 alone (since /huge
        // already pushed header_bytes way over budget).
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 1);
        assert_eq!(groups[2].len(), 1);
    }

    // Mock that records every `execute_operations` call's
    // `(session_id, op_count, is_final)`. Used to verify that
    // `execute_in_stages` issues the right call sequence: every call carries
    // the real session id, and only the last is flagged final.
    struct CommitRecorder {
        calls: RefCell<Vec<(u64, usize, bool)>>,
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
        session_id: u64,
        operations: Vec<candid::Reserved>,
        is_final: bool,
    }

    impl CanisterCall for CommitRecorder {
        fn call<A, R>(&self, method: &str, arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "execute_operations");
            let bytes = candid::encode_one(&arg).map_err(|e| e.to_string())?;
            let req: CommitArgsMirror = candid::decode_one(&bytes).map_err(|e| e.to_string())?;
            self.calls
                .borrow_mut()
                .push((req.session_id, req.operations.len(), req.is_final));
            let reply = candid::encode_one(()).map_err(|e| e.to_string())?;
            candid::decode_one(&reply).map_err(|e| e.to_string())
        }
    }

    #[test]
    fn execute_in_stages_single_group_is_final() {
        // Small enough to fit in one group → one execute_operations call
        // carrying the real session id and flagged final.
        let ops: Vec<Operation> = (0..10).map(|i| set_content_op(&format!("/f{i}"))).collect();
        let mock = CommitRecorder::new();
        execute_in_stages(&mock, 42, ops).unwrap();
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (42, 10, true));
    }

    #[test]
    fn execute_in_stages_multi_group_flags_only_last_final() {
        // 1200 ops → three 500/500/200 groups, all carrying the real session
        // id; only the last is flagged final (which finalizes the sync).
        let ops: Vec<Operation> = (0..1200)
            .map(|i| set_content_op(&format!("/f{i}")))
            .collect();
        let mock = CommitRecorder::new();
        execute_in_stages(&mock, 42, ops).unwrap();
        let calls = mock.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![(42, 500, false), (42, 500, false), (42, 200, true)]
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
                vec![1u64]
            };
            enc_map.insert(
                Encoding::from_token(name).expect("supported test encoding"),
                ProjectAssetEncoding {
                    chunk_ids,
                    sha256: sha.clone(),
                    chunk_sha256: Vec::new(),
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
        encodings: &[(&str, Vec<u8>)],
    ) -> (String, AssetDetails) {
        let encs = encodings
            .iter()
            .map(|(enc, sha)| AssetEncodingDetails {
                encoding: Encoding::from_token(enc).expect("supported test encoding"),
                sha256: serde_bytes::ByteBuf::from(sha.clone()),
            })
            .collect();
        (
            key.to_string(),
            AssetDetails {
                key: key.to_string(),
                encodings: encs,
                content_type: content_type.to_string(),
                headers: vec![],
            },
        )
    }

    // Like `mk_canister_asset`, but with the per-asset response headers the
    // `list` query would report — for exercising the headers diff.
    fn mk_canister_asset_with_headers(
        key: &str,
        content_type: &str,
        encodings: &[(&str, Vec<u8>)],
        headers: &[(&str, &str)],
    ) -> (String, AssetDetails) {
        let (k, mut details) = mk_canister_asset(key, content_type, encodings);
        details.headers = headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        (k, details)
    }

    fn count_op(ops: &[Operation], kind: &str) -> usize {
        ops.iter()
            .filter(|op| {
                matches!(
                    (op, kind),
                    (Operation::DeleteAsset(_), "DeleteAsset")
                        | (Operation::CreateAsset(_), "CreateAsset")
                        | (Operation::SetAssetContent(_), "SetAssetContent")
                        | (Operation::UnsetAssetContent(_), "UnsetAssetContent")
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[], &[]);
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
            &[("identity", sha)],
        )]);
        assert!(build_operations(&project, &canister, &[], &[], &[]).is_empty());
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
            &[("identity", vec![1, 2, 3])],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
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
            &[("identity", vec![1, 2, 3])],
        )]);
        let ops = build_operations(&HashMap::new(), &canister, &[], &[], &[]);
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
            &[("identity", vec![1, 2, 3])],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
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
            &[("identity", sha), ("gzip", vec![9, 8, 7])],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
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
            &[("identity", identity_sha)],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 0);
        assert_eq!(count_op(&ops, "UnsetAssetContent"), 0);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn empty_project_deletes_all_canister_assets() {
        let canister = HashMap::from([
            mk_canister_asset("/a.html", "text/html", &[("identity", vec![1])]),
            mk_canister_asset("/b.js", "application/javascript", &[("identity", vec![2])]),
        ]);
        let ops = build_operations(&HashMap::new(), &canister, &[], &[], &[]);
        assert_eq!(count_op(&ops, "DeleteAsset"), 2);
        assert_eq!(ops.len(), 2);
    }

    // ── redirect-rule diff ──────────────────────────────────────────────────

    fn mk_rule(from: RulePattern, to: &str, status: u16) -> RedirectRule {
        RedirectRule {
            from,
            to: to.to_string(),
            status,
            headers: vec![],
        }
    }

    fn set_rules_op(ops: &[Operation]) -> Option<&[RedirectRule]> {
        ops.iter().find_map(|op| match op {
            Operation::SetRedirectRules(args) => Some(args.rules.as_slice()),
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
            &[("identity", sha)],
        )]);
        let project_rules = vec![mk_rule(RulePattern::Exact("/old".into()), "/new", 301)];
        let ops = build_operations(&project, &canister, &project_rules, &[], &[]);
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
        let canister_rules = vec![mk_rule(RulePattern::Exact("/old".into()), "/new", 301)];
        let ops = build_operations(&HashMap::new(), &HashMap::new(), &[], &canister_rules, &[]);
        let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert!(rules.is_empty(), "expected empty-vec replace-all op");
    }

    #[test]
    fn unchanged_rules_emit_no_op() {
        // Same rules on both sides — no SetRedirectRules op emitted.
        let rules = vec![mk_rule(
            RulePattern::Subtree("/blog/".into()),
            "/blog/index.html",
            200,
        )];
        let ops = build_operations(&HashMap::new(), &HashMap::new(), &rules, &rules, &[]);
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
        let a = mk_rule(RulePattern::Exact("/a".into()), "/x", 301);
        let b = mk_rule(RulePattern::Exact("/b".into()), "/y", 301);
        let ops = build_operations(
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
        // must trigger, with no start_sync / execute_operations calls.
        //
        // The project ships no root 404.html and no `/*` rule, so the sync
        // path injects a branded /404.html asset, synthesises its html-handling
        // rules, and appends the `/*` catch-all — all of which the canister
        // must already hold for the diff to be empty.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("_redirects"), b"/old /new 301\n").unwrap();

        let mut canister_rules =
            crate::html_handling::synthesize(&[not_found::ROOT_404_KEY.into()]);
        canister_rules.push(mk_rule(RulePattern::Exact("/old".into()), "/new", 301));
        canister_rules.push(not_found::catchall_rule());

        let mock = SyncMock::new();
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        mock.push_ok("get_asset_details", vec![branded_404_canister_asset(&[])]);
        // Trailing empty page terminates list_all_assets' cursor walk.
        mock.push_ok("get_asset_details", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", canister_rules);
        // Trailing empty page terminates list_all_redirect_rules' cursor walk.
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        // No start_sync / execute_operations programmed — if sync reached them
        // SyncMock would panic with "no programmed response".
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    // Mirrors the private `StartSyncResult` in canister.rs — same variant and
    // field names give the same Candid encoding, so the test mock can decode it.
    #[derive(CandidType)]
    enum StartSyncOk {
        Started {
            session_id: u64,
        },
        #[allow(dead_code)]
        Busy {
            owner: Principal,
            idle_for_secs: u64,
        },
    }

    #[test]
    fn sync_emits_rules_op_when_redirects_file_only_changed() {
        // _redirects has a rule; canister is empty. The project ships no root
        // 404.html and no `/*` rule, so the sync path also injects a branded
        // /404.html asset and appends the `/*` catch-all — meaning the diff
        // carries both the asset upload and the SetRedirectRules op. We only
        // assert the run succeeds end-to-end (the per-op shape is covered by
        // build_operations unit tests).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("_redirects"), b"/old /new 301\n").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        mock.push_ok("get_asset_details", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());
        mock.push_ok("start_sync", StartSyncOk::Started { session_id: 1 });
        // Injected /404.html bytes are uploaded before operations execute.
        mock.push_ok("upload_chunks", ());
        mock.push_ok("execute_operations", ());

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
        let asset = prepare_asset(source, &[], &HashMap::new()).unwrap();
        assert!(
            asset.encodings.contains_key(&Encoding::Identity),
            "identity must be present"
        );
        assert!(
            !asset.encodings.contains_key(&Encoding::Gzip),
            "gzip must be absent when not smaller"
        );
    }

    // A compressible asset whose content actually shrinks gets all three stored
    // encodings: identity (always), plus gzip and brotli. This is the headline
    // behaviour change — brotli is now produced alongside gzip for text-like
    // content. Highly repetitive text guarantees both compressors beat identity,
    // so neither is dropped by the keep-if-smaller guard.
    #[test]
    fn prepare_asset_keeps_gzip_and_brotli_for_compressible() {
        use std::io::Write;
        let mut f = tempfile::Builder::new().suffix(".css").tempfile().unwrap();
        f.write_all("body { color: red; }\n".repeat(500).as_bytes())
            .unwrap();
        let source = AssetSource {
            path: f.path().to_path_buf(),
            key: "/style.css".to_string(),
        };
        let asset = prepare_asset(source, &[], &HashMap::new()).unwrap();
        let mut encs: Vec<Encoding> = asset.encodings.keys().copied().collect();
        encs.sort();
        assert_eq!(
            encs,
            vec![Encoding::Identity, Encoding::Gzip, Encoding::Brotli],
            "compressible content should store identity + gzip + brotli"
        );
    }

    // `_headers` Content-Type override drives both the stored media type and
    // the encoder selection. Without the override, a `.did` file is
    // `application/octet-stream` (mime_guess has no entry) and gets only the
    // identity encoding; with the override to `text/plain`, encoders_for
    // selects gzip too.
    #[test]
    fn header_content_type_override_applies_to_prepare_asset() {
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
        let without = prepare_asset(mk_source(), &[], &HashMap::new()).unwrap();
        assert_eq!(without.media_type.to_string(), "application/octet-stream");
        assert!(!without.encodings.contains_key(&Encoding::Gzip));

        // With override to text/plain via `_headers`, both the media type
        // and the encoder pick change.
        let rules =
            crate::headers::parse("/*.did\n  Content-Type: text/plain; charset=utf-8\n").unwrap();
        let with = prepare_asset(mk_source(), &rules, &HashMap::new()).unwrap();
        assert_eq!(with.media_type.to_string(), "text/plain; charset=utf-8");
        assert!(
            with.encodings.contains_key(&Encoding::Gzip),
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[], &[]);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
        assert!(!ops.iter().any(|op| matches!(
            op,
            Operation::SetAssetContent(a) if a.encoding == Encoding::Gzip
        )));
    }

    #[test]
    fn create_asset_args_use_defaults() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &[], &[], &[]);
        let create_op = ops
            .iter()
            .find_map(|op| {
                if let Operation::CreateAsset(a) = op {
                    Some(a)
                } else {
                    None
                }
            })
            .expect("CreateAsset op");

        assert!(create_op.headers.is_empty());
    }

    fn set_header_ops(
        ops: &[Operation],
    ) -> std::collections::BTreeMap<&str, &SetAssetHeadersArguments> {
        ops.iter()
            .filter_map(|op| match op {
                Operation::SetAssetHeaders(a) => Some((a.key.as_str(), a)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn update_headers_emits_nothing_when_canister_matches_defaults() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
        assert!(
            set_header_ops(&ops).is_empty(),
            "no SetAssetHeaders op when canister already matches defaults"
        );
    }

    #[test]
    fn update_headers_clears_canister_headers() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset_with_headers(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
            &[("X-Frame-Options", "DENY")],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
        let by_key = set_header_ops(&ops);
        assert_eq!(by_key.len(), 1);
        // An empty headers vec clears the headers map on the canister.
        assert!(by_key["/index.html"].headers.is_empty());
    }

    #[test]
    fn update_headers_skips_assets_being_recreated_due_to_content_type_drift() {
        // Asset on canister has a different content_type → step 1 deletes it
        // and step 2 recreates it with default headers. update_headers
        // must not emit a redundant SetAssetHeaders op for that key, even
        // though the canister asset still carries (pre-deletion) headers.
        let project = HashMap::from([mk_project_asset(
            "/file",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let canister = HashMap::from([mk_canister_asset_with_headers(
            "/file",
            "application/octet-stream",
            &[("identity", vec![1, 2, 3])],
            &[("X-Frame-Options", "DENY")],
        )]);
        let ops = build_operations(&project, &canister, &[], &[], &[]);
        assert_eq!(count_op(&ops, "DeleteAsset"), 1);
        assert_eq!(count_op(&ops, "CreateAsset"), 1);
        assert!(
            set_header_ops(&ops).is_empty(),
            "no SetAssetHeaders op when the asset is being recreated in the same batch"
        );
    }

    #[test]
    fn update_headers_skips_assets_not_on_canister() {
        // Asset is new to the canister — headers get set via CreateAsset,
        // not SetAssetHeaders.
        let project = HashMap::from([mk_project_asset(
            "/new.html",
            "text/html",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &[], &[], &[]);
        assert!(set_header_ops(&ops).is_empty());
    }

    // ── _headers integration ───────────────────────────────────────────────

    fn mk_header_rule(pattern_src: &str, headers: &[(&str, &str)]) -> HeaderRule {
        HeaderRule {
            pattern: crate::glob::parse(pattern_src).unwrap(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            content_type: None,
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[], &header_rules);
        let create_op = ops
            .iter()
            .find_map(|op| match op {
                Operation::CreateAsset(a) => Some(a),
                _ => None,
            })
            .expect("CreateAsset op");
        assert_eq!(
            create_op.headers,
            vec![("X-Frame-Options".to_string(), "DENY".to_string())]
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[], &header_rules);
        let create_op = ops
            .iter()
            .find_map(|op| match op {
                Operation::CreateAsset(a) => Some(a),
                _ => None,
            })
            .expect("CreateAsset op");
        assert!(create_op.headers.is_empty());
    }

    #[test]
    fn update_headers_sets_headers_when_canister_missing_them() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
        )]);
        let header_rules = vec![mk_header_rule("/*", &[("X-Frame-Options", "DENY")])];
        let ops = build_operations(&project, &canister, &[], &[], &header_rules);
        let by_key = set_header_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert_eq!(
            by_key["/index.html"].headers,
            vec![("X-Frame-Options".to_string(), "DENY".to_string())]
        );
    }

    #[test]
    fn update_headers_clears_headers_when_no_rules_match() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset_with_headers(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
            &[("X-Frame-Options", "DENY")],
        )]);
        // No header rules — canister-stored headers should be cleared.
        let ops = build_operations(&project, &canister, &[], &[], &[]);
        let by_key = set_header_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert!(by_key["/index.html"].headers.is_empty());
    }

    #[test]
    fn three_xx_redirect_rule_carries_resolved_headers() {
        // 3xx rules synthesize their response; populate `headers` from any
        // `_headers` rule whose pattern matches the redirect's `from`.
        let header_rules = vec![mk_header_rule("/*", &[("X-Robots-Tag", "noindex")])];
        let project_rules = vec![mk_rule(RulePattern::Exact("/old".into()), "/new", 301)];
        let ops = build_operations(
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
            vec![("X-Robots-Tag".to_string(), "noindex".to_string())]
        );
    }

    #[test]
    fn non_3xx_redirect_rule_does_not_carry_resolved_headers() {
        // 200 / 4xx rules inherit headers from their target asset, so the
        // plugin must leave `RedirectRule.headers` empty even when a
        // matching `_headers` rule exists.
        let header_rules = vec![mk_header_rule("/*", &[("X-Robots-Tag", "noindex")])];
        for status in [200u16, 404, 410] {
            let project_rules = vec![mk_rule(
                RulePattern::Exact("/old".into()),
                "/target.html",
                status,
            )];
            let ops = build_operations(
                &HashMap::new(),
                &HashMap::new(),
                &project_rules,
                &[],
                &header_rules,
            );
            let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
            assert_eq!(rules.len(), 1);
            assert!(
                rules[0].headers.is_empty(),
                "status {status}: expected no headers on non-3xx rule"
            );
        }
    }

    #[test]
    fn three_xx_redirect_rule_omits_headers_when_no_match() {
        let header_rules = vec![mk_header_rule("/other", &[("X-Foo", "bar")])];
        let project_rules = vec![mk_rule(RulePattern::Exact("/old".into()), "/new", 301)];
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            &project_rules,
            &[],
            &header_rules,
        );
        let rules = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert!(rules[0].headers.is_empty());
    }

    #[test]
    fn redirect_rules_match_when_headers_populated_matches_canister() {
        // Canister stores the same rule (with the resolved 3xx headers) — no
        // SetRedirectRules op should be emitted.
        let header_rules = vec![mk_header_rule("/*", &[("X-Robots-Tag", "noindex")])];
        let project_rules = vec![mk_rule(RulePattern::Exact("/old".into()), "/new", 301)];
        let canister_rules = vec![RedirectRule {
            from: RulePattern::Exact("/old".into()),
            to: "/new".to_string(),
            status: 301,
            headers: vec![("X-Robots-Tag".into(), "noindex".into())],
        }];
        let ops = build_operations(
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
    fn update_headers_no_op_when_canister_headers_match_resolved() {
        let project = HashMap::from([mk_project_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3], true)],
        )]);
        let canister = HashMap::from([mk_canister_asset_with_headers(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
            &[("X-Frame-Options", "DENY")],
        )]);
        let header_rules = vec![mk_header_rule("/*", &[("X-Frame-Options", "DENY")])];
        let ops = build_operations(&project, &canister, &[], &[], &header_rules);
        assert!(
            set_header_ops(&ops).is_empty(),
            "no SetAssetHeaders op when resolved headers byte-match canister-stored"
        );
    }

    // ---- Authorization tests ----

    // Mock for ensure_can_sync: handles can_sync and authorize only.
    struct PermissionMock {
        // What the canister's `can_sync` reports for the identity.
        can_sync: bool,
        // Tracks the `direct` flag for each authorize call.
        authorize_calls: RefCell<Vec<bool>>,
    }

    impl PermissionMock {
        fn new(can_sync: bool) -> Self {
            Self {
                can_sync,
                authorize_calls: RefCell::new(vec![]),
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
                "can_sync" => {
                    let bytes = candid::encode_one(self.can_sync).map_err(|e| e.to_string())?;
                    candid::decode_one(&bytes).map_err(|e| e.to_string())
                }
                "authorize" => {
                    self.authorize_calls.borrow_mut().push(direct);
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

    // Proxy mode: identity cannot sync yet → authorize called via proxy.
    #[test]
    fn ensure_can_sync_grants_via_proxy_when_absent() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(false);
        ensure_can_sync(&mock, &identity.to_text(), true).unwrap();
        // authorize must be called exactly once with direct=false (routed via proxy).
        assert_eq!(*mock.authorize_calls.borrow(), vec![false]);
    }

    // Proxy mode: identity can already sync → authorize not called.
    #[test]
    fn ensure_can_sync_skips_grant_when_already_authorized() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(true);
        ensure_can_sync(&mock, &identity.to_text(), true).unwrap();
        assert!(mock.authorize_calls.borrow().is_empty());
    }

    // Direct mode: identity can sync (authorized or a controller) → succeeds,
    // no authorize call.
    #[test]
    fn ensure_can_sync_direct_mode_ok_when_can_sync() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(true);
        ensure_can_sync(&mock, &identity.to_text(), false).unwrap();
        assert!(mock.authorize_calls.borrow().is_empty());
    }

    // Direct mode: identity cannot sync → fails fast (no proxy to grant through).
    #[test]
    fn ensure_can_sync_direct_mode_fails_fast_when_cannot_sync() {
        let identity = Principal::anonymous();
        let mock = PermissionMock::new(false);
        let err = ensure_can_sync(&mock, &identity.to_text(), false).unwrap_err();
        assert!(err.contains("not authorized"), "got: {err}");
        assert!(mock.authorize_calls.borrow().is_empty());
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

    #[test]
    fn sync_short_circuits_when_headers_file_only_matches_canister() {
        // The canister already stores the headers a `_headers`-only project
        // would resolve. The "nothing to commit" short-circuit must trigger.
        // The asset is `.txt`, not `.html`, so the auto-synthesised
        // html-handling rules don't get in the way of the comparison.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"hello").unwrap();
        let headers_file = b"/*\n  X-Frame-Options: DENY\n";
        std::fs::write(dir.path().join("_headers"), headers_file).unwrap();

        use sha2::Digest;
        let identity_sha = sha2::Sha256::digest(b"hello").to_vec();

        // No root 404.html and no `/*` rule, so the sync path injects a branded
        // /404.html (which the `/*` _headers rule also covers) plus its
        // html-handling rules and the `/*` catch-all; the canister must already
        // hold all of it for the short-circuit to fire.
        let header_rules =
            crate::headers::parse(std::str::from_utf8(headers_file).unwrap()).unwrap();
        let mut synth = crate::html_handling::synthesize(&[not_found::ROOT_404_KEY.into()]);
        synth.push(not_found::catchall_rule());
        // The canister stores rules with `_headers` resolved into 3xx rules, so
        // mirror that here or the comparison would spuriously differ.
        let canister_rules = resolve_3xx_rule_headers(&synth, &header_rules);

        let mock = SyncMock::new();
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        mock.push_ok(
            "get_asset_details",
            vec![
                AssetDetails {
                    key: "/notes.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    encodings: vec![AssetEncodingDetails {
                        encoding: Encoding::Identity,
                        sha256: serde_bytes::ByteBuf::from(identity_sha),
                    }],
                    // Matches what `_headers` resolves to, so no SetAssetHeaders.
                    headers: vec![("X-Frame-Options".into(), "DENY".into())],
                },
                branded_404_canister_asset(&header_rules),
            ],
        );
        mock.push_ok("get_asset_details", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", canister_rules);
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        // No start_sync / execute_operations programmed — would panic if reached.
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
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        mock.push_ok("get_asset_details", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());
        mock.push_ok("start_sync", StartSyncOk::Started { session_id: 1 });
        mock.push_ok("upload_chunks", ());
        mock.push_ok("execute_operations", ());

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
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
            .find(|r| matches!(&r.from, RulePattern::Exact(p) if p == "/index"))
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
            .position(|r| matches!(&r.from, RulePattern::Exact(p) if p == "/index"))
            .expect("a rule at /index");
        let catchall_pos = combined
            .iter()
            .position(|r| matches!(&r.from, RulePattern::Subtree(p) if p == "/"))
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
        // start_sync.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        use sha2::Digest;
        let identity_sha = sha2::Sha256::digest(b"<html></html>").to_vec();

        // The project ships no root 404.html and no `/*` rule, so the injected
        // branded /404.html joins /index.html in html-handling synthesis, and
        // the `/*` catch-all is appended. The canister already holds the full
        // set, so nothing is committed.
        let mut canister_rules = crate::html_handling::synthesize(&[
            "/index.html".to_string(),
            not_found::ROOT_404_KEY.to_string(),
        ]);
        canister_rules.push(not_found::catchall_rule());

        let mock = SyncMock::new();
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        mock.push_ok(
            "get_asset_details",
            vec![
                AssetDetails {
                    key: "/index.html".to_string(),
                    content_type: "text/html".to_string(),
                    encodings: vec![AssetEncodingDetails {
                        encoding: Encoding::Identity,
                        sha256: serde_bytes::ByteBuf::from(identity_sha),
                    }],
                    headers: vec![],
                },
                branded_404_canister_asset(&[]),
            ],
        );
        mock.push_ok("get_asset_details", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", canister_rules);
        // Trailing empty page terminates list_all_redirect_rules' cursor walk.
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        // No start_sync / execute_operations programmed — would panic if reached.
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    // Direct mode: identity passes the early authorization check, but a later
    // start_sync failure (e.g. the authorized set changed under us) must
    // still propagate.
    #[test]
    fn sync_propagates_error_from_start_sync() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        let mock = SyncMock::new();
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        // Empty canister → build_operations will produce work → start_sync is called.
        mock.push_ok("get_asset_details", Vec::<AssetDetails>::new());
        mock.push_ok("get_redirect_rules", Vec::<RedirectRule>::new());
        mock.push_err(
            "start_sync",
            "Caller is not authorized to sync assets and is not a controller.",
        );

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );

        let err = result.unwrap_err();
        assert!(
            err.contains("not authorized"),
            "expected start_sync error to propagate, got: {err}"
        );
    }

    // Direct mode: identity absent from the authorized set → sync fails fast,
    // before any local scanning or canister diffing.
    #[test]
    fn sync_fails_fast_when_identity_not_authorized_in_direct_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<html></html>").unwrap();

        let mock = SyncMock::new();
        // Only can_sync is programmed: if sync reached scanning/diffing (list,
        // get_redirect_rules, …) SyncMock would panic on the unprogrammed
        // method. can_sync=false means the identity cannot sync.
        mock.push_ok("can_sync", false);

        let err = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("not authorized"), "got: {err}");
    }
}
