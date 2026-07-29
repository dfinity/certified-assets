//! Orchestrates: load assets, diff against canister, upload chunks, commit batch.
//!
//! V2-only port of `ic-asset`'s `sync` flow, simplified:
//! - synchronous (drives the host's sync `canister-call` import)
//! - no proposal mode

use candid::Principal;
use serde_bytes::ByteBuf;
use std::collections::HashMap;

use crate::canister::{
    CallType, CanisterCall, authorize_via_proxy, can_sync, execute_operations, list_all_assets,
    list_all_redirect_rules, start_sync, version,
};
use asset_prep::{
    MAX_CHUNK_SIZE, PlannedAsset, PreparedAsset, PreparedChunk, ProjectPlan, plan_project,
};
use wire_types::{
    AssetDetails, ChunkId, CreateAssetArguments, DeleteAssetArguments, Encoding,
    ExecuteOperationsArguments, Operation, RedirectRule, RulePattern, SetAssetContentArguments,
    SetAssetHeadersArguments, SetRedirectRulesArguments, UnsetAssetContentArguments,
    UploadChunksArguments,
};

/// One encoding of an asset, as the canister diff/upload sees it: the prepared
/// chunks from `asset-prep` (their bytes are taken during upload, leaving the
/// per-chunk `len`/`sha256` for certification) plus the sync diff state.
struct ProjectAssetEncoding {
    /// Whole-encoding hash, certified as the single-chunk 200 body hash.
    sha256: [u8; 32],
    /// Per-chunk `(len, sha256, bytes)` from `asset-prep::prepare_project`. The
    /// bytes are `take`n into the upload buffer in `pack_and_upload_chunks`; the
    /// `len`/`sha256` remain for multi-chunk 206 certification.
    chunks: Vec<PreparedChunk>,
    /// This exact encoding (same content_type + sha256) is already on the
    /// canister, so it is neither uploaded nor re-set.
    already_in_place: bool,
    /// Chunk ids assigned in `pack_and_upload_chunks`; one per chunk, in order.
    chunk_ids: Vec<u64>,
}

struct ProjectAsset {
    key: String,
    content_type: String,
    /// Per-asset response headers, already resolved from `_headers` by
    /// `asset-prep`'s planning phase — the canonical stored form. Used as-is by
    /// `build_operations` (no re-resolution).
    headers: Vec<(String, String)>,
    encodings: HashMap<Encoding, ProjectAssetEncoding>,
    /// Whether any encoding will be stored as more than one chunk. Used to reject
    /// 4xx error-page rules whose target is too large to serve as a single inline
    /// body (see [`validate_error_page_targets`]).
    ///
    /// Carried as a flag rather than derived from `encodings` because an asset
    /// the canister already holds is never encoded, so it has no chunks here.
    /// `asset-prep` decides it from the uncompressed length alone.
    multichunk: bool,
}

/// Turns the planned assets into the keyed diff structure the sync pipeline
/// operates on — **encoding only what the canister doesn't already hold.**
///
/// For each planned asset, [`current_encodings`] asks whether the canister's
/// stored content is already exactly what preparation would produce. When it is,
/// the asset is adopted as-is (every encoding already in place, nothing to
/// upload) and the expensive gzip/brotli pass is skipped entirely — which is
/// where a re-deploy's local cost goes. Otherwise it is encoded and diffed
/// per-encoding, so a partially-current asset still uploads only what's missing.
///
/// Note this skips *encoding*, never *diffing*: headers and content_type are
/// compared for every asset either way, since `_headers` can change while
/// content doesn't.
fn diff_assets(
    planned: Vec<PlannedAsset>,
    canister_assets: &HashMap<String, AssetDetails>,
) -> Result<HashMap<String, ProjectAsset>, String> {
    let mut project_assets = HashMap::with_capacity(planned.len());
    let mut reused = 0usize;

    for asset in planned {
        let multichunk = asset.is_multichunk();
        let project_asset = match current_encodings(&asset, canister_assets.get(&asset.key)) {
            Some(encodings) => {
                reused += 1;
                ProjectAsset {
                    key: asset.key,
                    content_type: asset.content_type,
                    headers: asset.headers,
                    encodings,
                    multichunk,
                }
            }
            None => {
                let PreparedAsset {
                    key,
                    content_type,
                    headers,
                    encodings,
                } = asset.encode()?;
                let encodings = encodings
                    .into_iter()
                    .map(|enc| {
                        let already_in_place = is_already_in_place(
                            &key,
                            &content_type,
                            enc.encoding,
                            &enc.sha256,
                            canister_assets,
                        );
                        (
                            enc.encoding,
                            ProjectAssetEncoding {
                                sha256: enc.sha256,
                                chunks: enc.chunks,
                                already_in_place,
                                chunk_ids: Vec::new(),
                            },
                        )
                    })
                    .collect();
                ProjectAsset {
                    key,
                    content_type,
                    headers,
                    encodings,
                    multichunk,
                }
            }
        };

        project_assets.insert(project_asset.key.clone(), project_asset);
    }

    println!(
        "encoded {} asset(s); {reused} already current on the canister",
        project_assets.len() - reused
    );
    Ok(project_assets)
}

/// The canister's encodings for `planned`, when the canister already holds
/// exactly the content preparation would produce — so encoding can be skipped.
///
/// Sound because compression is deterministic: for a given build of
/// `asset-prep`, every compressed encoding is a pure function of the identity
/// bytes. So if the canister holds the same identity hash under the same
/// `content_type`, its compressed encodings are byte-identical to the ones we
/// would spend brotli time recomputing.
///
/// Three things must line up, and the third is deliberately strict:
///
/// 1. same `content_type` — it is part of the stored, certified response;
/// 2. same identity hash — identity is always kept, so it is always reported;
/// 3. the stored encoding set is *exactly* the set preparation attempts.
///
/// (3) is what makes this safe without extra canister state. A missing
/// compressed encoding is ambiguous — it could mean "compression didn't shrink
/// this asset" or "an earlier deploy died mid-upload" — and the two are
/// indistinguishable without doing the compression. Treating any mismatch as
/// stale re-encodes those assets on every sync, but an asset whose compressed
/// form isn't smaller than its identity form is tiny by definition, so the cost
/// is noise.
///
/// This also relies on preparation parameters being frozen within a release
/// series: the version lock pairs *code*, but a canister upgraded in place still
/// holds content written by an earlier build of the same series.
fn current_encodings(
    planned: &PlannedAsset,
    canister_asset: Option<&AssetDetails>,
) -> Option<HashMap<Encoding, ProjectAssetEncoding>> {
    let canister_asset = canister_asset?;
    if canister_asset.content_type != planned.content_type {
        return None;
    }

    let attempted = planned.attempted_encodings();
    if canister_asset.encodings.len() != attempted.len()
        || !attempted.iter().all(|encoding| {
            canister_asset
                .encodings
                .iter()
                .any(|d| d.encoding == *encoding)
        })
    {
        return None;
    }

    let mut encodings = HashMap::with_capacity(canister_asset.encodings.len());
    for details in &canister_asset.encodings {
        // A malformed hash can't be matched or reused; treat the asset as stale
        // and let the normal path re-upload it.
        let sha256: [u8; 32] = details.sha256.as_ref().try_into().ok()?;
        if details.encoding.is_identity() && sha256 != planned.identity_sha256 {
            return None;
        }
        encodings.insert(
            details.encoding,
            ProjectAssetEncoding {
                sha256,
                chunks: Vec::new(),
                already_in_place: true,
                chunk_ids: Vec::new(),
            },
        );
    }
    Some(encodings)
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
        if project_assets.get(&rule.to).is_some_and(|a| a.multichunk) {
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
            ));
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

    // Plan the project's `dist/`: scan + parse `_redirects`/`_headers` +
    // synthesise html-handling/404 rules + load each asset, resolve its media
    // type and headers, and hash its uncompressed bytes. This is the cheap half
    // of the canister-agnostic preparation path shared with the offline
    // `state-hash-cli` verifier (see `asset-prep`); the expensive half —
    // gzip/brotli — is deferred to `diff_assets`, which runs it only for assets
    // the canister doesn't already hold.
    let plan = plan_project(dir)?;
    println!("planned {} asset(s) from {dir}", plan.assets.len());
    println!(
        "{} redirect rule(s) (incl. synthesised)",
        plan.redirect_rules.len()
    );

    let ProjectPlan {
        assets: planned_assets,
        // Already in canonical stored form — 3xx rules carry their resolved
        // `_headers`. Used directly in the diff; no re-resolution.
        redirect_rules: project_rules,
    } = plan;

    let canister_assets: HashMap<String, AssetDetails> = list_all_assets(canister)?;
    println!("canister currently has {} asset(s)", canister_assets.len());

    let canister_rules = list_all_redirect_rules(canister)?;
    println!(
        "canister currently has {} redirect rule(s)",
        canister_rules.len()
    );

    // Phase 1: encode what's stale and compute the diff — no batch created yet.
    let mut project_assets = diff_assets(planned_assets, &canister_assets)?;

    // Reject oversized 4xx error-page targets before starting a sync.
    validate_error_page_targets(&project_rules, &project_assets)?;

    if build_operations(
        &project_assets,
        &canister_assets,
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

    // Phase 2: start a sync and upload chunks for encodings not already in place.
    let session_id = start_sync(canister)?;
    println!("started sync session {session_id}");

    pack_and_upload_chunks(canister, session_id, &mut project_assets)?;

    let operations = build_operations(
        &project_assets,
        &canister_assets,
        &project_rules,
        &canister_rules,
    );
    println!("executing {} operation(s)", operations.len());

    // The canister recomputes its canonical state hash while finalizing the last
    // group and hands it back, so the summary can report it without a second
    // round trip. It is *canister-reported* — a self-consistency read, not
    // third-party verification; for that, run `state-hash <dist>` offline and
    // compare against the canister's `state_hash()` (see
    // `docs/verifying-contents.md`).
    let state_hash = execute_in_stages(canister, session_id, operations)?;

    Ok(match state_hash {
        Some(hash) => format!(
            "synced {} asset(s) to canister; canister reports state hash {}",
            project_assets.len(),
            hex::encode(hash)
        ),
        None => format!("synced {} asset(s) to canister", project_assets.len()),
    })
}

/// Whether the canister already holds this exact encoding (same `content_type`
/// and whole-encoding `sha256`), so it need not be uploaded or re-set.
fn is_already_in_place(
    key: &str,
    content_type: &str,
    encoding: Encoding,
    sha256: &[u8; 32],
    canister_assets: &HashMap<String, AssetDetails>,
) -> bool {
    let Some(canister_asset) = canister_assets.get(key) else {
        return false;
    };
    if canister_asset.content_type != content_type {
        return false;
    }
    canister_asset
        .encodings
        .iter()
        .find(|d| d.encoding == encoding)
        .is_some_and(|d| d.sha256.as_ref() == sha256)
}

/// Pack-and-upload pass: collect every chunk from every not-yet-uploaded
/// encoding across all assets, then ship them in `upload_chunks` calls of up
/// to `MAX_CHUNK_SIZE` total bytes each.
///
/// This is where the wall-clock win lives versus the old "one chunk per call"
/// pattern: a project of 100 small files used to make 100 round-trips; now
/// they ride in a single call (≈1.9 MB budget).
///
/// Chunk ids come back over the wire. Each `upload_chunks` call returns the ids
/// the canister assigned to its chunks, in that call's content order. We scatter
/// `results[i][j]` into the slot that produced the j-th chunk of the i-th call —
/// a purely positional mapping, with no assumption about the order the calls ran
/// relative to one another. That is exactly what lets the transport issue these
/// calls concurrently (see `CanisterCall::dispatch_batch`).
///
/// Routing is by `(asset_key, encoding, chunk_index)`: each chunk carries a
/// `Slot` recording where its returned id must land in `enc.chunk_ids`.
fn pack_and_upload_chunks<C: CanisterCall>(
    canister: &C,
    session_id: u64,
    project_assets: &mut HashMap<String, ProjectAsset>,
) -> Result<(), String> {
    /// Where a single chunk's returned id must land.
    struct Slot {
        asset_key: String,
        encoding: Encoding,
        chunk_index: usize,
    }

    struct PendingChunk {
        slot: Slot,
        data: Vec<u8>,
    }

    let mut pending: Vec<PendingChunk> = Vec::new();
    for asset in project_assets.values_mut() {
        let key = asset.key.clone();
        for (&encoding, enc) in &mut asset.encodings {
            if enc.already_in_place {
                continue;
            }
            // Chunks were already sliced and per-chunk hashed by `asset-prep`.
            // Take each chunk's bytes into the upload buffer, leaving its
            // `len`/`sha256` behind for multi-chunk 206 certification.
            enc.chunk_ids = vec![0u64; enc.chunks.len()];
            for (i, chunk) in enc.chunks.iter_mut().enumerate() {
                pending.push(PendingChunk {
                    slot: Slot {
                        asset_key: key.clone(),
                        encoding,
                        chunk_index: i,
                    },
                    data: std::mem::take(&mut chunk.data),
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
    let mut total_bytes = 0u64;

    // Build one upload call per batch, keeping each batch's per-chunk routing
    // alongside its arguments so the returned ids can be scattered back by
    // position after the calls complete.
    let mut args: Vec<UploadChunksArguments> = Vec::new();
    let mut batch_routes: Vec<Vec<Slot>> = Vec::new();

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
        total_bytes += batch_size as u64;

        // Split each pending chunk into its wire bytes (moved into the request)
        // and its routing `Slot` (kept for the scatter below). Candid copies the
        // bytes on encode either way, so taking them here is a move, not a copy.
        let mut chunks = Vec::with_capacity(batch.len());
        let mut routes = Vec::with_capacity(batch.len());
        for p in batch {
            chunks.push(ByteBuf::from(p.data));
            routes.push(p.slot);
        }
        args.push(UploadChunksArguments { session_id, chunks });
        batch_routes.push(routes);
    }

    let total_calls = args.len();

    // Issue every batch through the typed batch seam. `call_batch` returns one
    // `Vec<ChunkId>` per batch, positionally (result i ↔ batch i); the transport
    // decides whether to run them sequentially or concurrently.
    let results =
        canister.call_batch::<_, Vec<ChunkId>>("upload_chunks", args, CallType::Update, true);

    for (routes, result) in batch_routes.into_iter().zip(results) {
        let ids = result?;
        if ids.len() != routes.len() {
            return Err(format!(
                "upload_chunks returned {} ids for {} chunk(s)",
                ids.len(),
                routes.len()
            ));
        }
        for (slot, id) in routes.into_iter().zip(ids) {
            let enc = project_assets
                .get_mut(&slot.asset_key)
                .expect("asset present (collected above)")
                .encodings
                .get_mut(&slot.encoding)
                .expect("encoding present (collected above)");
            enc.chunk_ids[slot.chunk_index] = id;
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
/// Returns the canonical state hash the canister recomputed while finalizing —
/// the `is_final` call carries it back, so reporting it costs no extra round
/// trip. `None` if the canister returned no hash (or a malformed one), which is
/// cosmetic: the sync itself has already succeeded by then.
///
/// Trade-off: splitting forfeits cross-call atomicity. A failure mid-deploy
/// leaves the canister with the operations from previously successful calls
/// applied; the next sync run diffs against the canister and resumes from
/// there.
fn execute_in_stages<C: CanisterCall>(
    canister: &C,
    session_id: u64,
    operations: Vec<Operation>,
) -> Result<Option<[u8; 32]>, String> {
    /// A reported hash is cosmetic, so a wrong-sized blob degrades to `None`
    /// rather than failing a sync that has already been applied.
    fn as_hash(reported: Option<ByteBuf>) -> Option<[u8; 32]> {
        reported.and_then(|h| h.as_ref().try_into().ok())
    }

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
        )
        .map(as_hash);
    }
    let total = groups.len();
    let mut state_hash = None;
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
        // Only the `is_final` call reports a hash; earlier groups return `None`.
        state_hash = as_hash(execute_operations(
            canister,
            ExecuteOperationsArguments {
                session_id,
                operations: ops,
                is_final,
            },
        )?);
    }
    Ok(state_hash)
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
) -> Vec<Operation> {
    let mut ops = Vec::new();
    let mut canister_assets = canister_assets.clone();

    // 1. Delete obsolete assets, or assets whose content_type no longer matches.
    let mut to_remove = Vec::new();
    for (key, ca) in &canister_assets {
        let project = project_assets.get(key);
        let should_delete = match project {
            None => true,
            Some(pa) => pa.content_type != ca.content_type,
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

    // 2. Create new assets (those not present after deletions). Per-asset headers
    //    were already resolved from `_headers` by `asset-prep::prepare_project`.
    for (key, pa) in project_assets {
        if !canister_assets.contains_key(key) {
            ops.push(Operation::CreateAsset(CreateAssetArguments {
                key: key.clone(),
                content_type: pa.content_type.clone(),
                headers: pa.headers.clone(),
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

    // 4. Set content for every encoding that wasn't already in place. The
    //    per-chunk `sha256`s come from `asset-prep`, which sliced and hashed the
    //    encoded bytes (the canister trusts them for 206 certification).
    for (key, pa) in project_assets {
        for (&encoding, enc) in &pa.encodings {
            if enc.already_in_place {
                continue;
            }
            ops.push(Operation::SetAssetContent(SetAssetContentArguments {
                key: key.clone(),
                encoding,
                chunk_ids: enc.chunk_ids.clone(),
                sha256: ByteBuf::from(enc.sha256.to_vec()),
                chunk_sha256: enc
                    .chunks
                    .iter()
                    .map(|c| ByteBuf::from(c.sha256.to_vec()))
                    .collect(),
            }));
        }
    }

    // 5. Update headers for assets that already exist on the canister and
    //    whose headers drifted from the project config.
    update_headers(&mut ops, project_assets, &canister_assets);

    // 6. Replace-all the canister's redirect rules when they differ from the
    //    project's. Comparison is order-sensitive — rules are matched in
    //    declaration order at request time, so reordering is a semantic change.
    //    `project_rules` is already in canonical stored form (3xx rules carry
    //    their resolved `_headers`; see `asset-prep::prepare_project`).
    if project_rules != canister_rules {
        ops.push(Operation::SetRedirectRules(SetRedirectRulesArguments {
            rules: project_rules.to_vec(),
        }));
    }

    ops
}

// For each asset that already exists on the canister, reset its `headers` when
// they drifted from the project config. Newly-created assets get the same
// values via `CreateAssetArguments`, so we don't emit `SetAssetHeaders` for
// them.
//
// Headers are taken from the prepared asset (resolved from `_headers` by
// `asset-prep::prepare_project`).
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
) {
    for (key, pa) in project_assets {
        // Only surviving assets reach here: `canister_assets` has already had
        // deletions (obsolete keys, content_type drift) removed.
        let Some(canister_asset) = canister_assets.get(key) else {
            continue;
        };

        if canister_asset.headers != pa.headers {
            ops.push(Operation::SetAssetHeaders(SetAssetHeadersArguments {
                key: key.clone(),
                headers: pa.headers.clone(),
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Call, CanisterCall};
    use asset_prep::not_found;
    use candid::{CandidType, Decode, Principal};
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use wire_types::{AssetDetails, AssetEncodingDetails, Operation};

    /// The canister-side state a finished sync leaves for the injected branded
    /// `/404.html`, derived by preparing `dir` (which ships no `/404.html`, so the
    /// branded default is injected) and projecting its prepared `/404.html` into
    /// the `AssetDetails` the `list` query would report — content_type, sorted
    /// per-encoding shas, and the headers `prepare_project` resolved from the
    /// project's `_headers`. Lets the short-circuit tests assert "a second sync of
    /// a 404-augmented project is a no-op" without hard-coding the page.
    fn branded_404_canister_asset(dir: &str) -> AssetDetails {
        let prepared = asset_prep::prepare_project(dir).expect("prepare project");
        let asset = prepared
            .assets
            .into_iter()
            .find(|a| a.key == not_found::ROOT_404_KEY)
            .expect("branded /404.html injected");
        let mut encodings: Vec<AssetEncodingDetails> = asset
            .encodings
            .iter()
            .map(|enc| AssetEncodingDetails {
                encoding: enc.encoding,
                sha256: serde_bytes::ByteBuf::from(enc.sha256.to_vec()),
            })
            .collect();
        encodings.sort_by_key(|a| a.encoding);
        AssetDetails {
            key: not_found::ROOT_404_KEY.to_string(),
            content_type: asset.content_type,
            encodings,
            headers: asset.headers,
        }
    }

    /// Slices `data` into prepared chunks the way `asset-prep` does, for building
    /// test `ProjectAssetEncoding`s (an empty encoding is one zero-byte chunk).
    fn prepared_chunks(data: &[u8]) -> Vec<PreparedChunk> {
        let slices: Vec<&[u8]> = if data.is_empty() {
            vec![&[][..]]
        } else {
            data.chunks(MAX_CHUNK_SIZE).collect()
        };
        slices
            .into_iter()
            .map(|c| PreparedChunk {
                len: c.len() as u32,
                sha256: Sha256::digest(c).into(),
                data: c.to_vec(),
            })
            .collect()
    }

    // Records the batch sizes the packer produced (chunks per `upload_chunks`
    // call). Used to verify that `pack_and_upload_chunks` collapses many small
    // chunks into single calls and assigns ids to the right encoding slots. It
    // numbers chunks 0, 1, 2, … in arrival order and echoes those ids back per
    // call, exactly as the canister does.
    struct ChunkBatchRecorder {
        batches: RefCell<Vec<usize>>, // chunks-per-batch
        next_id: RefCell<u64>,        // running chunk-id counter
    }

    impl ChunkBatchRecorder {
        fn new() -> Self {
            Self {
                batches: RefCell::new(Vec::new()),
                next_id: RefCell::new(0),
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
        fn dispatch(&self, call: Call) -> Result<Vec<u8>, String> {
            assert_eq!(call.method, "upload_chunks");
            let req: ChunksReqMirror =
                Decode!(&call.arg, ChunksReqMirror).map_err(|e| e.to_string())?;
            let n = req.chunks.len();
            self.batches.borrow_mut().push(n);
            let start = *self.next_id.borrow();
            *self.next_id.borrow_mut() = start + n as u64;
            let ids: Vec<u64> = (start..start + n as u64).collect();
            candid::encode_one(ids).map_err(|e| e.to_string())
        }
    }

    fn mk_pending_asset(key: &str, encoding: &str, data: Vec<u8>) -> (String, ProjectAsset) {
        let mut enc_map = HashMap::new();
        enc_map.insert(
            Encoding::from_token(encoding).expect("supported test encoding"),
            ProjectAssetEncoding {
                sha256: Sha256::digest(&data).into(),
                chunks: prepared_chunks(&data),
                already_in_place: false,
                chunk_ids: Vec::new(),
            },
        );
        (
            key.to_string(),
            ProjectAsset {
                key: key.to_string(),
                content_type: "application/octet-stream".to_string(),
                headers: vec![],
                encodings: enc_map,
                // Same rule `asset-prep` applies: identity is the longest kept
                // encoding, so its length alone decides this.
                multichunk: data.len() > MAX_CHUNK_SIZE,
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
        let actual: Vec<Vec<u8>> = enc.chunks.iter().map(|c| c.sha256.to_vec()).collect();
        let expected: Vec<Vec<u8>> = data
            .chunks(MAX_CHUNK_SIZE)
            .map(|c| Sha256::digest(c).to_vec())
            .collect();
        assert_eq!(actual, expected);
        // One chunk (hence one hash) per chunk id, in the same order.
        assert_eq!(enc.chunks.len(), enc.chunk_ids.len());
    }

    #[test]
    fn pack_empty_encoding_hashes_its_single_empty_chunk() {
        let mut assets = HashMap::from([mk_pending_asset("/empty", "identity", vec![])]);
        let mock = ChunkBatchRecorder::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();
        let enc = &assets["/empty"].encodings[&Encoding::Identity];
        let chunk_shas: Vec<Vec<u8>> = enc.chunks.iter().map(|c| c.sha256.to_vec()).collect();
        assert_eq!(chunk_shas, vec![Sha256::digest(b"").to_vec()]);
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

    // Overrides `dispatch_batch` to run the batched upload calls in REVERSED
    // order — standing in for a transport that executed them out of order —
    // while still returning results positionally (result[i] ↔ calls[i]). Ids are
    // handed out the way a real canister would for that actual execution order:
    // the call that runs first gets the lowest ids. Records the id assigned to
    // each chunk (keyed by its content hash) so the test can confirm the scatter
    // recovered each chunk's true id no matter what order the calls ran in.
    struct ReorderingUploadMock {
        assigned: RefCell<HashMap<[u8; 32], u64>>,
    }

    impl ReorderingUploadMock {
        fn new() -> Self {
            Self {
                assigned: RefCell::new(HashMap::new()),
            }
        }
    }

    impl CanisterCall for ReorderingUploadMock {
        fn dispatch(&self, _call: Call) -> Result<Vec<u8>, String> {
            unreachable!("the batched upload path goes through dispatch_batch")
        }

        fn dispatch_batch(&self, calls: Vec<Call>) -> Vec<Result<Vec<u8>, String>> {
            // Decode every call's chunks up front, keeping input position.
            let per_call: Vec<Vec<Vec<u8>>> = calls
                .iter()
                .map(|c| {
                    let req: ChunksReqMirror = Decode!(&c.arg, ChunksReqMirror).unwrap();
                    req.chunks.into_iter().map(|b| b.into_vec()).collect()
                })
                .collect();

            // Assign ids in REVERSED execution order — the last input call runs
            // first and takes the lowest ids — but store each call's ids at its
            // input index so the returned Vec stays positional.
            let mut ids_by_input: Vec<Vec<u64>> = vec![Vec::new(); per_call.len()];
            let mut next: u64 = 0;
            for i in (0..per_call.len()).rev() {
                let mut ids = Vec::with_capacity(per_call[i].len());
                for chunk in &per_call[i] {
                    let hash: [u8; 32] = Sha256::digest(chunk).into();
                    self.assigned.borrow_mut().insert(hash, next);
                    ids.push(next);
                    next += 1;
                }
                ids_by_input[i] = ids;
            }

            ids_by_input
                .into_iter()
                .map(|ids| candid::encode_one(ids).map_err(|e| e.to_string()))
                .collect()
        }
    }

    #[test]
    fn pack_maps_returned_ids_positionally_regardless_of_call_order() {
        // Several single-chunk assets each larger than half of MAX_CHUNK_SIZE, so
        // no two share a call → the packer emits one call per asset and the mock
        // can run them out of order. Distinct fill bytes give each a distinct
        // content hash.
        let size = MAX_CHUNK_SIZE / 2 + 1;
        let contents: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; size]).collect();
        let mut assets: HashMap<String, ProjectAsset> = contents
            .iter()
            .enumerate()
            .map(|(i, data)| mk_pending_asset(&format!("/a{i}"), "identity", data.clone()))
            .collect();

        let mock = ReorderingUploadMock::new();
        pack_and_upload_chunks(&mock, 1, &mut assets).unwrap();

        // Each asset's chunk must carry the exact id the mock assigned to that
        // chunk's bytes — proving the mapping is positional per call, not a
        // global arrival counter reproduced on the client.
        let assigned = mock.assigned.borrow();
        for (i, data) in contents.iter().enumerate() {
            let ids = &assets[&format!("/a{i}")].encodings[&Encoding::Identity].chunk_ids;
            let hash: [u8; 32] = Sha256::digest(data).into();
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0], assigned[&hash], "asset /a{i} got the wrong id");
        }

        // The assigned ids are a full permutation of 0..4 — and because the mock
        // ran the calls in reverse, they are genuinely scrambled relative to the
        // packer's call order, so a client-side counter would have mismatched.
        let mut all: Vec<u64> = contents
            .iter()
            .map(|d| assigned[&<[u8; 32]>::from(Sha256::digest(d))])
            .collect();
        all.sort_unstable();
        assert_eq!(all, vec![0, 1, 2, 3]);
    }

    #[test]
    fn pack_skips_already_in_place_encodings() {
        // Nothing to upload → no calls made.
        let (k, mut pa) = mk_pending_asset("/skip", "identity", vec![0u8; 100]);
        pa.encodings
            .get_mut(&Encoding::Identity)
            .unwrap()
            .already_in_place = true;
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
        fn dispatch(&self, call: Call) -> Result<Vec<u8>, String> {
            assert_eq!(call.method, "execute_operations");
            let req: CommitArgsMirror =
                Decode!(&call.arg, CommitArgsMirror).map_err(|e| e.to_string())?;
            self.calls
                .borrow_mut()
                .push((req.session_id, req.operations.len(), req.is_final));
            candid::encode_one(()).map_err(|e| e.to_string())
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
        content_type: &str,
        encodings: &[(&str, Vec<u8>, bool)],
    ) -> (String, ProjectAsset) {
        let mut enc_map = HashMap::new();
        for (name, sha, already_in_place) in encodings {
            // The diff tests only inspect operation shapes, not chunk bytes, so a
            // single dummy chunk carrying the test sha is enough. `chunk_ids` are
            // assigned by the packer; pre-fill one for already-in-place parity.
            let mut sha256 = [0u8; 32];
            let n = sha.len().min(32);
            sha256[..n].copy_from_slice(&sha[..n]);
            let chunk_ids = if *already_in_place {
                vec![]
            } else {
                vec![1u64]
            };
            enc_map.insert(
                Encoding::from_token(name).expect("supported test encoding"),
                ProjectAssetEncoding {
                    sha256,
                    chunks: vec![PreparedChunk {
                        len: 0,
                        sha256,
                        data: Vec::new(),
                    }],
                    already_in_place: *already_in_place,
                    chunk_ids,
                },
            );
        }
        (
            key.to_string(),
            ProjectAsset {
                key: key.to_string(),
                content_type: content_type.to_string(),
                headers: vec![],
                encodings: enc_map,
                multichunk: false,
            },
        )
    }

    /// Sets the resolved per-asset headers on a `mk_project_asset` result — the
    /// form `asset-prep::prepare_project` would produce from a matching `_headers`
    /// rule. Used by the header-diff tests.
    fn with_headers(
        asset: (String, ProjectAsset),
        headers: &[(&str, &str)],
    ) -> (String, ProjectAsset) {
        let (key, mut pa) = asset;
        pa.headers = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        (key, pa)
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
                        | (Operation::SetAssetHeaders(_), "SetAssetHeaders")
                        | (Operation::SetRedirectRules(_), "SetRedirectRules")
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[]);
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
        assert!(build_operations(&project, &canister, &[], &[]).is_empty());
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&HashMap::new(), &canister, &[], &[]);
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&HashMap::new(), &canister, &[], &[]);
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
        let ops = build_operations(&project, &canister, &project_rules, &[]);
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
        let ops = build_operations(&HashMap::new(), &HashMap::new(), &[], &canister_rules);
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
        let ops = build_operations(&HashMap::new(), &HashMap::new(), &rules, &rules);
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
            asset_prep::html_handling::synthesize(&[not_found::ROOT_404_KEY.into()]);
        canister_rules.push(mk_rule(RulePattern::Exact("/old".into()), "/new", 301));
        canister_rules.push(not_found::catchall_rule());

        let mock = SyncMock::new();
        mock.push_ok("version", wire_types::VERSION);
        mock.push_ok("can_sync", true);
        mock.push_ok(
            "get_asset_details",
            vec![branded_404_canister_asset(dir.path().to_str().unwrap())],
        );
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
        // Injected /404.html bytes are uploaded before operations execute;
        // SyncMock synthesizes the returned ids from the request.
        mock.push_ok("execute_operations", ());

        let result = sync(
            &mock,
            &[dir.path().to_str().unwrap().to_string()],
            &Principal::anonymous().to_text(),
            None,
        );
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    // (Asset preparation behaviour — gzip/brotli selection, the keep-if-smaller
    // guard, and `_headers` content-type overrides — is tested in `asset-prep`,
    // which now owns `prepare_project`.)

    // When gzip output is not smaller than identity, prepare skips it, so
    // build_operations sees only the identity encoding and emits no gzip op.
    #[test]
    fn gzip_absent_from_project_emits_no_gzip_op() {
        let project = HashMap::from([mk_project_asset(
            "/tiny.txt",
            "text/plain",
            &[("identity", vec![1, 2, 3], false)],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &[], &[]);
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[]);
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&project, &canister, &[], &[]);
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
        let ops = build_operations(&project, &HashMap::new(), &[], &[]);
        assert!(set_header_ops(&ops).is_empty());
    }

    // ── header / redirect-rule diff (headers pre-resolved by asset-prep) ─────
    //
    // Header *resolution* from `_headers` lives in `asset-prep::prepare_project`
    // (tested there). These tests cover how `build_operations` diffs the
    // already-resolved per-asset headers and pre-resolved redirect rules.

    #[test]
    fn create_asset_carries_prepared_headers() {
        let project = HashMap::from([with_headers(
            mk_project_asset(
                "/index.html",
                "text/html",
                &[("identity", vec![1, 2, 3], false)],
            ),
            &[("X-Frame-Options", "DENY")],
        )]);
        let ops = build_operations(&project, &HashMap::new(), &[], &[]);
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
    fn update_headers_sets_headers_when_canister_missing_them() {
        let project = HashMap::from([with_headers(
            mk_project_asset(
                "/index.html",
                "text/html",
                &[("identity", vec![1, 2, 3], true)],
            ),
            &[("X-Frame-Options", "DENY")],
        )]);
        let canister = HashMap::from([mk_canister_asset(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
        )]);
        let ops = build_operations(&project, &canister, &[], &[]);
        let by_key = set_header_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert_eq!(
            by_key["/index.html"].headers,
            vec![("X-Frame-Options".to_string(), "DENY".to_string())]
        );
    }

    #[test]
    fn update_headers_clears_headers_when_project_has_none() {
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
        // Project asset has no headers — canister-stored headers must be cleared.
        let ops = build_operations(&project, &canister, &[], &[]);
        let by_key = set_header_ops(&ops);
        assert_eq!(by_key.len(), 1);
        assert!(by_key["/index.html"].headers.is_empty());
    }

    #[test]
    fn update_headers_no_op_when_canister_headers_match() {
        let project = HashMap::from([with_headers(
            mk_project_asset(
                "/index.html",
                "text/html",
                &[("identity", vec![1, 2, 3], true)],
            ),
            &[("X-Frame-Options", "DENY")],
        )]);
        let canister = HashMap::from([mk_canister_asset_with_headers(
            "/index.html",
            "text/html",
            &[("identity", vec![1, 2, 3])],
            &[("X-Frame-Options", "DENY")],
        )]);
        let ops = build_operations(&project, &canister, &[], &[]);
        assert!(
            set_header_ops(&ops).is_empty(),
            "no SetAssetHeaders op when prepared headers byte-match canister-stored"
        );
    }

    #[test]
    fn redirect_rules_pass_through_verbatim() {
        // build_operations emits the prepared rules as-is (incl. any resolved 3xx
        // headers) — it does not re-resolve. A rule already carrying headers that
        // matches the canister emits no op; a differing one emits a replace-all.
        let rule = RedirectRule {
            from: RulePattern::Exact("/old".into()),
            to: "/new".to_string(),
            status: 301,
            headers: vec![("X-Robots-Tag".into(), "noindex".into())],
        };
        // Matches canister → no op.
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            std::slice::from_ref(&rule),
            std::slice::from_ref(&rule),
        );
        assert!(set_rules_op(&ops).is_none());

        // Differs from canister → replace-all emits the rule verbatim.
        let ops = build_operations(
            &HashMap::new(),
            &HashMap::new(),
            std::slice::from_ref(&rule),
            &[],
        );
        let emitted = set_rules_op(&ops).expect("SetRedirectRules op missing");
        assert_eq!(emitted, std::slice::from_ref(&rule));
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
        fn dispatch(&self, call: Call) -> Result<Vec<u8>, String> {
            match call.method.as_str() {
                "can_sync" => candid::encode_one(self.can_sync).map_err(|e| e.to_string()),
                "authorize" => {
                    self.authorize_calls.borrow_mut().push(call.direct);
                    candid::encode_one(()).map_err(|e| e.to_string())
                }
                other => panic!("unexpected method: {other}"),
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
        fn dispatch(&self, call: Call) -> Result<Vec<u8>, String> {
            // The upload wire contract — return one id per staged chunk, in
            // order — is fixed, so synthesize it from the request rather than
            // scripting it. These sync-flow tests care about call *sequencing*,
            // not id values (execute_operations is mocked), and the request's
            // chunk count is what the batch length check needs to line up.
            if call.method == "upload_chunks" {
                let req: ChunksReqMirror =
                    Decode!(&call.arg, ChunksReqMirror).map_err(|e| e.to_string())?;
                let ids: Vec<u64> = (0..req.chunks.len() as u64).collect();
                return candid::encode_one(ids).map_err(|e| e.to_string());
            }
            self.queue
                .borrow_mut()
                .entry(call.method.clone())
                .or_default()
                .pop_front()
                .unwrap_or_else(|| panic!("no programmed response for '{}'", call.method))
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
        std::fs::write(
            dir.path().join("_headers"),
            b"/*\n  X-Frame-Options: DENY\n",
        )
        .unwrap();
        let dir_str = dir.path().to_str().unwrap();

        use sha2::Digest;
        let identity_sha = sha2::Sha256::digest(b"hello").to_vec();

        // No root 404.html and no `/*` rule, so the sync path injects a branded
        // /404.html (which the `/*` _headers rule also covers) plus its
        // html-handling rules and the `/*` catch-all; the canister must already
        // hold all of it for the short-circuit to fire. The exact stored rules
        // are whatever `prepare_project` produces (3xx headers already resolved).
        let canister_rules = asset_prep::prepare_project(dir_str).unwrap().redirect_rules;

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
                branded_404_canister_asset(dir_str),
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
        // SyncMock synthesizes upload_chunks' returned ids from the request.
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
        let user_rules = asset_prep::redirects::parse("/index /elsewhere 301\n").unwrap();
        let synthesised = asset_prep::html_handling::synthesize(&["/index.html".to_string()]);

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
        let user_rules = asset_prep::redirects::parse("/* /404.html 404\n").unwrap();
        let synthesised = asset_prep::html_handling::synthesize(&["/index.html".to_string()]);

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
        let mut canister_rules = asset_prep::html_handling::synthesize(&[
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
                branded_404_canister_asset(dir.path().to_str().unwrap()),
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

    // ───────── Lazy encoding ─────────
    //
    // `diff_assets` must encode an asset only when the canister doesn't already
    // hold exactly what preparation would produce. "Was it encoded?" is directly
    // observable: a reused asset carries no chunks at all (an encoded one always
    // has at least one per encoding, even for empty content).

    /// A body repetitive enough that both gzip and brotli beat identity, so the
    /// asset keeps the full `{identity, gzip, brotli}` set — the case where
    /// skipping the encode pass actually saves work.
    fn compressible_html() -> Vec<u8> {
        format!("<!DOCTYPE html><h1>{}</h1>", "hello world ".repeat(200)).into_bytes()
    }

    /// The `AssetDetails` map the canister would report after a full sync of
    /// `dir` — i.e. what the diff sees on a re-deploy of an unchanged project.
    fn canister_view(dir: &str) -> HashMap<String, AssetDetails> {
        asset_prep::prepare_project(dir)
            .expect("prepare project")
            .assets
            .into_iter()
            .map(|a| {
                let details = AssetDetails {
                    encodings: a
                        .encodings
                        .iter()
                        .map(|e| AssetEncodingDetails {
                            encoding: e.encoding,
                            sha256: ByteBuf::from(e.sha256.to_vec()),
                        })
                        .collect(),
                    content_type: a.content_type,
                    headers: a.headers,
                    key: a.key.clone(),
                };
                (a.key, details)
            })
            .collect()
    }

    fn was_encoded(assets: &HashMap<String, ProjectAsset>, key: &str) -> bool {
        assets[key].encodings.values().any(|e| !e.chunks.is_empty())
    }

    #[test]
    fn unchanged_asset_is_not_encoded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), compressible_html()).unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let canister = canister_view(dir_str);
        // Full set kept, so this exercises the reuse path rather than the
        // "compression didn't help" one.
        assert_eq!(canister["/index.html"].encodings.len(), 3);

        let plan = plan_project(dir_str).unwrap();
        let project = diff_assets(plan.assets, &canister).unwrap();

        for key in project.keys() {
            assert!(!was_encoded(&project, key), "{key} should not be encoded");
        }
        assert!(
            build_operations(
                &project,
                &canister,
                &plan.redirect_rules,
                &plan.redirect_rules
            )
            .is_empty(),
            "an unchanged project must produce no operations"
        );
    }

    #[test]
    fn header_only_change_reuses_content_and_sets_headers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), compressible_html()).unwrap();
        let dir_str = dir.path().to_str().unwrap();

        // Canister state from before the `_headers` file existed.
        let canister = canister_view(dir_str);
        std::fs::write(
            dir.path().join("_headers"),
            b"/*\n  X-Frame-Options: DENY\n",
        )
        .unwrap();

        let plan = plan_project(dir_str).unwrap();
        let project = diff_assets(plan.assets, &canister).unwrap();

        assert!(
            !was_encoded(&project, "/index.html"),
            "content is unchanged, so it must not be re-encoded"
        );
        let ops = build_operations(
            &project,
            &canister,
            &plan.redirect_rules,
            &plan.redirect_rules,
        );
        assert_eq!(count_op(&ops, "SetAssetHeaders"), project.len());
        assert_eq!(count_op(&ops, "SetAssetContent"), 0);
    }

    #[test]
    fn changed_asset_is_re_encoded_and_uploaded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), compressible_html()).unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let canister = canister_view(dir_str);
        std::fs::write(dir.path().join("index.html"), b"<h1>new</h1>").unwrap();

        let plan = plan_project(dir_str).unwrap();
        let project = diff_assets(plan.assets, &canister).unwrap();

        assert!(was_encoded(&project, "/index.html"));
        assert!(
            !was_encoded(&project, not_found::ROOT_404_KEY),
            "the untouched branded 404 must still be reused"
        );
        let ops = build_operations(
            &project,
            &canister,
            &plan.redirect_rules,
            &plan.redirect_rules,
        );
        assert!(count_op(&ops, "SetAssetContent") > 0);
    }

    #[test]
    fn missing_encoding_forces_re_encode_and_uploads_only_the_gap() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), compressible_html()).unwrap();
        let dir_str = dir.path().to_str().unwrap();

        // Simulate a deploy that died before brotli landed: identity and gzip
        // match, brotli is absent. Indistinguishable from "brotli didn't shrink
        // this asset" without encoding, so the asset must be re-encoded.
        let mut canister = canister_view(dir_str);
        canister
            .get_mut("/index.html")
            .unwrap()
            .encodings
            .retain(|e| e.encoding != Encoding::Brotli);

        let plan = plan_project(dir_str).unwrap();
        let project = diff_assets(plan.assets, &canister).unwrap();

        assert!(was_encoded(&project, "/index.html"));
        // ...but only the missing encoding is actually uploaded: the per-encoding
        // hash check still marks identity and gzip as already in place.
        let ops = build_operations(
            &project,
            &canister,
            &plan.redirect_rules,
            &plan.redirect_rules,
        );
        assert_eq!(count_op(&ops, "SetAssetContent"), 1);
    }

    #[test]
    fn content_type_drift_forces_re_encode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), compressible_html()).unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let mut canister = canister_view(dir_str);
        canister.get_mut("/index.html").unwrap().content_type = "text/plain".to_string();

        let plan = plan_project(dir_str).unwrap();
        let project = diff_assets(plan.assets, &canister).unwrap();

        assert!(was_encoded(&project, "/index.html"));
    }
}
