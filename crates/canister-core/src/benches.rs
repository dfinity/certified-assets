//! Instruction-count microbenchmarks, run with [`canbench`](https://github.com/dfinity/bench).
//!
//! These measure Wasm **instructions** (and heap / stable-memory growth) for the
//! two paths the stable-memory migration touched — serving assets and committing
//! a sync — plus the post-upgrade rebuild. Instructions are deterministic and
//! network-independent, so this answers "did stable structures make these paths
//! meaningfully more expensive?" without a replica or mainnet. See
//! [`BENCHMARKING.md`](../../../BENCHMARKING.md) for the full plan.
//!
//! Run from this crate's directory: `canbench` (add `--persist` to update
//! `canbench_results.yml`). The build is driven by `canbench.yml`.
//!
//! ## How these run
//!
//! `canbench` executes each `#[bench]` as a **query call** against a single
//! canister instance. Query state changes are rolled back afterwards, so every
//! benchmark starts from the same empty committed state — each one builds its own
//! `State` in setup with no cross-benchmark contamination. On wasm,
//! `DefaultMemoryImpl` is real stable memory, so the stable-structure costs are
//! measured under the IC's actual instruction model.
//!
//! `#[bench(raw)]` + [`bench_fn`] measures only the closure; the setup before it
//! (building state, syncing assets) is excluded.

use crate::http::HttpRequest;
use crate::runtime::SystemContext;
use crate::state::State;
use crate::sync::{ComputationStatus, ExecuteOperationsProgress};
use canbench_rs::{bench, bench_fn, BenchResult};
use candid::Principal;
use ic_stable_structures::DefaultMemoryImpl;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use wire_types::{
    CreateAssetArguments, Encoding, ExecuteOperationsArguments, Operation,
    SetAssetContentArguments, StartSyncResult, UploadChunksArguments,
};

// ---- benchmark sizing knobs ----
//
// Named so the cost curves are easy to probe: bump `LARGE_NUM_CHUNKS` to stress
// the per-callback `metadata.get` (Risk A in BENCHMARKING.md), or
// `REBUILD_NUM_ASSETS` to trace the post-upgrade rebuild scaling (Risk B).

/// A small single-chunk asset (typical HTML page).
const SMALL_ASSET_BYTES: usize = 10 * 1024;

/// A large multi-chunk asset. 8 × 1 MiB ⇒ eight certified 206 responses, one per
/// chunk, each re-resolving the asset from its URL (metadata read + chunk-cert
/// scan + chunk read + witness) — this is where the per-chunk serve cost shows up.
const LARGE_CHUNK_BYTES: usize = 1024 * 1024;
const LARGE_NUM_CHUNKS: usize = 8;

/// A sync committing many small assets (one chunk each).
const COMMIT_NUM_ASSETS: usize = 50;
const COMMIT_ASSET_BYTES: usize = 4 * 1024;

/// Assets to populate before measuring the post-upgrade rebuild.
const REBUILD_NUM_ASSETS: usize = 100;
const REBUILD_ASSET_BYTES: usize = 4 * 1024;

// A fixed timestamp keeps the sync state machine deterministic without reading
// the system clock.
const FIXED_TS_NS: u64 = 1_700_000_000_000_000_000;

fn ctx() -> SystemContext {
    SystemContext::new_with_options(FIXED_TS_NS)
}

fn caller() -> Principal {
    Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap()
}

fn identity() -> Encoding {
    Encoding::from_token("identity").expect("identity is a supported encoding")
}

fn sha256_of(chunks: &[ByteBuf]) -> ByteBuf {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    ByteBuf::from(hasher.finalize().to_vec())
}

/// A `GET` request that accepts the identity encoding (what the benches store).
fn get(url: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        url: url.to_string(),
        headers: vec![("Accept-Encoding".to_string(), "identity".to_string())],
        body: ByteBuf::new(),
        certificate_version: Some(2),
    }
}

/// Like [`get`], but with an open-ended `Range` header — what the gateway sends
/// when fetching a subsequent chunk of a large asset during 206 reassembly.
fn get_range(url: &str, start: usize) -> HttpRequest {
    let mut req = get(url);
    req.headers
        .push(("Range".to_string(), format!("bytes={start}-")));
    req
}

/// Drives `execute_operations` to completion synchronously. Mirrors the
/// canister's real loop but without the async self-call / instruction-limit
/// handling — a single bench message isn't subject to it.
fn run_to_completion(state: &mut State, args: &ExecuteOperationsArguments, ctx: &SystemContext) {
    let mut progress = ExecuteOperationsProgress::default();
    loop {
        match state.execute_operations(args, progress, ctx) {
            ComputationStatus::Done(()) => return,
            ComputationStatus::InProgress(p) => progress = p,
            ComputationStatus::Error(e) => panic!("execute_operations failed: {e}"),
        }
    }
}

/// Opens a sync and stages one chunk per asset, returning the session id and the
/// assembled `CreateAsset` + `SetAssetContent` operations — *without* committing.
/// Callers that want to measure the commit run `run_to_completion` separately.
fn stage_assets(
    state: &mut State,
    ctx: &SystemContext,
    num_assets: usize,
    chunk_bytes: usize,
) -> (u64, Vec<Operation>) {
    let session_id = match state.start_sync(caller(), ctx) {
        StartSyncResult::Started { session_id } => session_id,
        other => panic!("expected Started, got {other:?}"),
    };

    let mut ops = Vec::with_capacity(num_assets * 2);
    for i in 0..num_assets {
        let key = format!("/asset-{i}.bin");
        let chunk = ByteBuf::from(vec![i as u8; chunk_bytes]);
        let sha256 = sha256_of(std::slice::from_ref(&chunk));
        // Chunk ids are the staging slot indices the canister assigns in upload
        // order; one chunk per asset means the next id is the current length.
        let chunk_id = state.chunks.len() as u64;
        state
            .upload_chunks(
                UploadChunksArguments {
                    session_id,
                    chunks: vec![chunk],
                },
                ctx,
            )
            .unwrap();
        ops.push(Operation::CreateAsset(CreateAssetArguments {
            key: key.clone(),
            content_type: "application/octet-stream".to_string(),
            headers: vec![],
        }));
        ops.push(Operation::SetAssetContent(SetAssetContentArguments {
            key,
            encoding: identity(),
            chunk_ids: vec![chunk_id],
            sha256,
        }));
    }
    (session_id, ops)
}

/// Fully syncs `num_assets` single-chunk assets (keys `/asset-{i}.bin`) into a
/// fresh `State` and returns it.
fn populate_assets(num_assets: usize, chunk_bytes: usize) -> State {
    let mut state = State::default();
    let c = ctx();
    let (session_id, ops) = stage_assets(&mut state, &c, num_assets, chunk_bytes);
    run_to_completion(
        &mut state,
        &ExecuteOperationsArguments {
            session_id,
            operations: ops,
            is_final: true,
        },
        &c,
    );
    state
}

/// Syncs a single asset at `key` with `num_chunks` chunks of `chunk_bytes` each.
fn populate_one(key: &str, content_type: &str, num_chunks: usize, chunk_bytes: usize) -> State {
    let mut state = State::default();
    let c = ctx();
    let session_id = match state.start_sync(caller(), &c) {
        StartSyncResult::Started { session_id } => session_id,
        other => panic!("expected Started, got {other:?}"),
    };
    let chunks: Vec<ByteBuf> = (0..num_chunks)
        .map(|i| ByteBuf::from(vec![i as u8; chunk_bytes]))
        .collect();
    let sha256 = sha256_of(&chunks);
    let chunk_ids: Vec<u64> = (0..num_chunks as u64).collect();
    state
        .upload_chunks(UploadChunksArguments { session_id, chunks }, &c)
        .unwrap();
    let ops = vec![
        Operation::CreateAsset(CreateAssetArguments {
            key: key.to_string(),
            content_type: content_type.to_string(),
            headers: vec![],
        }),
        Operation::SetAssetContent(SetAssetContentArguments {
            key: key.to_string(),
            encoding: identity(),
            chunk_ids,
            sha256,
        }),
    ];
    run_to_completion(
        &mut state,
        &ExecuteOperationsArguments {
            session_id,
            operations: ops,
            is_final: true,
        },
        &c,
    );
    state
}

/// Serving a small single-chunk asset: one metadata read + one chunk read, plus
/// the (heap) witness. The stable-memory delta on the serve path is tiny;
/// this sets the floor.
#[bench(raw)]
fn serve_small_asset() -> BenchResult {
    let state = populate_one("/index.html", "text/html", 1, SMALL_ASSET_BYTES);
    // Sanity (not measured): a broken setup would otherwise measure the 404 path.
    assert_eq!(state.http_request(get("/index.html"), &[]).status_code, 200);

    let req = get("/index.html");
    bench_fn(|| {
        std::hint::black_box(state.http_request(req, &[]));
    })
}

/// Serving a large multi-chunk asset end to end the way the gateway does it: a
/// plain GET returns chunk 0 as a 206, then one `Range` request per remaining
/// chunk. Each call re-resolves the asset from its URL (metadata read +
/// chunk-cert scan + chunk read + witness), so this is the bench that surfaces
/// the per-chunk serve cost; it scales with `LARGE_NUM_CHUNKS`.
#[bench(raw)]
fn serve_large_asset() -> BenchResult {
    let state = populate_one(
        "/big.bin",
        "application/octet-stream",
        LARGE_NUM_CHUNKS,
        LARGE_CHUNK_BYTES,
    );
    // Sanity (not measured): a plain GET of a multi-chunk asset is a 206 chunk 0.
    assert_eq!(state.http_request(get("/big.bin"), &[]).status_code, 206);

    bench_fn(|| {
        // Chunks are uniform `LARGE_CHUNK_BYTES`, so chunk `i` begins at
        // `i * LARGE_CHUNK_BYTES`. The gateway sends the first chunk's request
        // without a Range header and each subsequent one with `bytes={start}-`.
        for i in 0..LARGE_NUM_CHUNKS {
            let req = if i == 0 {
                get("/big.bin")
            } else {
                get_range("/big.bin", i * LARGE_CHUNK_BYTES)
            };
            std::hint::black_box(state.http_request(req, &[]));
        }
    })
}

/// Committing a sync of many small assets: the `execute_operations` commit, where
/// chunk hashing, the stable-memory writes (metadata + content), and heap
/// recertification happen. Setup stages the chunks and assembles the ops (not
/// measured). Divide the result by `COMMIT_NUM_ASSETS` for a per-asset figure.
#[bench(raw)]
fn sync_commit() -> BenchResult {
    let mut state = State::default();
    let c = ctx();
    let (session_id, ops) = stage_assets(&mut state, &c, COMMIT_NUM_ASSETS, COMMIT_ASSET_BYTES);
    let args = ExecuteOperationsArguments {
        session_id,
        operations: ops,
        is_final: true,
    };
    bench_fn(|| run_to_completion(&mut state, &args, &c))
}

/// Committing a sync of one large multi-chunk asset (8 × 1 MiB). Unlike
/// `sync_commit` (4 KiB assets, where chunk-write cost is in the noise), this
/// surfaces the content-write coefficient — the stable write of ~8 MiB of chunk
/// bytes — alongside the unchanged SHA-256 hashing and recertification.
#[bench(raw)]
fn sync_commit_large() -> BenchResult {
    let mut state = State::default();
    let c = ctx();
    let session_id = match state.start_sync(caller(), &c) {
        StartSyncResult::Started { session_id } => session_id,
        other => panic!("expected Started, got {other:?}"),
    };
    let chunks: Vec<ByteBuf> = (0..LARGE_NUM_CHUNKS)
        .map(|i| ByteBuf::from(vec![i as u8; LARGE_CHUNK_BYTES]))
        .collect();
    let sha256 = sha256_of(&chunks);
    let chunk_ids: Vec<u64> = (0..LARGE_NUM_CHUNKS as u64).collect();
    state
        .upload_chunks(UploadChunksArguments { session_id, chunks }, &c)
        .unwrap();
    let args = ExecuteOperationsArguments {
        session_id,
        operations: vec![
            Operation::CreateAsset(CreateAssetArguments {
                key: "/big.bin".to_string(),
                content_type: "application/octet-stream".to_string(),
                headers: vec![],
            }),
            Operation::SetAssetContent(SetAssetContentArguments {
                key: "/big.bin".to_string(),
                encoding: identity(),
                chunk_ids,
                sha256,
            }),
        ],
        is_final: true,
    };
    bench_fn(|| run_to_completion(&mut state, &args, &c))
}

/// The post-upgrade rebuild: a fresh `State` over already-populated stable memory
/// plus `post_upgrade_rebuild`, which iterates all metadata to reconstruct the
/// heap certification tree. Cost scales with `REBUILD_NUM_ASSETS` (Risk B).
#[bench(raw)]
fn post_upgrade_rebuild() -> BenchResult {
    // Setup: populate stable memory, then drop the State. The bytes persist for
    // the rest of this query, so a new State reads them back — the same trick the
    // upgrade roundtrip unit test uses.
    let populated = populate_assets(REBUILD_NUM_ASSETS, REBUILD_ASSET_BYTES);
    drop(populated);

    bench_fn(|| {
        let mut state = State::new(DefaultMemoryImpl::default());
        state.post_upgrade_rebuild();
        std::hint::black_box(state.root_hash());
    })
}
