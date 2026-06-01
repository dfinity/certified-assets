//! Layer 1 benchmark — measures the canister-call pattern `sync()` emits.
//!
//! The mock returns instantly, so wall-clock here reflects scan + encode +
//! Candid only. The wins we're targeting (chunk batching, `last_chunk`
//! inlining, eliminating per-asset `get_asset_properties`) all move the
//! *call pattern*, which is what the printed table surfaces.
//!
//! Run on a baseline branch, save the output, then re-run on a changed
//! branch and diff:
//!
//! ```sh
//! cargo test --release --test bench_sync \
//!   -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Tests are `#[ignore]`'d so they don't slow down the regular suite.

use assets_sync::canister::{AssetDetails, AssetProperties, CallType, CanisterCall, RedirectRule};
use assets_sync::sync::sync;
use candid::{CandidType, Decode, Encode, Nat, Principal};
use serde::Deserialize;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::Path;

// Wire-compatible mirrors of the response types defined privately in
// assets_sync::canister. Same field name → same Candid encoding.
#[derive(CandidType)]
struct CreateBatchOk {
    batch_id: Nat,
}
#[derive(CandidType)]
struct CreateChunksOk {
    chunk_ids: Vec<Nat>,
}

// Wire-compatible mirror of CreateChunksRequest so the mock can count chunks
// submitted per call and return one id per chunk — works whether the plugin
// sends a single chunk per call (today) or batches many (after optimisation).
#[derive(CandidType, Deserialize)]
struct CreateChunksReqMirror {
    #[allow(dead_code)]
    batch_id: Nat,
    content: Vec<serde_bytes::ByteBuf>,
}

/// Records every canister call (method, Candid arg bytes) and auto-responds
/// with empty/default values — i.e. a first-time deploy against a fresh
/// canister.
struct BenchMock {
    /// Per-method `(call_count, total_arg_bytes)`. BTreeMap so the printed
    /// report is stable across runs.
    stats: RefCell<BTreeMap<String, (u64, u64)>>,
    next_chunk_id: Cell<u64>,
}

impl BenchMock {
    fn new() -> Self {
        Self {
            stats: RefCell::new(BTreeMap::new()),
            next_chunk_id: Cell::new(0),
        }
    }

    fn report(&self, label: &str) {
        let stats = self.stats.borrow();
        let total_calls: u64 = stats.values().map(|(c, _)| *c).sum();
        let total_bytes: u64 = stats.values().map(|(_, b)| *b).sum();
        println!();
        println!("── {label} ──");
        println!("{:<28} {:>8} {:>14}", "method", "calls", "arg bytes");
        println!("{:-<28} {:->8} {:->14}", "", "", "");
        for (m, (c, b)) in stats.iter() {
            println!("{m:<28} {c:>8} {b:>14}");
        }
        println!("{:-<28} {:->8} {:->14}", "", "", "");
        println!("{:<28} {:>8} {:>14}", "TOTAL", total_calls, total_bytes);
    }
}

impl CanisterCall for BenchMock {
    fn call<A, R>(&self, method: &str, arg: A, _: CallType, _: bool) -> Result<R, String>
    where
        A: CandidType,
        R: CandidType + serde::de::DeserializeOwned,
    {
        let arg_bytes = Encode!(&arg).map_err(|e| e.to_string())?;
        {
            let mut stats = self.stats.borrow_mut();
            let entry = stats.entry(method.to_string()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += arg_bytes.len() as u64;
        }

        let resp = match method {
            "api_version" => Encode!(&2u16),
            "list" => Encode!(&Vec::<AssetDetails>::new()),
            "get_redirect_rules" => Encode!(&Vec::<RedirectRule>::new()),
            "get_asset_properties" => Encode!(&AssetProperties {
                max_age: None,
                headers: None,
                allow_raw_access: Some(true),
            }),
            "create_batch" => Encode!(&CreateBatchOk {
                batch_id: Nat::from(1u32),
            }),
            "create_chunks" => {
                let req = Decode!(&arg_bytes, CreateChunksReqMirror)
                    .map_err(|e| format!("decode create_chunks req: {e}"))?;
                let n = req.content.len() as u64;
                let start = self.next_chunk_id.get();
                self.next_chunk_id.set(start + n);
                let ids: Vec<Nat> = (0..n).map(|i| Nat::from(start + i)).collect();
                Encode!(&CreateChunksOk { chunk_ids: ids })
            }
            "commit_batch" => Encode!(&()),
            "list_permitted" => Encode!(&Vec::<Principal>::new()),
            "grant_permission" => Encode!(&()),
            other => panic!("BenchMock: unexpected method '{other}'"),
        }
        .map_err(|e| e.to_string())?;

        Decode!(&resp, R).map_err(|e| e.to_string())
    }
}

/// Writes `count` files of `size_bytes` each into `dir`. Bytes come from a
/// deterministic LCG so they're incompressible — gzip is skipped per file,
/// keeping encoder choice out of the measurement.
fn write_incompressible_files(dir: &Path, count: usize, size_bytes: usize) {
    let mut state: u64 = 0xdead_beef_cafe_f00d;
    let mut buf = vec![0u8; size_bytes];
    for i in 0..count {
        for b in buf.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
        std::fs::write(dir.join(format!("f_{i:05}.bin")), &buf).unwrap();
    }
}

fn run_bench(label: &str, count: usize, size_bytes: usize) {
    let tmp = tempfile::tempdir().unwrap();
    write_incompressible_files(tmp.path(), count, size_bytes);
    let dirs = vec![tmp.path().to_str().unwrap().to_string()];

    let mock = BenchMock::new();
    let started = std::time::Instant::now();
    let result = sync(&mock, &dirs, &Principal::anonymous().to_text(), None);
    let elapsed = started.elapsed();
    result.expect("sync failed");

    mock.report(&format!(
        "{label}   ({count} × {size_bytes} bytes)   wall: {elapsed:?}"
    ));
}

// ── Fixtures ────────────────────────────────────────────────────────────────
//
// Sized to exercise the three regimes the optimisations target:
//  - many small files  → most calls today are `create_chunks` for sub-MAX
//    chunks; chunk-batching should collapse the count
//  - few medium files  → mix of multi-chunk uploads + single trailing chunk;
//    last_chunk inlining should remove the trailing-chunk call
//  - one huge file     → multi-chunk upload of a single asset; chunk packing
//    doesn't help (chunks already at MAX), but a useful control case

#[test]
#[ignore = "bench: run with --release --ignored -- --nocapture --test-threads=1"]
fn bench_many_tiny_files() {
    run_bench("many_tiny   1000 × 1 KB", 1000, 1024);
}

#[test]
#[ignore = "bench: run with --release --ignored -- --nocapture --test-threads=1"]
fn bench_many_small_files() {
    run_bench("many_small  100 × 5 KB", 100, 5 * 1024);
}

#[test]
#[ignore = "bench: run with --release --ignored -- --nocapture --test-threads=1"]
fn bench_few_medium_files() {
    run_bench("few_medium  10 × 2 MB", 10, 2 * 1024 * 1024);
}

#[test]
#[ignore = "bench: run with --release --ignored -- --nocapture --test-threads=1"]
fn bench_one_huge_file() {
    run_bench("one_huge    1 × 50 MB", 1, 50 * 1024 * 1024);
}
