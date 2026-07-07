//! Layer 1 benchmark — measures the canister-call pattern `sync()` emits.
//!
//! The mock returns instantly, so wall-clock here reflects scan + encode +
//! Candid only.
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

use candid::{CandidType, Decode, Encode, Principal};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use sync_core::{CallType, CanisterCall, sync};
use wire_types::{AssetDetails, RedirectRule};

// Wire-compatible mirrors of the response types defined privately in
// sync_core::canister. Same variant/field names → same Candid encoding.
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

/// Records every canister call (method, Candid arg bytes) and auto-responds
/// with empty/default values — i.e. a first-time deploy against a fresh
/// canister.
struct BenchMock {
    /// Per-method `(call_count, total_arg_bytes)`. BTreeMap so the printed
    /// report is stable across runs.
    stats: RefCell<BTreeMap<String, (u64, u64)>>,
}

impl BenchMock {
    fn new() -> Self {
        Self {
            stats: RefCell::new(BTreeMap::new()),
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
            "version" => Encode!(&wire_types::VERSION),
            "get_asset_details" => Encode!(&Vec::<AssetDetails>::new()),
            "get_redirect_rules" => Encode!(&Vec::<RedirectRule>::new()),
            "start_sync" => Encode!(&StartSyncOk::Started { session_id: 1 }),
            "upload_chunks" => Encode!(&()),
            "execute_operations" => Encode!(&()),
            // The bench drives sync() in direct mode, which checks can_sync up
            // front; report the identity as allowed so it proceeds.
            "can_sync" => Encode!(&true),
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
//  - many small files  → most calls today are `upload_chunks` for sub-MAX
//    chunks; chunk-batching should collapse the count
//  - few medium files  → mix of multi-chunk uploads + a smaller trailing chunk
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
