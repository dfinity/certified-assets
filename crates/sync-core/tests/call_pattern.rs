//! Regression tests for the canister-call pattern `sync()` emits.
//!
//! Each fixture runs `sync()` against a mock that returns instantly and records,
//! per method, the call count and the total Candid arg bytes. Both are a pure
//! function of the input (fixed file count/size, fixed LCG seed) and the sync
//! algorithm — no wall-clock, nothing host-dependent — so each test asserts the
//! full call fingerprint against a committed golden. A diff means the emitted
//! call pattern changed: intended (update the golden), or a regression such as
//! lost chunk-batching inflating `upload_chunks`, or lost operation-grouping
//! inflating `execute_operations`.
//!
//! On failure the harness prints the captured per-method report — the easiest
//! way to read the new numbers. To see that report (and wall-clock) without a
//! failure, run:
//!
//! ```sh
//! cargo test --release --test call_pattern -- --nocapture --test-threads=1
//! ```

use candid::{CandidType, Decode, Encode, Principal};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use sync_core::{Call, CanisterCall, Compressors, sync};
use wire_types::{AssetDetails, RedirectRule, UploadChunksArguments};

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

/// The deterministic canister-call fingerprint of one `sync()` run: per-method
/// call count, plus the total Candid arg bytes across every call. Two equal
/// fingerprints mean the emitted call pattern is byte-for-byte identical.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallFingerprint {
    /// method name → call count (BTreeMap keeps compare + Debug order stable)
    calls: BTreeMap<String, u64>,
    /// total Candid arg bytes summed across every call
    total_arg_bytes: u64,
}

/// Records every canister call (method, Candid arg bytes) and auto-responds
/// with empty/default values — i.e. a first-time deploy against a fresh
/// canister.
struct RecordingMock {
    /// Per-method `(call_count, total_arg_bytes)`. BTreeMap so the printed
    /// report is stable across runs.
    stats: RefCell<BTreeMap<String, (u64, u64)>>,
}

impl RecordingMock {
    fn new() -> Self {
        Self {
            stats: RefCell::new(BTreeMap::new()),
        }
    }

    /// Distils the recorded stats into the asserted fingerprint (keeping the
    /// per-method call counts, folding bytes down to a single total).
    fn fingerprint(&self) -> CallFingerprint {
        let stats = self.stats.borrow();
        CallFingerprint {
            calls: stats.iter().map(|(m, (c, _))| (m.clone(), *c)).collect(),
            total_arg_bytes: stats.values().map(|(_, b)| *b).sum(),
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

impl CanisterCall for RecordingMock {
    fn dispatch(&self, call: Call) -> Result<Vec<u8>, String> {
        {
            let mut stats = self.stats.borrow_mut();
            let entry = stats.entry(call.method.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += call.arg.len() as u64;
        }

        match call.method.as_str() {
            "version" => Encode!(&wire_types::VERSION),
            "get_asset_details" => Encode!(&Vec::<AssetDetails>::new()),
            "get_redirect_rules" => Encode!(&Vec::<RedirectRule>::new()),
            "start_sync" => Encode!(&StartSyncOk::Started { session_id: 1 }),
            "upload_chunks" => {
                // Echo one id per staged chunk, as the canister does.
                let req = Decode!(&call.arg, UploadChunksArguments).map_err(|e| e.to_string())?;
                let ids: Vec<u64> = (0..req.chunks.len() as u64).collect();
                Encode!(&ids)
            }
            "execute_operations" => Encode!(&None::<serde_bytes::ByteBuf>),
            // The test drives sync() in direct mode, which checks can_sync up
            // front; report the identity as allowed so it proceeds.
            "can_sync" => Encode!(&true),
            // An empty canister has no recorded compression fingerprint, so
            // report the "unknown" value — every asset is new here anyway.
            "preparation_canary" => Encode!(&serde_bytes::ByteBuf::from(vec![0u8; 32])),
            other => panic!("RecordingMock: unexpected method '{other}'"),
        }
        .map_err(|e| e.to_string())
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

fn run_scenario(label: &str, count: usize, size_bytes: usize) -> CallFingerprint {
    let tmp = tempfile::tempdir().unwrap();
    write_incompressible_files(tmp.path(), count, size_bytes);
    let dirs = vec![tmp.path().to_str().unwrap().to_string()];

    let mock = RecordingMock::new();
    let started = std::time::Instant::now();
    let result = sync(
        &mock,
        &dirs,
        &Principal::anonymous().to_text(),
        None,
        &Compressors::canonical(),
    );
    let elapsed = started.elapsed();
    result.expect("sync failed");

    // Printed only under `--nocapture`, and shown by the harness when the
    // fingerprint assertion below fails.
    mock.report(&format!(
        "{label}   ({count} × {size_bytes} bytes)   wall: {elapsed:?}"
    ));
    mock.fingerprint()
}

/// Builds an expected fingerprint from `(method, call_count)` pairs plus the
/// total arg-byte count. Every method `sync()` calls must be listed, or the
/// maps won't compare equal.
fn expected(calls: &[(&str, u64)], total_arg_bytes: u64) -> CallFingerprint {
    CallFingerprint {
        calls: calls.iter().map(|(m, c)| ((*m).to_string(), *c)).collect(),
        total_arg_bytes,
    }
}

/// Asserts the run's fingerprint against its golden, with guidance on failure.
fn assert_fingerprint(actual: CallFingerprint, expected: CallFingerprint) {
    assert_eq!(
        actual, expected,
        "\ncanister-call pattern changed — see the per-method report printed \
         above. If intentional, update the golden; otherwise this is a \
         regression (e.g. lost chunk-batching or operation-grouping)."
    );
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
fn many_tiny_files() {
    // 1000 sub-MAX chunks collapse into a single `upload_chunks` call; the 2005
    // resulting operations batch into 5 `execute_operations` calls.
    assert_fingerprint(
        run_scenario("many_tiny   1000 × 1 KB", 1000, 1024),
        expected(
            &[
                ("version", 1),
                ("can_sync", 1),
                ("preparation_canary", 1),
                ("get_asset_details", 1),
                ("get_redirect_rules", 1),
                ("start_sync", 1),
                ("upload_chunks", 1),
                ("execute_operations", 5),
            ],
            1_160_920,
        ),
    );
}

#[test]
fn many_small_files() {
    // 100 sub-MAX chunks still fit one `upload_chunks` call and one operation
    // batch.
    assert_fingerprint(
        run_scenario("many_small  100 × 5 KB", 100, 5 * 1024),
        expected(
            &[
                ("version", 1),
                ("can_sync", 1),
                ("preparation_canary", 1),
                ("get_asset_details", 1),
                ("get_redirect_rules", 1),
                ("start_sync", 1),
                ("upload_chunks", 1),
                ("execute_operations", 1),
            ],
            528_204,
        ),
    );
}

#[test]
fn few_medium_files() {
    // 10 × 2 MB → multi-chunk uploads packed by byte budget into 12 calls.
    assert_fingerprint(
        run_scenario("few_medium  10 × 2 MB", 10, 2 * 1024 * 1024),
        expected(
            &[
                ("version", 1),
                ("can_sync", 1),
                ("preparation_canary", 1),
                ("get_asset_details", 1),
                ("get_redirect_rules", 1),
                ("start_sync", 1),
                ("upload_chunks", 12),
                ("execute_operations", 1),
            ],
            20_976_577,
        ),
    );
}

#[test]
fn one_huge_file() {
    // A single 50 MB asset splits into chunks already at MAX (packing can't
    // help), so `upload_chunks` stays high at 28 calls.
    assert_fingerprint(
        run_scenario("one_huge    1 × 50 MB", 1, 50 * 1024 * 1024),
        expected(
            &[
                ("version", 1),
                ("can_sync", 1),
                ("preparation_canary", 1),
                ("get_asset_details", 1),
                ("get_redirect_rules", 1),
                ("start_sync", 1),
                ("upload_chunks", 28),
                ("execute_operations", 1),
            ],
            52_433_943,
        ),
    );
}
