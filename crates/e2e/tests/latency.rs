//! `#[ignore]`'d latency bench: the native transport's concurrency speedup on a
//! local pocket-ic network with an artificial per-update-call delay.
//!
//! # Why the artificial delay
//!
//! The win from concurrent uploads is overlapping *client-side round-trip
//! latency* across many in-flight ingress messages. A default local replica
//! finalizes almost instantly, so there is nothing to overlap and the effect
//! hides. The launcher's `artificial-delay-ms` (set in this fixture's
//! `icp.yaml`) adds a fixed delay to every *update* call at the replica, so the
//! upload phase — all update calls — pays it once per call when serial and
//! overlaps it when concurrent. The diff's asset listing is queries, which are
//! not delayed, so the measured gap is the upload phase alone.
//!
//! # Serial baseline
//!
//! Concurrency here is a tunable cap on one code path: `AgentCall`'s
//! `max_in_flight`. `max_in_flight = 1` (via `buffered(1)`) runs the batch
//! strictly one call at a time — the serial baseline — and `max_in_flight = N`
//! the concurrent treatment. Same path, only the concurrency variable changes.
//! (The future plugin bench will do the same, sweeping the icp-cli runtime's
//! batch-import cap over {1, N}.)
//!
//! # Running
//!
//! Needs `make wasm` first (the fixture pins `../../dist/canister.wasm`). Then:
//!
//! ```sh
//! cargo test -p e2e --test latency -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use candid::Principal;
use e2e::{LocalNetwork, canister_id, gateway_url, icp_cmd, setup_project};
use ic_agent::Agent;
use ic_agent::identity::AnonymousIdentity;
use sync_agent::{SyncOpts, sync};

/// Files and per-file size for the payload. Each file is incompressible and
/// larger than half the ~1.9 MB per-call chunk budget, so no two share a call:
/// the packer emits one upload call per file, giving many batches for the
/// concurrency to overlap.
const FILES: usize = 16;
const FILE_BYTES: usize = 1_500_000;
/// Concurrency cap for the concurrent run (the serial run uses 1).
const MAX_IN_FLIGHT: usize = 16;

/// Write `FILES` incompressible files into `dir`. Bytes come from a deterministic
/// LCG so gzip can't shrink them — keeping each file a single stored chunk and
/// keeping encoder choice out of the measurement.
fn write_incompressible_files(dir: &std::path::Path) {
    let mut state: u64 = 0xdead_beef_cafe_f00d;
    let mut buf = vec![0u8; FILE_BYTES];
    for i in 0..FILES {
        for b in buf.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
        std::fs::write(dir.join(format!("f_{i:05}.bin")), &buf).unwrap();
    }
}

/// Sync `dir` to `canister` at `max_in_flight`, returning the wall-clock. Signs
/// as the anonymous identity, which the caller has authorized on the canister.
async fn sync_timed(
    api_url: &str,
    canister: Principal,
    dir: String,
    max_in_flight: usize,
) -> Duration {
    let agent = Agent::builder()
        .with_url(api_url)
        .with_identity(AnonymousIdentity)
        .build()
        .expect("build ic-agent");
    agent
        .fetch_root_key()
        .await
        .expect("fetch_root_key (local replica)");
    let started = Instant::now();
    let summary = sync(Arc::new(agent), canister, dir, SyncOpts { max_in_flight })
        .await
        .expect("sync failed");
    let elapsed = started.elapsed();
    println!("  max_in_flight={max_in_flight}: {elapsed:?}\n  {summary}");
    elapsed
}

#[test]
#[ignore = "latency bench: run with --ignored --nocapture (needs make wasm + local network launcher)"]
fn native_transport_concurrency_speedup() {
    let project = setup_project("latency");
    // Declared after `project` so it stops the replica before the dir is removed.
    let _network = LocalNetwork::start(project.path());

    // Install both build-only canisters (no sync step); we upload via sync-agent.
    icp_cmd(project.path()).arg("deploy").assert().success();

    // sync-agent signs as the anonymous identity, which isn't a controller of the
    // icp-deployed canisters, so authorize it explicitly. `authorize` is
    // controller-only, and `icp` (the deployer/controller) makes the call.
    let anon = Principal::anonymous().to_text();
    for name in ["bench-serial", "bench-concurrent"] {
        icp_cmd(project.path())
            .args([
                "canister",
                "call",
                name,
                "authorize",
                &format!("(principal \"{anon}\")"),
            ])
            .assert()
            .success();
    }

    let api_url = gateway_url(project.path()); // launcher: gateway URL == API URL
    let serial_cid = Principal::from_text(canister_id(project.path(), "bench-serial")).unwrap();
    let concurrent_cid =
        Principal::from_text(canister_id(project.path(), "bench-concurrent")).unwrap();

    let payload = tempfile::tempdir().unwrap();
    write_incompressible_files(payload.path());
    let dir = payload.path().to_str().unwrap().to_string();

    println!("\nnative upload latency: {FILES} × {FILE_BYTES} bytes");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (serial, concurrent) = rt.block_on(async {
        let serial = sync_timed(&api_url, serial_cid, dir.clone(), 1).await;
        let concurrent = sync_timed(&api_url, concurrent_cid, dir.clone(), MAX_IN_FLIGHT).await;
        (serial, concurrent)
    });

    let speedup = serial.as_secs_f64() / concurrent.as_secs_f64();
    println!(
        "\nserial (1) {serial:?}  vs  concurrent ({MAX_IN_FLIGHT}) {concurrent:?}  →  {speedup:.2}× faster"
    );

    // Concurrency should be well clear of serial. We don't assert a specific
    // multiple — the fixed sequential calls (start_sync, execute_operations) and
    // real transfer/polling put a floor on the concurrent run, so the local
    // ratio is a "trend", not the full round-trip speedup (that shows on
    // mainnet). Require a solid margin so the guard trips on a real regression
    // (e.g. uploads accidentally serialized) but not on machine-to-machine noise.
    assert!(
        serial.as_secs_f64() > concurrent.as_secs_f64() * 1.5,
        "expected concurrent uploads clearly faster than serial, \
         got serial={serial:?} concurrent={concurrent:?}"
    );
}
