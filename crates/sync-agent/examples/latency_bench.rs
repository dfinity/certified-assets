//! Manual latency bench for the concurrent native transport.
//!
//! This times one `sync_agent::sync` at a chosen concurrency against a
//! canister you control. It is **not** a CI test: it needs a live replica and a
//! deployed certified-assets canister the given identity may sync. Build-checked
//! by `cargo build --examples`, run explicitly.
//!
//! # Why it lives here and not in a PocketIC test
//!
//! The win from concurrency is overlapping *client-side round-trip latency*
//! across many in-flight ingress messages. PocketIC executes rounds
//! deterministically with nothing to overlap, so it can't show the effect. A
//! single-node local replica has small finality/poll latency, so you'll see the
//! *trend*; the full ~2× lives on mainnet where each round-trip is seconds.
//!
//! # Running
//!
//! Because a re-sync of an unchanged project is a no-op diff (nothing to
//! upload), each concurrency level must run against a *fresh* canister. Deploy
//! two canisters, then:
//!
//! ```sh
//! BENCH_REPLICA_URL=http://127.0.0.1:4943 \
//! BENCH_IDENTITY_PEM=$HOME/.config/icp/identity/default/identity.pem \
//! BENCH_DIR=./dist \
//! BENCH_CANISTER_ID=<fresh-canister-a> BENCH_MAX_IN_FLIGHT=1 \
//!   cargo run -p sync-agent --release --example latency_bench
//!
//! BENCH_CANISTER_ID=<fresh-canister-b> BENCH_MAX_IN_FLIGHT=16 \
//!   cargo run -p sync-agent --release --example latency_bench
//! ```
//!
//! Compare the two reported wall-clock times.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use candid::Principal;
use ic_agent::Agent;
use sync_agent::{SyncOpts, sync};

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

/// Load an identity from a PEM file, trying secp256k1 then Ed25519 — the two
/// key types `icp`/`dfx` write.
fn load_identity(pem: &str) -> anyhow::Result<Arc<dyn ic_agent::Identity>> {
    use ic_agent::identity::{BasicIdentity, Secp256k1Identity};
    if let Ok(id) = Secp256k1Identity::from_pem_file(pem) {
        return Ok(Arc::new(id));
    }
    let id = BasicIdentity::from_pem_file(pem)
        .with_context(|| format!("could not read {pem} as a secp256k1 or Ed25519 PEM"))?;
    Ok(Arc::new(id))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let replica_url = env("BENCH_REPLICA_URL")?;
    let canister_id = Principal::from_text(env("BENCH_CANISTER_ID")?)
        .context("BENCH_CANISTER_ID is not a valid principal")?;
    let dir = env("BENCH_DIR")?;
    let identity = load_identity(&env("BENCH_IDENTITY_PEM")?)?;
    let max_in_flight: usize = env("BENCH_MAX_IN_FLIGHT")
        .ok()
        .as_deref()
        .unwrap_or("16")
        .parse()
        .context("BENCH_MAX_IN_FLIGHT must be a positive integer")?;

    let agent = Agent::builder()
        .with_url(&replica_url)
        .with_arc_identity(identity)
        .build()
        .context("build ic-agent")?;
    // Local replicas use a self-signed root key the agent must fetch; never do
    // this against mainnet.
    agent
        .fetch_root_key()
        .await
        .context("fetch_root_key (local replica only)")?;

    println!("syncing {dir} -> {canister_id} at max_in_flight={max_in_flight} via {replica_url}");
    let started = Instant::now();
    let summary = sync(
        Arc::new(agent),
        canister_id,
        dir.clone(),
        SyncOpts { max_in_flight },
    )
    .await?;
    let elapsed = started.elapsed();

    println!("{summary}");
    println!("── max_in_flight={max_in_flight}  wall: {elapsed:?} ──");
    Ok(())
}
