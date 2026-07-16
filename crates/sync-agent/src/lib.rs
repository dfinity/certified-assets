//! Native transport for `sync-core`, built on `ic-agent` + `tokio`.
//!
//! `sync-core` is synchronous and transport-agnostic: it hands the upload phase
//! all its `upload_chunks` calls at once through [`CanisterCall::dispatch_batch`]
//! and maps the returned chunk ids back by position. This crate supplies a
//! transport that runs that batch **concurrently** — up to `max_in_flight`
//! ingress messages in flight at once — so a native client overlaps the
//! per-call round-trip latency the way the legacy `dfx` uploader did.
//!
//! It lives outside `sync-core` on purpose: `sync-core` stays lean and WASI-free
//! (the `icp deploy` sync-plugin compiles it to Wasm), while the heavy native
//! stack (`ic-agent`, `tokio`, `reqwest`) lives here for clients that run their
//! own async runtime.

use std::sync::Arc;

use candid::Principal;
use futures::stream::{self, StreamExt};
use ic_agent::Agent;
use sync_core::{Call, CallType, CanisterCall};

/// A `sync-core` transport backed by a live `ic-agent`.
///
/// `dispatch` (single call) blocks on the agent; `dispatch_batch` runs the
/// calls concurrently — up to `max_in_flight` at a time — while yielding results
/// **in input order**, which is the positional contract `sync-core` relies on.
pub struct AgentCall {
    agent: Arc<Agent>,
    canister_id: Principal,
    /// Handle to the runtime that spawned the blocking `sync-core` call, so the
    /// synchronous `dispatch*` methods can drive async agent calls via
    /// `block_on`. Captured before `spawn_blocking` (see [`sync`]).
    rt: tokio::runtime::Handle,
    /// Ceiling on concurrent in-flight update calls, mirroring the legacy `dfx`
    /// uploader's cap. Transport-owned; `sync-core` never sees it.
    max_in_flight: usize,
}

impl AgentCall {
    /// The async worker both `dispatch` and `dispatch_batch` drive. Moves the
    /// already-encoded candid bytes to the canister and returns the raw reply.
    /// Native clients call directly, so `Call::direct` is not consulted.
    async fn send(&self, c: Call) -> Result<Vec<u8>, String> {
        let r = match c.call_type {
            CallType::Update => {
                self.agent
                    .update(&self.canister_id, &c.method)
                    .with_arg(c.arg)
                    .call_and_wait()
                    .await
            }
            CallType::Query => {
                self.agent
                    .query(&self.canister_id, &c.method)
                    .with_arg(c.arg)
                    .call()
                    .await
            }
        };
        r.map_err(|e| format!("{}: {e}", c.method))
    }
}

impl CanisterCall for AgentCall {
    fn dispatch(&self, c: Call) -> Result<Vec<u8>, String> {
        self.rt.block_on(self.send(c))
    }

    // Override only the raw batch seam; the typed `call` / `call_batch` are
    // inherited. `buffered` (NOT `buffer_unordered`) runs up to `max_in_flight`
    // futures concurrently while yielding them in input order — so `result[i]`
    // stays the reply to `calls[i]`, which is what the upload path's positional
    // id scatter depends on.
    fn dispatch_batch(&self, calls: Vec<Call>) -> Vec<Result<Vec<u8>, String>> {
        self.rt.block_on(async {
            stream::iter(calls)
                .map(|c| self.send(c))
                .buffered(self.max_in_flight)
                .collect::<Vec<_>>()
                .await
        })
    }
}

/// Concurrency and behavior knobs for [`sync`].
pub struct SyncOpts {
    /// Maximum number of update calls in flight at once. Defaults, via
    /// [`SyncOpts::default`], to 16 — matching the legacy `dfx` uploader's cap.
    pub max_in_flight: usize,
}

impl Default for SyncOpts {
    fn default() -> Self {
        Self { max_in_flight: 16 }
    }
}

/// Sync a prepared `dir` to `canister_id` using `agent`, running chunk uploads
/// concurrently. This is the one call a native client makes; it hides the
/// sync/async bridge (`sync-core` is synchronous) by running the blocking sync
/// on a dedicated thread while agent calls are driven back on `agent`'s runtime.
pub async fn sync(
    agent: Arc<Agent>,
    canister_id: Principal,
    dir: String,
    opts: SyncOpts,
) -> anyhow::Result<String> {
    let identity = agent
        .get_principal()
        .map_err(|e| anyhow::anyhow!("agent has no identity principal: {e}"))?
        .to_text();
    let rt = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let call = AgentCall {
            agent,
            canister_id,
            rt,
            max_in_flight: opts.max_in_flight.max(1),
        };
        // Native clients call the canister directly, so no proxy id.
        sync_core::sync(&call, &[dir], &identity, None)
    })
    .await
    .map_err(|e| anyhow::anyhow!("sync task panicked: {e}"))?
    .map_err(|e| anyhow::anyhow!("sync failed: {e}"))
}
