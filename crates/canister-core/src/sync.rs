//! Data types for a sync and its chunked uploads — the `State`-free data layer
//! of the sync domain.
//!
//! A sync stages chunked content under a [`SyncSession`] and then applies a
//! batch of operations incrementally, driven by the generic incremental-
//! computation harness ([`ComputationStatus`], [`ExecuteOperationsProgress`]) —
//! one operation per step, so a many-operation commit can yield between
//! operations.
//!
//! These are the pure data types; they cross the state boundary and are named by
//! `lib` (the driver loop), the tests, and the benches — which is why they live
//! at the crate root rather than inside `State`'s module tree. The `impl State`
//! methods that drive a sync — `start_sync`, `upload_chunks`,
//! `execute_operations` — are the `State`-bound half, in [`crate::state`]'s
//! private `sync` submodule.

use crate::cert::AssetKey;
use candid::Principal;
use wire_types::SessionId;

/// How long a sync may sit idle (no calls carrying its session id) before a
/// *different* caller is allowed to reclaim it. Comfortably shorter than any
/// real deploy's inter-call gap; the owner can always reclaim their own sync
/// immediately regardless of this.
pub(crate) const SYNC_IDLE_TIMEOUT_NANOS: u64 = 30_000_000_000;

/// The single in-progress sync. The canister holds at most one at a time;
/// `start_sync` rejects a second caller while this is present and non-stale.
pub(crate) struct SyncSession {
    pub id: SessionId,
    pub owner: Principal,
    pub last_activity_ns: u64,
}

/// Status of an incremental computation
#[derive(Clone, Debug)]
pub(crate) enum ComputationStatus<D, P, E> {
    /// Computation completed successfully
    Done(D),
    /// Computation in progress, with progress state to resume from
    InProgress(P),
    /// Computation failed with an error
    Error(E),
}

#[derive(Debug, Default)]
pub(crate) enum ExecuteOperationsProgress {
    /// Initial state when `execute_operations` is first called.
    ///
    /// This phase validates that the call belongs to the active sync (and
    /// records activity), then transitions to `ProcessingOperations` with the
    /// first operation.
    #[default]
    Starting,
    /// Processing operations one at a time. Each call applies a single operation
    /// (including writing a `SetAssetContent` encoding's chunks to stable memory
    /// and re-certifying the asset), then yields so the driver can reset the
    /// instruction counter between operations. Content is no longer hashed here:
    /// the client supplies the hashes and the canister trusts them (see
    /// [`State::complete_set_asset_content`](crate::state::State)).
    ProcessingOperations { operation_index: usize },
    /// After all operations of a **final** call are applied, recompute the cached
    /// canonical state hash (see the `state-hash` crate), folding in one asset per
    /// step so a many-asset state stays within the per-message instruction limit.
    /// The streaming hasher and a key cursor ride across steps; when the keyspace
    /// is exhausted the redirect rules are folded in, the hash is cached, and the
    /// computation is `Done`.
    HashingState {
        hasher: state_hash::StateHasher,
        /// The last asset key folded in; the next step resumes strictly after it
        /// (`None` ⇒ start from the first key).
        resume_after: Option<AssetKey>,
    },
}
