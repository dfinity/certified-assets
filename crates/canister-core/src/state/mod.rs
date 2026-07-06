//! The certified-assets state machine: the orchestrator that ties the durable
//! store to the certification layer and exposes the canister's behavior.
//!
//! [`State`] itself holds no stable structures and no certified tree directly. It
//! composes two owned pieces plus the small transient/heap bits that don't belong
//! to either:
//! - [`crate::store::Store`] — all durable state in stable memory (settings,
//!   per-asset metadata, content chunks, tokens). The sole owner of the
//!   `ic-stable-structures` handles and the memory layout.
//! - [`crate::cert::Certifier`] — the derived certified-response tree, the
//!   per-rule certified entries, the env cookie, and the policy that maintains
//!   them so the certified leaf always matches the served response.
//! - transient upload state (staged chunks, the active sync session) and the
//!   hot-path access-protection token index, which live on `State`.
//!
//! `State`'s methods are the orchestration: an asset mutation writes the `Store`
//! then asks the `Certifier` to re-certify; serving reads the `Store` for content
//! and the `Certifier` for witnesses. There is no serialize/deserialize step
//! across upgrades — `pre_upgrade` is gone and `post_upgrade` only rebuilds the
//! derived heap state from the store (see [`State::post_upgrade_rebuild`]).
//!
//! Every `impl State` block lives in this module, split across focused
//! submodules so `State`'s behavior is discoverable in one place while each
//! concern stays small. This module owns the struct, its construction, and the
//! thin store/certifier accessors; the behavior is split into:
//! - [`assets`] — asset create/set-content/unset/delete/set-headers + details query
//! - [`rules`] — redirect-rule mutations + the 404 fallback + rules query
//! - [`env`](mod@env) — the env cookie capture / re-certify path
//! - [`hashing`] — the canonical state-hash computation
//! - [`serving`] — the HTTP read path (`http_request` and its resolvers)
//! - [`sync`] — start/upload/execute sync orchestration (and the sync data types)
//! - [`protection`] — access protection (the "private app" feature)
//! - [`upgrade`] — rebuilding all derived heap state after an upgrade
//!
//! Because all of them are submodules here, `State`'s owned pieces
//! (`store`, `certifier`, `sync_session`, `token_index`) are **private** to this
//! module tree — no other part of the crate can reach into them.
//!
//! NB. This module does not depend on `ic_cdk` for environment access (time,
//! certificates): those are passed in as formal arguments so the state machine
//! is easy to test. It does use `ic-stable-structures`' `DefaultMemoryImpl`,
//! which transparently resolves to real stable memory on wasm and to an
//! in-process `VectorMemory` off-wasm (which is what lets the tests drive a full
//! upgrade roundtrip over a shared memory handle).

mod assets;
mod env;
mod protection;
mod hashing;
mod rules;
mod serving;
mod upgrade;

// `pub(crate)` (not `mod`) because its data types cross the state boundary:
// `ComputationStatus` (the sync-driver result, used in `lib`),
// `ExecuteOperationsProgress` (benches), and `SYNC_IDLE_TIMEOUT_NANOS` (tests)
// are reached as `crate::state::sync::…`.
pub(crate) mod sync;

use crate::cert::{AssetKey, Certifier};
use crate::store::Store;
use candid::Principal;
use ic_certification::Hash;
use ic_stable_structures::DefaultMemoryImpl;
use std::collections::HashMap;
use sync::{Chunk, SyncSession};
use wire_types::SessionId;

/// Maximum number of items the canister returns from a single paginated query
/// (`get_asset_details`, `get_redirect_rules`). The caller follows the cursor
/// until it sees a short or empty page; it never needs to know this value.
pub const PAGE_SIZE: usize = 100;

pub struct State {
    /// Durable state: everything persisted in stable memory. All storage access
    /// funnels through this typed interface — `State` never touches a
    /// `StableCell`/`StableBTreeMap`/`MemoryId` directly. Private: every
    /// `impl State` block lives in a submodule of this module, so they can all
    /// reach it while the store's own internals — and this field — stay hidden
    /// from the rest of the crate. See [`Store`].
    store: Store,

    // ---- transient heap (lost on upgrade) ----
    /// Chunks staged by `upload_chunks` for the current sync, in upload order:
    /// the slot index is the chunk id (`ChunkId`). `SetAssetContent` `take()`s
    /// each slot as it consumes the bytes, leaving a `None` hole, so memory is
    /// freed incrementally without renumbering the surviving slots. Cleared on
    /// sync start/finish. The plugin reproduces these same indices locally, so
    /// they are never sent over the wire. `pub(crate)` because the unit tests and
    /// benches stage chunks directly before driving a sync.
    pub(crate) chunks: Vec<Option<Chunk>>,
    /// The single in-progress sync, if any. At most one runs at a time.
    sync_session: Option<SyncSession>,

    // ---- derived heap (rebuilt in post_upgrade) ----
    /// The certified-response tree, the per-rule certified entries, the env
    /// cookie, and the policy that maintains them. All derived from `store`
    /// (plus the env snapshot) and rebuilt on upgrade. Serving reads it for
    /// witnesses; the mutation paths drive its (re)certification. Private for the
    /// same reason as `store`. See [`Certifier`].
    certifier: Certifier,
    /// Hot-path access-protection index: `SHA-256(value) -> expires_at`. The
    /// per-request check hashes the presented cookie and looks it up here — a heap-map read, no
    /// stable access or `TokenMeta` deserialize. Pure derived state (every entry
    /// is reconstructable from the token store, which carries each token's
    /// `token_id` and expiry), so it lives in heap and is rebuilt on upgrade like
    /// the certified tree. Kept one-to-one with the token store; revocation/expiry
    /// are live.
    token_index: HashMap<[u8; 32], u64>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(DefaultMemoryImpl::default())
    }
}

impl State {
    /// Builds a `State` over the given stable memory. The durable [`Store`]
    /// transparently picks up existing data if the memory was already populated
    /// (e.g. after an upgrade), or starts empty over fresh memory; the heap
    /// fields start empty and are rebuilt from that durable state in
    /// `post_upgrade`.
    ///
    /// The explicit-memory constructor is what makes the upgrade-roundtrip unit
    /// test possible: off-wasm `DefaultMemoryImpl` is a cheaply-cloneable handle
    /// to a shared byte buffer, so a test can build two `State`s over the same
    /// memory to simulate an upgrade.
    pub fn new(memory: DefaultMemoryImpl) -> Self {
        Self {
            store: Store::new(memory),
            chunks: Vec::new(),
            sync_session: None,
            certifier: Certifier::default(),
            token_index: HashMap::new(),
        }
    }

    // ---- settings accessors ----

    /// Allocates a fresh, never-reused sync session id.
    pub fn alloc_session_id(&mut self) -> SessionId {
        self.store.alloc_session_id()
    }

    /// Whether an asset exists at `key`.
    pub fn contains_asset(&self, key: &AssetKey) -> bool {
        self.store.contains_asset(key)
    }

    /// Whether the asset at `key` exists and stores any encoding as more than one
    /// chunk. A 4xx custom-error-page rule can only serve a single-chunk target
    /// (see the alias-rule certification in [`Certifier`]), so the sync op guard
    /// rejects 4xx rules whose target is already multi-chunk.
    pub fn target_is_multichunk(&self, key: &str) -> bool {
        self.store
            .get_asset(&key.to_string())
            .is_some_and(|meta| meta.encodings.values().any(|e| e.num_chunks > 1))
    }

    pub fn authorize(&mut self, principal: Principal) {
        self.store.authorize(principal);
    }

    pub fn deauthorize(&mut self, principal: &Principal) {
        self.store.deauthorize(principal);
    }

    pub fn list_authorized(&self) -> Vec<Principal> {
        self.store.list_authorized()
    }

    pub fn is_authorized(&self, principal: &Principal) -> bool {
        self.store.is_authorized(principal)
    }

    pub fn root_hash(&self) -> Hash {
        self.certifier.root_hash()
    }

    // ---- access protection ----

    /// The configured login-page path when access protection is on, else `None`. Reads
    /// the in-memory `StableCell`, so it is cheap enough to call per request.
    pub fn protection_login_page(&self) -> Option<String> {
        self.store.protection_login_page()
    }
}
