//! Candid wire types for the assets canister interface.
//!
//! These are the Rust shapes of the records and variants in
//! [`candid/assets.did`](../../../candid/assets.did) that cross the wire between
//! the canister (server) and the sync plugin / e2e tests (clients). They live in
//! a single dependency-light crate so the two sides share one definition instead
//! of each hand-maintaining its own copy.
//!
//! Conventions:
//! - `blob` fields use [`serde_bytes::ByteBuf`].
//! - Every type derives the union of what either side needs: `CandidType` (wire
//!   encode/decode), serde `Serialize`/`Deserialize` (the canister persists
//!   [`RedirectRule`] in stable state via CBOR), plus `Clone`/`Debug`/`Eq`.
//!
//! Internal canister types that never cross the wire — `Asset`, `AssetEncoding`,
//! and the stable-state shapes — stay in `canister-core`.

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub mod bundle_tag;
pub use bundle_tag::{format_tag, BUNDLE_TAG};

/// Identifies an in-progress sync. Sequential and monotonic across the
/// canister's whole lifetime, so a session id is never reused — calls carrying
/// a superseded id are cleanly rejected.
pub type SessionId = u64;
pub type ChunkId = u64;

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
}

/// Add or change content for an asset, by content encoding.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<ChunkId>,
    pub sha256: ByteBuf,
}

/// Remove content for an asset, by content encoding.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
}

/// Delete an asset.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct DeleteAssetArguments {
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct SetAssetHeadersArguments {
    pub key: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum RulePattern {
    /// Matches a single absolute path, e.g. `/old-page`.
    Exact(String),
    /// Matches any URL whose path starts with this prefix. The prefix must end
    /// with `/` so the subtree boundary is unambiguous.
    Subtree(String),
}

/// A single redirect/rewrite/error rule, mirroring one line of a Netlify-style
/// `_redirects` file.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct RedirectRule {
    /// Request-side pattern.
    pub from: RulePattern,
    /// Target. Interpretation depends on `status`:
    /// - 200: absolute asset path (rewrite — serve target's body)
    /// - 3xx: absolute URL or absolute path (sent as `Location`)
    /// - 4xx: absolute asset path to serve as the custom error page
    ///   (e.g. `/404.html`); if the asset doesn't exist the rule stays
    ///   inert and unmatched paths fall through to the canister's
    ///   built-in 404
    pub to: String,
    /// One of 200, 301, 302, 307, 308, 404, 410.
    pub status: u16,
    /// Extra response headers on top of status-intrinsic ones.
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct SetRedirectRulesArguments {
    pub rules: Vec<RedirectRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum Operation {
    CreateAsset(CreateAssetArguments),
    SetAssetContent(SetAssetContentArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    DeleteAsset(DeleteAssetArguments),
    SetAssetHeaders(SetAssetHeadersArguments),
    SetRedirectRules(SetRedirectRulesArguments),
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct ExecuteOperationsArguments {
    pub session_id: SessionId,
    pub operations: Vec<Operation>,
    /// Set on the last call of a sync. When all operations have been applied,
    /// the canister finalizes the sync and returns to the "no ongoing sync"
    /// state. Non-final calls keep the session open for further operations.
    pub is_final: bool,
}

/// Result of `start_sync`. `Busy` is a normal, expected outcome — not an error.
///
/// `Busy` is returned only when a *different* caller holds an active (not yet
/// stale) sync: a caller always reclaims their own sync immediately, and any
/// caller reclaims one that has gone stale, so neither path ever yields `Busy`.
/// The only recourse is therefore to wait — until the holder finishes, or its
/// sync goes stale and a retry reclaims it. `owner` and `idle_for_secs` report
/// who holds the lock and for how long.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum StartSyncResult {
    Started {
        session_id: SessionId,
    },
    Busy {
        owner: Principal,
        idle_for_secs: u64,
    },
}

/// Stage content chunks under a sync. The plugin moves chunk bytes into
/// `chunks` (owned `ByteBuf`); the canister receives the same shape. Candid
/// copies the bytes into the message buffer on encode either way, so owning
/// here costs nothing over a borrow.
///
/// The call returns nothing: chunk ids are not sent over the wire. Within a
/// sync the canister numbers staged chunks 0, 1, 2, … in arrival order, and
/// because uploads are issued one call at a time the plugin reproduces the same
/// numbering locally (see `pack_and_upload_chunks` in `sync-core`). Both ends
/// must keep that numbering in lockstep; if uploads are ever parallelized this
/// implicit agreement breaks and the ids must be exchanged explicitly again.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct UploadChunksArguments {
    pub session_id: SessionId,
    pub chunks: Vec<ByteBuf>,
}

/// One encoding of an asset, as the `get_asset_details` query reports it.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: ByteBuf,
}

/// An asset as the `get_asset_details` query reports it. `headers` carries the
/// asset's per-asset response headers; the sync diff reads them straight from
/// here, so there is no separate per-asset properties query.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
}
