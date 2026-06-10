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
//! Types that only ever live on one side stay in that crate: the canister's
//! internal `ListRequest` and its fuller, authoritative `AssetDetails` producer
//! type (which carries `length`/`modified`/`headers`) remain in `canister-core`.

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Identifies an in-progress sync. Sequential and monotonic across the
/// canister's whole lifetime, so a session id is never reused — calls carrying
/// a superseded id are cleanly rejected.
pub type SessionId = u64;
pub type ChunkId = u64;

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
    pub headers: Option<Vec<(String, String)>>,
}

/// Add or change content for an asset, by content encoding.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<ChunkId>,
    /// If set: appended as the final chunk.
    pub last_chunk: Option<ByteBuf>,
    pub sha256: Option<ByteBuf>,
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
pub struct SetAssetPropertiesArguments {
    pub key: String,
    pub headers: Option<Option<Vec<(String, String)>>>,
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
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct SetRedirectRulesArguments {
    pub rules: Vec<RedirectRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub enum BatchOperationKind {
    CreateAsset(CreateAssetArguments),
    SetAssetContent(SetAssetContentArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    DeleteAsset(DeleteAssetArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
    SetRedirectRules(SetRedirectRulesArguments),
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct ExecuteOperationsArguments {
    pub session_id: SessionId,
    pub operations: Vec<BatchOperationKind>,
    /// Set on the last call of a sync. When all operations have been applied,
    /// the canister finalizes the sync and returns to the "no ongoing sync"
    /// state. Non-final calls keep the session open for further operations.
    pub is_final: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct CancelSyncArguments {
    pub session_id: SessionId,
}

/// Result of `start_sync`. `Busy` is a normal, expected outcome — not an error
/// — so the caller can surface who holds the lock and decide whether to wait.
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
/// `content` (owned `ByteBuf`); the canister receives the same shape. Candid
/// copies the bytes into the message buffer on encode either way, so owning
/// here costs nothing over a borrow.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct CreateChunksArguments {
    pub session_id: SessionId,
    pub content: Vec<ByteBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct CreateChunksResponse {
    pub chunk_ids: Vec<ChunkId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct AssetProperties {
    pub headers: Option<Vec<(String, String)>>,
}

/// One encoding of an asset, as the `list` query reports it. This is the
/// client-decoded projection: the canister's authoritative producer type also
/// carries `length` and `modified`, which clients don't need and therefore
/// don't decode.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<ByteBuf>,
}

/// An asset as the `list` query reports it (client-decoded projection — see
/// [`AssetEncodingDetails`]).
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}
