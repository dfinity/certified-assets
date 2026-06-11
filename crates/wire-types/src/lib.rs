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

/// The content encodings the canister and sync plugin support. A deliberately
/// small, closed set — see `sync-core`'s `content` module for the
/// simplicity / bandwidth / canister-storage trade-off behind which encodings
/// are produced. Carried as a Candid variant (one byte on the wire) rather than
/// a string, and used directly as the per-encoding map key in the canister's
/// stable state.
///
/// `Identity` is the uncompressed form. It is a real, stored encoding (the
/// fallback body served when nothing else is acceptable), but it is *not* a
/// valid `Content-Encoding` response value — the IANA `identity` token exists
/// only in the `Accept-Encoding` context — so it is never emitted as a header
/// ([`Encoding::header_name`] returns `None`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, CandidType, Serialize, Deserialize,
)]
pub enum Encoding {
    Identity,
    Gzip,
    Brotli,
}

impl Encoding {
    /// Preference order for serving when the client expressed no usable
    /// `Accept-Encoding`: identity first (uncompressed, maximally compatible),
    /// then the compressed forms. Also the order encodings are certified in.
    pub const PREFERENCE_ORDER: [Encoding; 3] =
        [Encoding::Identity, Encoding::Gzip, Encoding::Brotli];

    /// The HTTP coding token for this encoding (`identity` / `gzip` / `br`).
    /// Always a real name, including for identity — use [`Self::header_name`]
    /// when building the `Content-Encoding` response header.
    pub const fn label(self) -> &'static str {
        match self {
            Encoding::Identity => "identity",
            Encoding::Gzip => "gzip",
            Encoding::Brotli => "br",
        }
    }

    /// The `Content-Encoding` response header value, or `None` for identity
    /// (which must not carry the header).
    pub const fn header_name(self) -> Option<&'static str> {
        match self {
            Encoding::Identity => None,
            Encoding::Gzip => Some("gzip"),
            Encoding::Brotli => Some("br"),
        }
    }

    pub const fn is_identity(self) -> bool {
        matches!(self, Encoding::Identity)
    }

    /// Parses a single `Accept-Encoding` / `Content-Encoding` coding token
    /// (case-insensitive), ignoring any `;q=…` parameters. Returns `None` for
    /// codings we don't support.
    pub fn from_token(token: &str) -> Option<Self> {
        let name = token.split(';').next().unwrap_or(token).trim();
        if name.eq_ignore_ascii_case("identity") {
            Some(Encoding::Identity)
        } else if name.eq_ignore_ascii_case("gzip") {
            Some(Encoding::Gzip)
        } else if name.eq_ignore_ascii_case("br") {
            Some(Encoding::Brotli)
        } else {
            None
        }
    }

    /// Parses an `Accept-Encoding` header value into the supported encodings the
    /// client will accept, in the client's listed order. Unsupported codings are
    /// dropped, and a coding with an explicit `q=0` ("not acceptable") is
    /// excluded. The listed order is preserved so callers can honour client
    /// preference before falling back to [`Self::PREFERENCE_ORDER`].
    pub fn parse_accept_encoding(value: &str) -> Vec<Encoding> {
        value
            .split(',')
            .filter_map(|part| {
                let enc = Encoding::from_token(part)?;
                (!token_is_rejected(part)).then_some(enc)
            })
            .collect()
    }
}

/// Whether an `Accept-Encoding` token carries an explicit `q=0`, marking the
/// coding "not acceptable". Other `q` weights are ignored — we honour the
/// client's listed order rather than reordering by weight.
fn token_is_rejected(token: &str) -> bool {
    token.split(';').skip(1).any(|param| {
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let val = kv.next().unwrap_or("").trim();
        key.eq_ignore_ascii_case("q") && val.parse::<f32>().map(|q| q <= 0.0).unwrap_or(false)
    })
}

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
    pub encoding: Encoding,
    pub chunk_ids: Vec<ChunkId>,
    pub sha256: ByteBuf,
}

/// Remove content for an asset, by content encoding.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Serialize, Deserialize)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub encoding: Encoding,
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
    pub encoding: Encoding,
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

#[cfg(test)]
mod tests {
    use super::Encoding::{self, Brotli, Gzip, Identity};

    #[test]
    fn header_name_omits_identity() {
        assert_eq!(Identity.header_name(), None);
        assert_eq!(Gzip.header_name(), Some("gzip"));
        assert_eq!(Brotli.header_name(), Some("br"));
        assert!(Identity.is_identity());
        assert!(!Gzip.is_identity());
    }

    #[test]
    fn label_is_always_a_name() {
        assert_eq!(Identity.label(), "identity");
        assert_eq!(Gzip.label(), "gzip");
        assert_eq!(Brotli.label(), "br");
    }

    #[test]
    fn from_token_is_case_insensitive_and_ignores_params() {
        assert_eq!(Encoding::from_token("gzip"), Some(Gzip));
        assert_eq!(Encoding::from_token("GZIP"), Some(Gzip));
        assert_eq!(Encoding::from_token("br"), Some(Brotli));
        assert_eq!(Encoding::from_token("identity"), Some(Identity));
        assert_eq!(Encoding::from_token("  gzip ; q=0.5 "), Some(Gzip));
        // Unsupported codings.
        assert_eq!(Encoding::from_token("deflate"), None);
        assert_eq!(Encoding::from_token("zstd"), None);
        assert_eq!(Encoding::from_token("*"), None);
    }

    #[test]
    fn parse_accept_encoding_keeps_client_order() {
        assert_eq!(
            Encoding::parse_accept_encoding("br, gzip, identity"),
            vec![Brotli, Gzip, Identity]
        );
        assert_eq!(
            Encoding::parse_accept_encoding("gzip, br"),
            vec![Gzip, Brotli]
        );
    }

    #[test]
    fn parse_accept_encoding_ignores_q_weights_but_drops_q0() {
        // Non-zero weights are kept, in listed order (we don't reorder by q).
        assert_eq!(
            Encoding::parse_accept_encoding("br;q=0.8, gzip;q=1.0"),
            vec![Brotli, Gzip]
        );
        // q=0 means "not acceptable" — the fix for the bug where a weighted
        // token like `gzip;q=1.0` used to match nothing and silently fall back
        // to identity.
        assert_eq!(
            Encoding::parse_accept_encoding("gzip;q=0, br"),
            vec![Brotli]
        );
        assert_eq!(
            Encoding::parse_accept_encoding("gzip;q=0.000"),
            Vec::<Encoding>::new()
        );
    }

    #[test]
    fn parse_accept_encoding_drops_unsupported_and_empty() {
        assert_eq!(
            Encoding::parse_accept_encoding("deflate, zstd, *"),
            Vec::<Encoding>::new()
        );
        assert_eq!(Encoding::parse_accept_encoding(""), Vec::<Encoding>::new());
    }

    #[test]
    fn preference_order_is_identity_first() {
        assert_eq!(Encoding::PREFERENCE_ORDER, [Identity, Gzip, Brotli]);
        // Ord matches declaration order, so it is a valid BTreeMap key ordering.
        assert!(Identity < Gzip && Gzip < Brotli);
    }
}
