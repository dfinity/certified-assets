//! Certification: everything that turns the canister's served content into an
//! IC-verifiable certified tree, behind a deliberately narrow interface.
//!
//! This module merges what used to be three flat modules so the connections are
//! traceable in one place, and so the bulk of the machinery can be *private*:
//!
//! - [`nested_tree`] — a generic Merkle tree ([`AsHashTree`]-backed). Used only
//!   by `primitives`, so it is entirely private here.
//! - [`primitives`] — the IC-certification vocabulary: tree-path addressing
//!   ([`AssetPath`], [`HashTreePath`], [`NestedTreeKey`]), response hashing
//!   ([`response_hash`], [`ResponseHash`]), certificate-expression builders, and
//!   the `CertifiedResponses` tree wrapper. The addressing/hashing helpers are
//!   re-exported for the domain modules (`asset`, `redirect`, `protection`) that
//!   compute response hashes; the tree wrapper itself stays private, reachable
//!   only by the certifier.
//! - [`certifier`] — the stateful [`Certifier`]: owns the `CertifiedResponses`
//!   tree, the per-rule certified entries, and the env cookie, plus the policy
//!   that keeps the certified leaf byte-identical to the served response.
//!
//! Only the names re-exported below cross this module's boundary. The tree type,
//! its addressing internals ([`primitives::RequestHash`], `WitnessResult`), and the whole
//! `nested_tree` are implementation details.
//!
//! [`AsHashTree`]: ic_certification::AsHashTree

mod certifier;
mod nested_tree;
mod primitives;

pub(crate) use certifier::Certifier;
pub(crate) use primitives::{
    build_ic_certificate_expression_from_headers,
    build_ic_certificate_expression_from_headers_and_encoding,
    build_ic_certificate_expression_header, response_hash, AssetKey, AssetPath,
    CertificateExpression, HashTreePath, NestedTreeKey, ResponseHash,
};
