//! Canister-call orchestration for the assets sync plugin.
//!
//! The local `dist/` preparation (scanning, MIME/encoding, `_headers`/`_redirects`
//! parsing, html-handling synthesis, content hashing) lives in the `asset-prep`
//! crate, shared with the offline `state-hash-cli` verifier. This crate keeps
//! only the half that talks to the canister: the [`CanisterCall`] transport, the
//! diff against current canister state, chunk upload, and staged execution.

mod canister;
mod sync;

pub use canister::{Call, CallType, CanisterCall};
pub use sync::sync;
