//! Local asset preparation: turn a project's `dist/` directory into the exact
//! per-asset content + headers + redirect rules a sync uploads — and into the
//! canonical [`state_hash::Manifest`].
//!
//! This is the **local half** of the sync pipeline, split out of `sync-core` so
//! it can be reused by two independent callers with no canister-call or WASI
//! code between them:
//!
//! - `sync-core`'s `sync()` calls [`prepare_project`], then diffs the result
//!   against the canister and uploads what changed.
//! - the standalone `state-hash-cli` verifier calls [`state_hash_for_dir`] to
//!   reproduce a canister's `state_hash()` from public source, with no replica,
//!   identity, or deploy capability linked in.
//!
//! Because both sides build the canonical manifest from this one code path, the
//! canister's stored-state hash and the verifier's `dist/`-derived hash agree by
//! construction (the cross-implementation test pins it).
//!
//! The one thing this crate does *not* decide is how content is compressed: the
//! caller supplies a [`Compressors`] registry. Both callers above inject
//! [`Compressors::canonical`], which is what makes their hashes comparable; a
//! platform embedding `sync-agent` may inject its own.

pub mod canary;
pub mod compressors;
pub mod content;
pub mod glob;
pub mod headers;
pub mod html_handling;
pub mod not_found;
pub mod redirects;
pub mod scan;

pub use compressors::{CompressFn, Compressors};

mod prepare;
pub use prepare::{
    ContentTypeOverrides, MAX_CHUNK_SIZE, PlannedAsset, PreparedAsset, PreparedChunk,
    PreparedEncoding, PreparedProject, ProjectPlan, manifest, plan_project,
    plan_project_with_content_types, prepare_project, prepare_project_with_content_types,
    state_hash_for_dir,
};

/// Strips a Netlify-style trailing comment from a single line of a `_redirects`
/// or `_headers` file. A `#` only starts a comment when it sits at the start of
/// the line or is preceded by whitespace; a `#` inside a token (e.g. the URL
/// fragment in `/to/#topic`, or a CSP `report-uri /csp#endpoint`) is preserved.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut prev_is_ws = true;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && prev_is_ws {
            return &line[..i];
        }
        prev_is_ws = b.is_ascii_whitespace();
    }
    line
}

#[cfg(test)]
mod strip_comment_tests {
    use super::strip_comment;

    #[test]
    fn leading_hash_strips_whole_line() {
        assert_eq!(strip_comment("# full-line comment"), "");
    }

    #[test]
    fn hash_after_space_starts_comment() {
        assert_eq!(strip_comment("/old /new 301 # tail"), "/old /new 301 ");
    }

    #[test]
    fn hash_after_tab_starts_comment() {
        assert_eq!(strip_comment("/old /new 301\t# tail"), "/old /new 301\t");
    }

    #[test]
    fn hash_inside_token_is_preserved() {
        assert_eq!(
            strip_comment("/from /to/#topic 301"),
            "/from /to/#topic 301"
        );
    }

    #[test]
    fn no_hash_returns_input_unchanged() {
        assert_eq!(strip_comment("/from /to 301"), "/from /to 301");
    }

    #[test]
    fn empty_input() {
        assert_eq!(strip_comment(""), "");
    }
}
