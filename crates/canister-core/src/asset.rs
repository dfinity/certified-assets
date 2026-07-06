//! The asset domain: the persisted per-asset metadata types ([`AssetMeta`],
//! [`EncodingMeta`]) plus the pure helpers that derive an asset encoding's
//! certified-response data.
//!
//! Metadata and content live in stable memory; the certificate expression and
//! response hashes are **not** stored — they are recomputed on demand from the
//! metadata here. The derivation helpers take plain data (custom headers,
//! content type, encoding name, sha256) so the same logic runs both when an
//! encoding is written and when the certified-response tree is rebuilt after an
//! upgrade. How these types are encoded into stable memory (their `Storable`
//! impls) lives with the [`crate::store::Store`]; response building lives on
//! [`crate::state::State`], which owns the chunk store.

use crate::cert::{
    build_ic_certificate_expression_from_headers_and_encoding,
    build_ic_certificate_expression_header, response_hash, CertificateExpression, ResponseHash,
};
use ic_representation_independent_hash::Value;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use wire_types::Encoding;

/// Percent-encodes every non-alphanumeric byte (the `NON_ALPHANUMERIC` set),
/// matching what `decodeURIComponent` reverses on the client. Used to render the
/// `ic_env` cookie payload: it encodes the `&`/`=` separators so they survive
/// transport inside a single cookie value and are restored client-side.
fn url_encode(url: &str) -> String {
    utf8_percent_encode(url, NON_ALPHANUMERIC).to_string()
}

/// Per-asset metadata. Content bytes live in the chunk store, grouped by each
/// encoding's `content_id`. Persisted as CBOR (see the `Storable` impl in
/// [`crate::store`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetMeta {
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub encodings: BTreeMap<Encoding, EncodingMeta>,
}

/// Per-encoding metadata. The certificate expression and response hashes are
/// **not** stored — they are recomputed on demand from these fields plus the
/// asset's `headers`/`content_type`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodingMeta {
    /// Groups this encoding's chunks in the content store.
    pub content_id: u64,
    /// Number of chunks, so streaming tokens can be built without a range scan.
    pub num_chunks: u32,
    pub sha256: [u8; 32],
    /// Total encoded length, i.e. the sum of all chunk lengths. Used as the
    /// `/total` in a 206 `Content-Range` and to reject out-of-range requests,
    /// without re-reading the chunks.
    pub content_len: u64,
}

/// Status codes we certify for every asset encoding.
pub const STATUS_CODES_TO_CERTIFY: [u16; 2] = [200, 304];

/// Renders the value of the canister-injected `Set-Cookie: ic_env=…` header from
/// an environment snapshot, in the exact format the client lib
/// (`@icp-sdk/core/agent/canister-env`) parses:
///
/// ```text
/// ic_env=<url_encode(payload)>; Secure; SameSite=None; Partitioned
/// payload = "ic_root_key=<hex(DER root key)>" + ("&" + "<name>=<value>")*
/// ```
///
/// The root key always comes first; `public_vars` follow in sorted (BTreeMap)
/// order. `url_encode` percent-encodes the `&`/`=` separators so the whole
/// payload rides inside one cookie value; `decodeURIComponent` restores them
/// client-side. `SameSite=None; Secure; Partitioned` (CHIPS) so page scripts can
/// still read it when the app is shown inside a **cross-site iframe** — a plain
/// cross-site cookie would be dropped by the browser before the client lib runs.
/// (`ic_env` is read-only client state, never sent back to the canister, so
/// `SameSite=None` only affects whether the browser stores it, not any request.)
/// Pure (no system-API access) so it can be unit-tested directly.
pub fn render_env_cookie(root_key: &[u8], public_vars: &BTreeMap<String, String>) -> String {
    let mut entries = vec![format!("ic_root_key={}", hex::encode(root_key))];
    for (name, value) in public_vars {
        entries.push(format!("{name}={value}"));
    }
    let payload = entries.join("&");
    format!(
        "ic_env={}; Secure; SameSite=None; Partitioned",
        url_encode(&payload)
    )
}

/// Whether an asset's content-type denotes HTML — i.e. whether it should carry
/// the env cookie. Ignores any `; charset=…` parameter and is case-insensitive.
/// Keying off content-type (rather than the `.html` key suffix) is what lets the
/// `/` 200-rewrite alias inherit the cookie: `/` and `/index.html` serve the
/// same `text/html` meta, so both match uniformly.
pub fn is_html_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("text/html")
}

/// The canister-managed strong validator for an encoding: the content's
/// SHA-256 as a quoted hex string, per RFC 7232 §2.3. The canister owns the
/// `ETag` header outright — a custom `etag` in an asset's `_headers` is rejected
/// at sync time (see `sync-core`), so the certified header set always carries
/// exactly this value. That makes `If-None-Match` revalidation correct by
/// construction: the validator *is* the content hash the 304 logic compares
/// against.
pub fn etag_value(sha256: &[u8; 32]) -> String {
    format!("\"{}\"", hex::encode(sha256))
}

/// `effective_headers` with the canister-managed `etag` folded in. Any stray
/// `etag` is stripped first so exactly one — ours — ends up certified and on
/// the wire.
fn effective_headers_with_etag(
    effective_headers: &[(String, String)],
    sha256: &[u8; 32],
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = effective_headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("etag"))
        .cloned()
        .collect();
    headers.push(("etag".to_string(), etag_value(sha256)));
    headers
}

/// The certificate expression for an encoding, derived from the response's
/// effective headers and the encoding name. The certified header set is
/// `content-type` (implied by the expression template), plus `content-encoding`
/// for non-identity encodings, the effective headers, and the canister-managed
/// `etag` (see [`etag_value`]).
///
/// `effective_headers` is [`crate::state::State::effective_headers`]: the asset's
/// own `_headers`, plus the canister-injected `ic_env` `set-cookie` on
/// `text/html` responses. It is therefore **not** just the user's custom headers
/// — the env cookie is a certified header like any other.
pub fn certificate_expression_for(
    effective_headers: &[(String, String)],
    encoding: Encoding,
    sha256: &[u8; 32],
) -> CertificateExpression {
    let effective_headers = effective_headers_with_etag(effective_headers, sha256);
    build_ic_certificate_expression_from_headers_and_encoding(
        &effective_headers,
        encoding.header_name(),
    )
}

/// The full response header list for an encoding: `content-type`,
/// `content-encoding` (non-identity), the effective headers, the canister-managed
/// `etag`, and the `IC-CertificateExpression` header.
///
/// `effective_headers` (see [`certificate_expression_for`]) carries the asset's
/// `_headers` **and** the canister-injected `ic_env` `set-cookie` on `text/html`
/// responses, so the rendered list includes that cookie when present.
pub fn headers_for(
    effective_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
    sha256: &[u8; 32],
) -> Vec<(String, String)> {
    let cert_expr = certificate_expression_for(effective_headers, encoding, sha256);
    let effective_headers = effective_headers_with_etag(effective_headers, sha256);
    build_headers(
        effective_headers.iter().map(|(k, v)| (k, v)),
        content_type,
        encoding,
        Some(&cert_expr),
    )
}

/// The certified 200/304 response hashes for an encoding. `effective_headers`
/// (see [`certificate_expression_for`]) includes the `ic_env` `set-cookie` on
/// `text/html` responses, so that cookie is part of the certified hash.
pub fn response_hashes_for(
    effective_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
    cert_expr: &CertificateExpression,
    sha256: &[u8; 32],
) -> HashMap<u16, [u8; 32]> {
    let effective_headers = effective_headers_with_etag(effective_headers, sha256);
    let base_headers: Vec<(String, Value)> = build_headers(
        effective_headers.iter().map(|(k, v)| (k, v)),
        content_type,
        encoding,
        Some(cert_expr),
    )
    .into_iter()
    .map(|(k, v)| (k, Value::String(v)))
    .collect();

    // HTTP 200 carries the body; 304 carries an empty body.
    let ResponseHash(response_hash_200) = response_hash(&base_headers, 200, sha256);
    let empty_body_hash: [u8; 32] = sha2::Sha256::digest([]).into();
    let ResponseHash(response_hash_304) = response_hash(&base_headers, 304, &empty_body_hash);

    let mut response_hashes = HashMap::new();
    response_hashes.insert(200, response_hash_200);
    response_hashes.insert(304, response_hash_304);

    debug_assert!(STATUS_CODES_TO_CERTIFY
        .iter()
        .all(|code| response_hashes.contains_key(code)));

    response_hashes
}

// ---- Phase 0 spike: 206 range-response certification ----
//
// A 206's certified header set is the 200's set plus `content-range`. Only the
// `Content-Range` *value* varies per chunk (it lives in the response hash), so
// the CEL/expression is the same for every chunk of an encoding. Certification
// is response-only (`RequestHash::default()`), so an arbitrary client range can
// be snapped to the containing chunk at serve time. These three helpers are used
// by both the certify path (`recertify_asset`) and the serve path
// (`build_range_response`) so the two can never disagree.

/// The certificate expression for a 206 range response: the 200 certified header
/// set plus `content-range`.
pub(crate) fn range_certificate_expression_for(
    effective_headers: &[(String, String)],
    encoding: Encoding,
    sha256: &[u8; 32],
) -> CertificateExpression {
    let mut headers = effective_headers_with_etag(effective_headers, sha256);
    // The value is irrelevant to the expression (it lists header *names*).
    headers.push(("content-range".to_string(), String::new()));
    build_ic_certificate_expression_from_headers_and_encoding(&headers, encoding.header_name())
}

/// The full served header list for a 206 range response, including
/// `content-range` and the `ic-certificateexpression` header.
pub(crate) fn range_headers_for(
    effective_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
    sha256: &[u8; 32],
    content_range: &str,
) -> Vec<(String, String)> {
    let cert_expr = range_certificate_expression_for(effective_headers, encoding, sha256);
    let mut headers = effective_headers_with_etag(effective_headers, sha256);
    headers.push(("content-range".to_string(), content_range.to_string()));
    build_headers(
        headers.iter().map(|(k, v)| (k, v)),
        content_type,
        encoding,
        Some(&cert_expr),
    )
}

/// The certified response hash for one 206 range chunk.
pub(crate) fn range_response_hash(
    effective_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
    sha256: &[u8; 32],
    content_range: &str,
    chunk_body_hash: &[u8; 32],
) -> [u8; 32] {
    let base_headers: Vec<(String, Value)> = range_headers_for(
        effective_headers,
        content_type,
        encoding,
        sha256,
        content_range,
    )
    .into_iter()
    .map(|(k, v)| (k, Value::String(v)))
    .collect();
    response_hash(&base_headers, 206, chunk_body_hash).0
}

fn build_headers(
    effective_headers: impl Iterator<Item = (impl Into<String>, impl Into<String>)>,
    content_type: impl Into<String>,
    encoding: Encoding,
    cert_expr: Option<&CertificateExpression>,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> =
        vec![("content-type".to_string(), content_type.into())];
    // Identity carries no `Content-Encoding` header; every other encoding does.
    if let Some(name) = encoding.header_name() {
        headers.push(("content-encoding".to_string(), name.to_string()));
    }
    for (k, v) in effective_headers {
        headers.push((k.into().to_lowercase(), v.into()));
    }
    if let Some(expr) = cert_expr {
        let (k, v) = build_ic_certificate_expression_header(expr);
        headers.push((k, v));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::url_encode;

    #[test]
    fn url_encode_escapes_cookie_separators() {
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }
}
