//! Pure helpers that derive an asset encoding's certified-response data.
//!
//! Asset metadata and content now live in stable memory (see
//! [`crate::stable_store`]); the certificate expression and response hashes are
//! **not** stored — they are recomputed on demand from the persisted metadata.
//! These functions take plain data (custom headers, content type, encoding
//! name, sha256) so the same logic runs both when an encoding is written and
//! when the certified-response tree is rebuilt after an upgrade. Response
//! building itself lives on [`crate::state::State`], which owns the chunk store.

use crate::certification::{
    build_ic_certificate_expression_from_headers_and_encoding,
    build_ic_certificate_expression_header, response_hash, CertificateExpression, ResponseHash,
};
use crate::url::url_encode;
use ic_representation_independent_hash::Value;
use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use wire_types::Encoding;

/// Status codes we certify for every asset encoding.
pub const STATUS_CODES_TO_CERTIFY: [u16; 2] = [200, 304];

/// Renders the value of the canister-injected `Set-Cookie: ic_env=…` header from
/// an environment snapshot, in the exact format the client lib
/// (`@icp-sdk/core/agent/canister-env`) parses:
///
/// ```text
/// ic_env=<url_encode(payload)>; SameSite=Lax
/// payload = "ic_root_key=<hex(DER root key)>" + ("&" + "<name>=<value>")*
/// ```
///
/// The root key always comes first; `public_vars` follow in sorted (BTreeMap)
/// order. `url_encode` percent-encodes the `&`/`=` separators so the whole
/// payload rides inside one cookie value; `decodeURIComponent` restores them
/// client-side. Pure (no system-API access) so it can be unit-tested directly.
pub fn render_env_cookie(root_key: &[u8], public_vars: &BTreeMap<String, String>) -> String {
    let mut entries = vec![format!("ic_root_key={}", hex::encode(root_key))];
    for (name, value) in public_vars {
        entries.push(format!("{name}={value}"));
    }
    let payload = entries.join("&");
    format!("ic_env={}; SameSite=Lax", url_encode(&payload))
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

/// The certificate expression for an encoding, derived from the response's
/// effective headers and the encoding name. The certified header set is
/// `content-type` (implied by the expression template), plus `content-encoding`
/// for non-identity encodings, plus the effective headers.
///
/// `effective_headers` is [`crate::state::State::effective_headers`]: the asset's
/// own `_headers`, plus the canister-injected `ic_env` `set-cookie` on
/// `text/html` responses. It is therefore **not** just the user's custom headers
/// — the env cookie is a certified header like any other.
pub fn certificate_expression_for(
    effective_headers: &[(String, String)],
    encoding: Encoding,
) -> CertificateExpression {
    build_ic_certificate_expression_from_headers_and_encoding(
        effective_headers,
        encoding.header_name(),
    )
}

/// The full response header list for an encoding: `content-type`,
/// `content-encoding` (non-identity), the effective headers, and the
/// `IC-CertificateExpression` header.
///
/// `effective_headers` (see [`certificate_expression_for`]) carries the asset's
/// `_headers` **and** the canister-injected `ic_env` `set-cookie` on `text/html`
/// responses, so the rendered list includes that cookie when present.
pub fn headers_for(
    effective_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
) -> Vec<(String, String)> {
    let cert_expr = certificate_expression_for(effective_headers, encoding);
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
