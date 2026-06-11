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
use ic_representation_independent_hash::Value;
use sha2::Digest;
use std::collections::HashMap;
use wire_types::Encoding;

/// Status codes we certify for every asset encoding.
pub(crate) const STATUS_CODES_TO_CERTIFY: [u16; 2] = [200, 304];

/// The certificate expression for an encoding, derived from the asset's custom
/// headers and the encoding name. The certified header set is `content-type`
/// (implied by the expression template), plus `content-encoding` for
/// non-identity encodings, plus the custom headers.
pub(crate) fn certificate_expression_for(
    custom_headers: &[(String, String)],
    encoding: Encoding,
) -> CertificateExpression {
    build_ic_certificate_expression_from_headers_and_encoding(
        custom_headers,
        encoding.header_name(),
    )
}

/// The full response header list for an encoding: `content-type`,
/// `content-encoding` (non-identity), the custom headers, and the
/// `IC-CertificateExpression` header.
pub(crate) fn headers_for(
    custom_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
) -> Vec<(String, String)> {
    let cert_expr = certificate_expression_for(custom_headers, encoding);
    build_headers(
        custom_headers.iter().map(|(k, v)| (k, v)),
        content_type,
        encoding,
        Some(&cert_expr),
    )
}

/// The certified 200/304 response hashes for an encoding.
pub(crate) fn response_hashes_for(
    custom_headers: &[(String, String)],
    content_type: &str,
    encoding: Encoding,
    cert_expr: &CertificateExpression,
    sha256: &[u8; 32],
) -> HashMap<u16, [u8; 32]> {
    let base_headers: Vec<(String, Value)> = build_headers(
        custom_headers.iter().map(|(k, v)| (k, v)),
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
    custom_headers: impl Iterator<Item = (impl Into<String>, impl Into<String>)>,
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
    for (k, v) in custom_headers {
        headers.push((k.into().to_lowercase(), v.into()));
    }
    if let Some(expr) = cert_expr {
        let (k, v) = build_ic_certificate_expression_header(expr);
        headers.push((k, v));
    }
    headers
}
