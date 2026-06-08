//! Asset domain types and the helpers that maintain certified state for an
//! asset's responses.
//!
//! - [`Asset`] / [`AssetEncoding`] hold an asset and its per-encoding response
//!   metadata, including the per-encoding response hashes used for v2
//!   certification.
//! - [`EncodedAsset`], [`AssetDetails`], [`AssetEncodingDetails`] are the
//!   Candid surface types used by `get` / `list`.
//! - [`on_asset_change`] is the central re-certification routine: every State
//!   method that mutates an asset funnels through it.
//! - [`encoding_certification_order`] is a small encoding utility shared
//!   between the state machine and the asset itself.

use crate::certification::{
    build_ic_certificate_expression_from_headers_and_encoding,
    build_ic_certificate_expression_header, response_hash, AssetKey, AssetPath,
    CertificateExpression, CertifiedResponses, HashTreePath, RequestHash, ResponseHash,
};
use crate::http::{
    CallbackFunc, HeaderField, HttpResponse, StreamingCallbackToken, StreamingStrategy,
};
use crate::rc_bytes::RcBytes;
use candid::{CandidType, Deserialize, Int, Nat};
use ic_certification::Hash;
use ic_representation_independent_hash::Value;
use serde_bytes::ByteBuf;
use sha2::Digest;
use std::collections::HashMap;

/// The preferred order in which we pick encodings.
const ENCODING_CERTIFICATION_ORDER: &[&str] = &["identity", "gzip", "compress", "deflate", "br"];
// All encodings get certified; this function returns them in preference order
// (preferred names first, then any remaining encodings in iteration order).
pub fn encoding_certification_order<'a>(
    actual_encodings: impl Iterator<Item = &'a String>,
) -> Vec<String> {
    let mut encoding_order: Vec<String> = ENCODING_CERTIFICATION_ORDER
        .iter()
        .map(|enc| enc.to_string())
        .collect();
    encoding_order.append(
        &mut actual_encodings
            .filter(|encoding| !ENCODING_CERTIFICATION_ORDER.contains(&encoding.as_str()))
            .map(|s| s.into())
            .collect(),
    );
    encoding_order
}

const STATUS_CODES_TO_CERTIFY: [u16; 2] = [200, 304];

pub(crate) type Timestamp = Int;

#[derive(Default, Clone, Debug)]
pub struct AssetEncoding {
    pub modified: Timestamp,
    pub content_chunks: Vec<RcBytes>,
    pub total_length: usize,
    pub certified: bool,
    pub sha256: [u8; 32],
    pub certificate_expression: Option<CertificateExpression>,
    pub response_hashes: Option<HashMap<u16, [u8; 32]>>,
}

impl AssetEncoding {
    fn asset_hash_path(&self, path: &AssetPath, status_code: u16) -> Option<HashTreePath> {
        self.certificate_expression.as_ref().and_then(|ce| {
            self.response_hashes.as_ref().and_then(|hashes| {
                hashes.get(&status_code).map(|response_hash| {
                    path.hash_tree_path(ce, &RequestHash::default(), response_hash.into())
                })
            })
        })
    }

    fn compute_response_hashes(
        &self,
        headers: &Option<Vec<(String, String)>>,
        content_type: &str,
        encoding_name: &str,
    ) -> HashMap<u16, [u8; 32]> {
        // Collect all user-defined headers
        let base_headers: Vec<(String, Value)> = build_headers(
            headers.as_ref().map(|h| h.iter().map(|(k, v)| (k, v))),
            content_type,
            encoding_name,
            self.certificate_expression.as_ref(),
        )
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();

        // HTTP 200
        let ResponseHash(response_hash_200) = response_hash(&base_headers, 200, &self.sha256);

        // HTTP 304
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
}

#[derive(Default, Clone, Debug)]
pub struct Asset {
    pub content_type: String,
    pub encodings: HashMap<String, AssetEncoding>,
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct EncodedAsset {
    pub content: RcBytes,
    pub content_type: String,
    pub content_encoding: String,
    pub total_length: Nat,
    pub sha256: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub content_type: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<ByteBuf>,
    pub length: Nat,
    pub modified: Timestamp,
}

impl Asset {
    fn update_ic_certificate_expressions(&mut self) {
        // gather all headers
        let mut headers: Vec<(String, Value)> = vec![];

        if let Some(custom_headers) = &self.headers {
            for (k, v) in custom_headers.iter() {
                headers.push((k.clone(), Value::String(v.clone())));
            }
        }

        // update
        for (enc_name, encoding) in self.encodings.iter_mut() {
            encoding.certificate_expression = Some(
                build_ic_certificate_expression_from_headers_and_encoding(&headers, Some(enc_name)),
            );
        }
    }

    pub fn get_headers_for_asset(&self, encoding_name: &str) -> Vec<(String, String)> {
        let ce = self
            .encodings
            .get(encoding_name)
            .and_then(|e| e.certificate_expression.as_ref());
        build_headers(
            self.headers.as_ref().map(|h| h.iter().map(|(k, v)| (k, v))),
            &self.content_type,
            encoding_name.to_owned(),
            ce,
        )
    }

    /// Builds the response for one encoding.
    ///
    /// When `status_override` is `None` this serves the normal 200/304 path
    /// (etag-based not-modified). When it is `Some(s)` — used by redirect
    /// rules that serve a custom error page — the response always carries
    /// the body with status `s`, and the etag / 304 logic is skipped.
    #[allow(clippy::too_many_arguments)]
    pub fn build_ok_http_response(
        &self,
        enc_name: &str,
        enc: &AssetEncoding,
        key: &str,
        chunk_index: usize,
        certificate_header: Option<&HeaderField>,
        callback: &CallbackFunc,
        etags: &[Hash],
        status_override: Option<u16>,
    ) -> HttpResponse {
        let mut headers = self.get_headers_for_asset(enc_name);
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }

        let streaming_strategy = StreamingCallbackToken::create_token(
            enc_name,
            enc.content_chunks.len(),
            enc.sha256,
            key,
            chunk_index,
        )
        .map(|token| StreamingStrategy::Callback {
            callback: callback.clone(),
            token,
        });

        let (status_code, body) = if let Some(status) = status_override {
            (status, enc.content_chunks[chunk_index].clone())
        } else if etags.contains(&enc.sha256) {
            (304, RcBytes::default())
        } else {
            if !headers
                .iter()
                .any(|(header_name, _)| header_name.eq_ignore_ascii_case("etag"))
            {
                headers.push((
                    "etag".to_string(),
                    format!("\"{}\"", hex::encode(enc.sha256)),
                ));
            }
            (200, enc.content_chunks[chunk_index].clone())
        };

        HttpResponse {
            status_code,
            headers,
            body,
            upgrade: None,
            streaming_strategy,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_http_response_for_encodings(
        &self,
        requested_encodings: &[String],
        key: &str,
        chunk_index: usize,
        certificate_header: Option<&HeaderField>,
        callback: &CallbackFunc,
        etags: &[Hash],
        status_override: Option<u16>,
    ) -> Option<HttpResponse> {
        // Return a requested encoding that is certified
        for enc_name in requested_encodings.iter() {
            if let Some(enc) = self.encodings.get(enc_name) {
                if enc.certified {
                    return Some(self.build_ok_http_response(
                        enc_name,
                        enc,
                        key,
                        chunk_index,
                        certificate_header,
                        callback,
                        etags,
                        status_override,
                    ));
                }
            }
        }

        // None of the requested encodings are available - fall back to the best certified encoding we have
        for enc_name in encoding_certification_order(self.encodings.keys()) {
            if let Some(enc) = self.encodings.get(&enc_name) {
                if enc.certified {
                    return Some(self.build_ok_http_response(
                        &enc_name,
                        enc,
                        key,
                        chunk_index,
                        certificate_header,
                        callback,
                        etags,
                        status_override,
                    ));
                }
            }
        }
        None
    }
}

fn build_headers(
    custom_headers: Option<impl Iterator<Item = (impl Into<String>, impl Into<String>)>>,
    content_type: impl Into<String>,
    encoding_name: impl Into<String>,
    cert_expr: Option<&CertificateExpression>,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> =
        vec![("content-type".to_string(), content_type.into())];
    let encoding_name = encoding_name.into();
    if encoding_name != "identity" {
        headers.push(("content-encoding".to_string(), encoding_name));
    }
    if let Some(arg_headers) = custom_headers {
        for (k, v) in arg_headers {
            headers.push((k.into().to_lowercase(), v.into()));
        }
    }
    if let Some(expr) = cert_expr {
        let (k, v) = build_ic_certificate_expression_header(expr);
        headers.push((k, v));
    }
    headers
}

pub(crate) fn on_asset_change(
    asset_hashes: &mut CertifiedResponses,
    key: &str,
    asset: &mut Asset,
    dependent_keys: Vec<AssetKey>,
) {
    let mut affected_keys = dependent_keys;
    affected_keys.push(key.to_string());

    delete_preexisting_asset_hashes(asset_hashes, &affected_keys);

    if asset.encodings.is_empty() {
        return;
    }

    for enc in asset.encodings.values_mut() {
        enc.certified = false;
    }

    asset.update_ic_certificate_expressions();

    let Asset {
        content_type,
        encodings,
        headers,
        ..
    } = asset;

    // Insert certified response values into hash_tree
    for (enc_name, enc) in encodings.iter_mut() {
        enc.response_hashes = Some(enc.compute_response_hashes(headers, content_type, enc_name));

        insert_new_response_hashes_for_encoding(asset_hashes, enc, &affected_keys);
        enc.certified = true;
    }
}

fn delete_preexisting_asset_hashes(
    asset_hashes: &mut CertifiedResponses,
    affected_keys: &[String],
) {
    for key in affected_keys.iter() {
        asset_hashes.remove_responses_for_path(key);
    }
}

fn insert_new_response_hashes_for_encoding(
    asset_hashes: &mut CertifiedResponses,
    enc: &AssetEncoding,
    affected_keys: &Vec<String>,
) {
    for key in affected_keys {
        let key_path = AssetPath::from(&key);
        for status_code in STATUS_CODES_TO_CERTIFY {
            if let Some(hash_path) = enc.asset_hash_path(&key_path, status_code) {
                asset_hashes.certify_response_precomputed(&hash_path);
            } else {
                unreachable!(
                    "Could not create a hash path for a status code {} and key {} - did you forget to compute a response hash for this status code?",
                    status_code, &key
                );
            }
        }
    }
}
