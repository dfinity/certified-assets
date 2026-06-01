//! Certification primitives and the in-memory certified-response tree.
//!
//! This module defines:
//! - The path/hash types used to address entries in the certified-responses tree
//!   (`AssetPath`, `HashTreePath`, `NestedTreeKey`, `RequestHash`, `ResponseHash`,
//!   `CertificateExpression`).
//! - The helpers that compute response hashes and build certificate expressions.
//! - [`CertifiedResponses`], the in-memory tree of certified responses, and its
//!   operations.

use crate::nested_tree::NestedTree;
use crate::rc_bytes::RcBytes;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use candid::CandidType;
use ic_certification::merge_hash_trees;
pub use ic_certification::HashTree;
use ic_representation_independent_hash::{representation_independent_hash, Value};
use serde::{Deserialize, Serialize};
use serde_cbor::ser::IoWrite;
use serde_cbor::Serializer;
use sha2::Digest;
use std::borrow::Borrow;

pub type AssetKey = String;

pub const IC_CERTIFICATE_EXPRESSION_VALUE: &str = r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type"{headers}]}}}})"#;

#[derive(Default, Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct CertificateExpression {
    pub expression: String,
    pub expression_hash: [u8; 32],
}

#[derive(Clone, Debug, CandidType, Deserialize, Default)]
pub struct RequestHash(Option<[u8; 32]>);

#[derive(Default, Clone, Copy, Debug, CandidType, Deserialize)]
pub struct ResponseHash(pub [u8; 32]);

impl<T> From<T> for ResponseHash
where
    T: Borrow<[u8; 32]>,
{
    fn from(hash: T) -> Self {
        ResponseHash(*hash.borrow())
    }
}

/// AssetKey that has been split into segments.
/// E.g. `["foo", "index.html"]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetPath(pub Vec<AssetKey>);

impl<T> From<T> for AssetPath
where
    T: AsRef<str>,
{
    fn from(key: T) -> Self {
        let mut iter = key.as_ref().split('/').peekable();
        if let Some(first_segment) = iter.peek() {
            // "/path/to/asset".split("/") produces an empty node before "path", therefore we need to skip it
            if first_segment.is_empty() {
                iter.next();
            }
        }
        Self(iter.map(|segment| segment.to_string()).collect())
    }
}

impl AssetPath {
    pub fn reconstruct_asset_key(&self) -> AssetKey {
        // this reconstructs "" as "/", but this is not a problem because no http client actually requests ""
        format!("/{}", self.0.join("/"))
    }

    pub fn asset_hash_path_root(&self) -> HashTreePath {
        let mut hash_path: Vec<NestedTreeKey> = self
            .0
            .iter()
            .map(|segment| segment.as_str().into())
            .collect();
        hash_path.push("<$>".into());
        hash_path.insert(0, "http_expr".into());
        HashTreePath(hash_path)
    }

    pub fn hash_tree_path(
        &self,
        certificate_expression: &CertificateExpression,
        RequestHash(maybe_request_hash): &RequestHash,
        ResponseHash(response_hash): ResponseHash,
    ) -> HashTreePath {
        let mut hash_path: Vec<NestedTreeKey> = vec![];
        if matches!(self.0.last(), Some(segment) if segment == "<*>") {
            // it's a fallback path
            hash_path.push("http_expr".into());
            hash_path.push("<*>".into());
        } else {
            hash_path.push("http_expr".into());
            hash_path = self.0.iter().fold(hash_path, |mut path, s| {
                path.push(s.as_str().into());
                path
            });
            hash_path.push("<$>".into()); // asset path terminator
        };
        hash_path.push(certificate_expression.expression_hash.into());
        hash_path.push(
            maybe_request_hash
                .map(|request_hash| request_hash.into())
                .unwrap_or_else(|| "".into()),
        );
        hash_path.push(NestedTreeKey::Hash(response_hash));
        HashTreePath(hash_path)
    }

    pub fn fallback_path() -> Self {
        Self(vec!["http_expr".into(), "<*>".into()])
    }
}

/// AssetPath that is ready to be inserted into asset_hashes.
/// E.g. `["http_expr", "foo", "index.html", "<$>", "<expr_hash>", "<request hash>", "<response_hash>"]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashTreePath(pub Vec<NestedTreeKey>);

impl From<Vec<NestedTreeKey>> for HashTreePath {
    fn from(vec: Vec<NestedTreeKey>) -> Self {
        Self(vec)
    }
}

impl HashTreePath {
    pub fn as_vec(&self) -> &Vec<NestedTreeKey> {
        &self.0
    }

    pub fn expr_path(&self) -> String {
        let strings = self
            .0
            .iter()
            .map(|key| match key {
                NestedTreeKey::String(k) => k.clone(),
                NestedTreeKey::Bytes(b) => hex::encode(b),
                NestedTreeKey::Hash(h) => hex::encode(h),
            })
            .collect::<Vec<String>>();
        let cbor = serialize_cbor_self_describing(&strings);
        BASE64.encode(cbor)
    }

    /// Produces all `HashTreePath`s required to prove
    /// - whether or not fallback file exists and
    /// - that there is no fallback file with higher priority
    ///
    /// in the hash tree.
    pub fn fallback_paths(&self) -> Vec<Self> {
        let mut paths = Vec::new();

        // starting at 1 because "http_expr" is always the starting element
        for i in 1..self.0.len() {
            let mut without_trailing_slash: Vec<NestedTreeKey> = self.0.as_slice()[0..i].into();
            let mut with_trailing_slash = without_trailing_slash.clone();
            without_trailing_slash.push("<*>".into());
            with_trailing_slash.push("".into());
            with_trailing_slash.push("<*>".into());

            paths.push(without_trailing_slash.into());
            paths.push(with_trailing_slash.into());
        }

        paths
    }

    pub fn new(
        asset: &str,
        status_code: u16,
        headers: &[(String, Value)],
        body: &RcBytes,
        body_hash: Option<[u8; 32]>,
    ) -> Self {
        Self::from_parts(asset, status_code, headers, body, body_hash, None, None)
    }

    pub fn from_parts(
        path: &str,
        status_code: u16,
        headers: &[(String, Value)],
        body: &[u8],
        body_hash: Option<[u8; 32]>,
        certificate_expression: Option<&CertificateExpression>,
        response_hash_value: Option<ResponseHash>,
    ) -> Self {
        let certificate_expression = certificate_expression
            .cloned()
            .unwrap_or_else(|| build_ic_certificate_expression_from_headers(headers));
        let request_hash = RequestHash::default(); // request certification currently not supported
        let body_hash = body_hash.unwrap_or_else(|| sha2::Sha256::digest(body).into());
        let resolved_response_hash =
            response_hash_value.unwrap_or_else(|| response_hash(headers, status_code, &body_hash));

        AssetPath::from(path).hash_tree_path(
            &certificate_expression,
            &request_hash,
            resolved_response_hash,
        )
    }

    pub fn not_found_base_path() -> Self {
        HashTreePath::from(Vec::from([
            NestedTreeKey::String("http_expr".into()),
            NestedTreeKey::String("<*>".into()),
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedTreeKey {
    String(String),
    Bytes(Vec<u8>),
    Hash([u8; 32]),
}

impl AsRef<[u8]> for NestedTreeKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            NestedTreeKey::String(s) => s.as_bytes(),
            NestedTreeKey::Bytes(b) => b.as_slice(),
            NestedTreeKey::Hash(h) => h,
        }
    }
}

impl From<&str> for NestedTreeKey {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}

impl From<&[u8]> for NestedTreeKey {
    fn from(slice: &[u8]) -> Self {
        Self::Bytes(slice.to_vec())
    }
}

impl From<[u8; 32]> for NestedTreeKey {
    fn from(hash: [u8; 32]) -> Self {
        Self::Hash(hash)
    }
}

impl From<String> for NestedTreeKey {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

fn serialize_cbor_self_describing<T>(value: &T) -> Vec<u8>
where
    T: serde::Serialize,
{
    let mut vec = Vec::new();
    let mut binding = IoWrite::new(&mut vec);
    let mut s = Serializer::new(&mut binding);
    s.self_describe()
        .expect("Cannot produce self-describing cbor.");
    value
        .serialize(&mut s)
        .expect("Failed to serialize self-describing CBOR.");
    vec
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessResult {
    PathFound,
    FallbackFound,
    NoneFound,
}

pub fn response_hash(
    certified_headers: &[(String, Value)],
    status_code: u16,
    body_hash: &[u8; 32],
) -> ResponseHash {
    // certification v2 spec:
    // Response hash is the hash of the concatenation of
    //   - representation-independent hash of headers
    //   - hash of the response body
    //
    // The representation-independent hash of headers consist of
    //    - all certified headers (here all headers), plus
    //    - synthetic header `:ic-cert-status` with value <HTTP status code of response>

    let mut headers = Vec::from(certified_headers);
    headers.push((
        ":ic-cert-status".to_string(),
        Value::Number(status_code.into()),
    ));
    let header_hash = representation_independent_hash(&headers);
    let hash: [u8; 32] = sha2::Sha256::digest([header_hash.as_ref(), body_hash].concat()).into();
    ResponseHash(hash)
}

pub fn build_ic_certificate_expression_from_headers_and_encoding<T>(
    headers: &[(String, T)],
    encoding_name: Option<&str>,
) -> CertificateExpression {
    let mut headers = headers
        .iter()
        .map(|(h, _)| format!(", \"{h}\""))
        .collect::<Vec<_>>()
        .join("");
    if let Some(encoding) = encoding_name {
        if encoding != "identity" {
            headers = format!(", \"content-encoding\"{headers}");
        }
    }

    let expression = IC_CERTIFICATE_EXPRESSION_VALUE.replace("{headers}", &headers);
    let hash: [u8; 32] = sha2::Sha256::digest(expression.as_bytes()).into();
    CertificateExpression {
        expression,
        expression_hash: hash,
    }
}

pub fn build_ic_certificate_expression_from_headers<T>(
    headers: &[(String, T)],
) -> CertificateExpression {
    let headers = headers
        .iter()
        .map(|(h, _)| format!(", \"{h}\""))
        .collect::<Vec<_>>()
        .join("");

    let expression = IC_CERTIFICATE_EXPRESSION_VALUE.replace("{headers}", &headers);
    let hash: [u8; 32] = sha2::Sha256::digest(expression.as_bytes()).into();
    CertificateExpression {
        expression,
        expression_hash: hash,
    }
}

pub fn build_ic_certificate_expression_header(
    certificate_expression: &CertificateExpression,
) -> (String, String) {
    (
        "ic-certificateexpression".to_string(),
        certificate_expression.expression.clone(),
    )
}

pub type CertifiedResponses = NestedTree<NestedTreeKey, Vec<u8>>;

impl CertifiedResponses {
    /// Certifies a response for a number of paths.
    ///
    /// # Arguments
    /// * `paths`: path(s) to the resource
    /// * `status_code`: HTTP status code of the response
    /// * `headers`: All certified headers. It is possible to respond with additional headers, but only the ones supplied in this argument are certified
    /// * `body`: Response body. Ignored if `body_hash.is_some()`
    /// * `body_hash`: Hash of the response body. If supplied the response body will not be hashed, which can save a lot of computation
    ///
    /// # Return Value
    /// * `Vec<HashTreePath>`: `HashTreePath`s corresponding to the supplied `paths`. Can be used to remove or re-insert certification for a specific response without having to re-compute the full path
    pub fn certify_response(
        &mut self,
        paths: &[&str],
        status_code: u16,
        headers: &[(String, Value)],
        body: &[u8],
        body_hash: Option<[u8; 32]>,
    ) -> Vec<HashTreePath> {
        let certificate_expression = build_ic_certificate_expression_from_headers(headers);
        let request_hash = RequestHash::default(); // request certification currently not supported
        let body_hash = body_hash.unwrap_or_else(|| sha2::Sha256::digest(body).into());
        let response_hash = response_hash(headers, status_code, &body_hash);

        paths
            .iter()
            .map(|path| {
                let asset_path = AssetPath::from(path);
                let hash_tree_path = asset_path.hash_tree_path(
                    &certificate_expression,
                    &request_hash,
                    response_hash,
                );
                self.certify_response_precomputed(&hash_tree_path);
                hash_tree_path
            })
            .collect()
    }

    /// Certifies a response that can be used if no certified response is available for the requested path.
    ///
    /// # Arguments
    /// * `status_code`: HTTP status code of the response
    /// * `headers`: All certified headers. It is possible to respond with additional headers, but only the ones supplied in this argument are certified
    /// * `body`: Response body. Ignored if `body_hash.is_some()`
    /// * `body_hash`: Hash of the response body. If supplied the response body will not be hashed, which can save a lot of computation
    ///
    /// # Return Value
    /// * `HashTreePath`: `HashTreePath` corresponding to the supplied response. Can be used to remove or re-insert certification for this specific response without having to re-compute the full path
    pub fn certify_fallback_response(
        &mut self,
        status_code: u16,
        headers: &[(String, Value)],
        body: &[u8],
        body_hash: Option<[u8; 32]>,
    ) -> HashTreePath {
        let certificate_expression = build_ic_certificate_expression_from_headers(headers);
        let cert_expr_header = build_ic_certificate_expression_header(&certificate_expression);
        let cert_expr_header = (cert_expr_header.0, Value::String(cert_expr_header.1));
        let mut certified_headers = Vec::from(headers);
        certified_headers.push(cert_expr_header);
        let request_hash = RequestHash::default(); // request certification currently not supported
        let body_hash = body_hash.unwrap_or_else(|| sha2::Sha256::digest(body).into());
        let response_hash = response_hash(&certified_headers, status_code, &body_hash);

        let asset_path = AssetPath::fallback_path();
        let hash_tree_path =
            asset_path.hash_tree_path(&certificate_expression, &request_hash, response_hash);
        self.certify_response_precomputed(&hash_tree_path);
        hash_tree_path
    }

    /// Certifies a response. Expects a finished `HashTreePath`, skipping the (sometimes expensive) computation of the `HashTreePath`.
    pub fn certify_response_precomputed(&mut self, path: &HashTreePath) {
        self.insert(path.as_vec(), Vec::new());
    }

    /// Removes all certified responses for a path.
    pub fn remove_responses_for_path(&mut self, path: &str) {
        let key = AssetPath::from(path);
        self.delete(key.asset_hash_path_root().as_vec());
    }

    /// Removes all certified fallback responses.
    pub fn remove_fallback_responses(&mut self) {
        self.delete(HashTreePath::not_found_base_path().as_vec());
    }

    /// Removes a specific response from the certified responses. Expects a finished `HashTreePath`, skipping the (sometimes expensive) computation of the `HashTreePath`.
    pub fn remove_response_precomputed(&mut self, path: &HashTreePath) {
        self.delete(path.as_vec());
    }

    /// If the path has certified responses this function creates a hash tree that proves...
    /// * The path is part of the CertifiedResponses hash tree
    ///
    /// The hash tree then includes certification for all valid responses for this path.
    ///
    /// If the path has no certified responses this function creates a hash tree that proves...
    /// * The absence of the path in the CertifiedResponses hash tree
    /// * The presence/absence of a 404 response
    ///
    /// The hash tree then includes certification for all valid responses for a 404 response.
    ///
    /// # Return Value
    /// `(found, tree)`
    /// * `found`:
    ///   * WitnessResult::Found if `path` has a certified response.
    ///   * `WitnessResult::FallbackFound` if the path has no certified response, but the fallback path has.
    ///   * `WitnessResult::NoneFound` if both `path` and the fallback path have no certified response.
    /// * `tree`: The `HashTree` as described above.
    pub fn witness_path(&self, path: &str) -> (HashTree, WitnessResult) {
        let path = AssetPath::from(path);
        let hash_tree_path_root = path.asset_hash_path_root();
        if self.contains_path(hash_tree_path_root.as_vec()) {
            (
                self.witness(hash_tree_path_root.as_vec()),
                WitnessResult::PathFound,
            )
        } else {
            let absence_proof = self.witness(hash_tree_path_root.as_vec());
            let fallback_paths = hash_tree_path_root.fallback_paths();

            let combined_proof =
                fallback_paths
                    .into_iter()
                    .fold(absence_proof, |accumulator, path| {
                        let new_proof = self.witness(path.as_vec());
                        merge_hash_trees(accumulator, new_proof)
                    });

            let fallback_path = HashTreePath::not_found_base_path();
            if self.contains_path(fallback_path.as_vec()) {
                (combined_proof, WitnessResult::FallbackFound)
            } else {
                (combined_proof, WitnessResult::NoneFound)
            }
        }
    }

    pub fn expr_path(&self, path: &str) -> String {
        let path = AssetPath::from(path);
        let hash_tree_path_root = path.asset_hash_path_root();
        if self.contains_path(hash_tree_path_root.as_vec()) {
            path.asset_hash_path_root().expr_path()
        } else {
            HashTreePath::not_found_base_path().expr_path()
        }
    }

    /// Same as `witness_path`, but produces a header that can be returned as a `HttpResponse` header instead of a witness `HashTree`.
    pub fn witness_to_header(
        &self,
        path: &str,
        certificate: &[u8],
    ) -> ((String, String), WitnessResult) {
        let (witness, witness_result) = self.witness_path(path);
        let expr_path = self.expr_path(path);

        let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
        serializer.self_describe().unwrap();
        witness.serialize(&mut serializer).unwrap();

        (
            (
                "IC-Certificate".to_string(),
                String::from("version=2, ")
                    + "certificate=:"
                    + &BASE64.encode(certificate)
                    + ":, tree=:"
                    + &BASE64.encode(serializer.into_inner())
                    + ":, expr_path=:"
                    + &expr_path
                    + ":",
            ),
            witness_result,
        )
    }
}
