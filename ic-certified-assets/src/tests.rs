use crate::batch::{ComputationStatus, BATCH_EXPIRY_NANOS};
use crate::http::{
    CallbackFunc, HttpRequest, HttpResponse, StreamingCallbackToken, StreamingStrategy,
};
use crate::stable::StableState;
use crate::state::State;
use crate::system_context::{CanisterEnv, SystemContext};
use crate::types::{
    AssetProperties, BatchId, BatchOperation, CommitBatchArguments, CreateAssetArguments,
    DeleteAssetArguments, DeleteBatchArguments, GetArg, GetChunkArg, ListRequest,
    SetAssetContentArguments, SetAssetPropertiesArguments,
};
use crate::url::{url_decode, url_encode, UrlDecodeError};
use crate::CreateChunksArg;
use candid::{Nat, Principal};
use ic_certification_testing::CertificateBuilder;
use ic_crypto_tree_hash::Digest;
use ic_http_certification::{Method, StatusCode};
use ic_response_verification_test_utils::{
    base64_encode, create_canister_id, get_current_timestamp,
};
use serde_bytes::ByteBuf;
use sha2::Digest as Sha2Digest;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

// from ic-response-verification tests
const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

/// The empty canister env value serialized as a cookie value
const DEFAULT_IC_ENV_COOKIE_VALUE: &str = "ic_env=ic%5Froot%5Fkey%3D; SameSite=Lax";

fn some_principal() -> Principal {
    Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap()
}

fn unused_callback() -> CallbackFunc {
    CallbackFunc::new(some_principal(), "unused".to_string())
}

fn mock_system_context() -> SystemContext {
    SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: vec![],
            icp_public_env_vars: BTreeMap::new(),
        }),
        100_000_000_000,
    )
}

/// Synchronous test driver for incremental computations.
/// Loops calling a state machine function until completion.
/// Unlike the async version, this doesn't check instruction counters or make async calls.
fn run_computation_until_completion<F, D, P, E>(mut compute_fn: F) -> Result<D, E>
where
    F: FnMut(P) -> ComputationStatus<D, P, E>,
    P: Default,
{
    let mut progress = P::default();

    loop {
        match compute_fn(progress) {
            ComputationStatus::Done(done) => return Ok(done),
            ComputationStatus::InProgress(p) => {
                progress = p;
            }
            ComputationStatus::Error(e) => return Err(e),
        }
    }
}

pub fn verify_response(
    state: &State,
    request: &HttpRequest,
    response: &HttpResponse,
) -> anyhow::Result<bool> {
    let mut response = response.clone();
    let current_time = get_current_timestamp();
    let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
    let min_requested_verification_version: u16 = 2;

    // inject certificate into IC-Certificate header with 'certificate=::'
    let data = CertificateBuilder::new(
        &canister_id.to_string(),
        Digest(state.root_hash()).as_bytes(),
    )?
    .with_time(current_time)
    .build()?;
    let replacement_cert_value = base64_encode(&data.cbor_encoded_certificate);
    let (_, header_value) = response
        .headers
        .iter_mut()
        .find(|(header, _)| header == "IC-Certificate")
        .expect("HttpResponse is missing 'IC-Certificate' header");
    *header_value = header_value.replace(
        "certificate=::",
        &format!("certificate=:{replacement_cert_value}:"),
    );

    // actual verification
    let request = ic_http_certification::http::HttpRequest::builder()
        .with_method(Method::from_str(&request.method).unwrap())
        .with_url(&request.url)
        .with_headers(request.headers.clone())
        .with_body(request.body.as_slice())
        .build();
    let response = ic_http_certification::http::HttpResponse::builder()
        .with_status_code(StatusCode::from_u16(response.status_code).unwrap())
        .with_headers(response.headers)
        .with_body(&response.body[..])
        .with_upgrade(false)
        .build();
    Ok(ic_response_verification::verify_request_response_pair(
        request,
        response,
        canister_id.as_ref(),
        current_time,
        MAX_CERT_TIME_OFFSET_NS,
        &data.root_key,
        min_requested_verification_version.try_into().unwrap(),
    )
    .map(|res| res.response.is_some())?)
}

fn certified_http_request(state: &State, request: HttpRequest) -> HttpResponse {
    let response = state.http_request(request.clone(), &[], unused_callback());
    match verify_response(state, &request, &response) {
        Err(err) => {
            panic!("Response verification failed with error {err:?}. Response: {response:#?}")
        }
        Ok(success) => {
            if !success {
                panic!("Response verification failed. Response: {response:?}")
            }
        }
    }
    response
}

struct AssetBuilder {
    name: String,
    content_type: String,
    encodings: Vec<(String, Vec<ByteBuf>)>,
    max_age: Option<u64>,
    headers: Option<BTreeMap<String, String>>,
    aliasing: Option<bool>,
    allow_raw_access: Option<bool>,
}

impl AssetBuilder {
    fn new(name: impl AsRef<str>, content_type: impl AsRef<str>) -> Self {
        Self {
            name: name.as_ref().to_string(),
            content_type: content_type.as_ref().to_string(),
            encodings: vec![],
            max_age: None,
            headers: None,
            aliasing: None,
            allow_raw_access: None,
        }
    }

    fn with_max_age(mut self, max_age: u64) -> Self {
        self.max_age = Some(max_age);
        self
    }

    fn with_encoding(mut self, name: impl AsRef<str>, chunks: Vec<impl AsRef<[u8]>>) -> Self {
        self.encodings.push((
            name.as_ref().to_string(),
            chunks
                .into_iter()
                .map(|c| ByteBuf::from(c.as_ref().to_vec()))
                .collect(),
        ));
        self
    }

    fn with_header(mut self, header_key: &str, header_value: &str) -> Self {
        let hm = self.headers.get_or_insert(BTreeMap::new());
        hm.insert(header_key.to_string(), header_value.to_string());
        self
    }

    fn with_aliasing(mut self, aliasing: bool) -> Self {
        self.aliasing = Some(aliasing);
        self
    }

    fn with_allow_raw_access(mut self, allow_raw_access: Option<bool>) -> Self {
        self.allow_raw_access = allow_raw_access;
        self
    }
}

struct RequestBuilder {
    resource: String,
    method: String,
    headers: Vec<(String, String)>,
    body: ByteBuf,
    certificate_version: Option<u16>,
}

impl RequestBuilder {
    fn get(resource: impl AsRef<str>) -> Self {
        Self {
            resource: resource.as_ref().to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: Some(2),
        }
    }

    fn with_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.headers
            .push((name.as_ref().to_string(), value.as_ref().to_string()));
        self
    }

    fn with_certificate_version(mut self, version: u16) -> Self {
        self.certificate_version = Some(version);
        self
    }

    fn build(self) -> HttpRequest {
        HttpRequest {
            method: self.method,
            url: self.resource,
            headers: self.headers,
            body: self.body,
            certificate_version: self.certificate_version,
        }
    }
}

fn create_assets(
    state: &mut State,
    system_context: &SystemContext,
    assets: Vec<AssetBuilder>,
) -> BatchId {
    let batch_id = state.create_batch(system_context).unwrap();

    let operations = assemble_create_assets_and_set_contents_operations(
        state,
        system_context,
        assets,
        &batch_id,
    );

    run_computation_until_completion(|progress| {
        state.commit_batch(
            &CommitBatchArguments {
                batch_id: batch_id.clone(),
                operations: operations.clone(),
            },
            progress,
            system_context,
        )
    })
    .unwrap();

    batch_id
}

fn assemble_create_assets_and_set_contents_operations(
    state: &mut State,
    system_context: &SystemContext,
    assets: Vec<AssetBuilder>,
    batch_id: &BatchId,
) -> Vec<BatchOperation> {
    let mut operations = vec![];

    for asset in assets {
        if state.get_asset_properties(asset.name.clone()).is_ok() {
            operations.push(BatchOperation::DeleteAsset(DeleteAssetArguments {
                key: asset.name.clone(),
            }));
        }
        operations.push(BatchOperation::CreateAsset(CreateAssetArguments {
            key: asset.name.clone(),
            content_type: asset.content_type,
            max_age: asset.max_age,
            headers: asset.headers,
            enable_aliasing: asset.aliasing,
            allow_raw_access: asset.allow_raw_access,
        }));

        for (enc, chunks) in asset.encodings {
            let chunk_ids = state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_id.clone(),
                        content: chunks,
                    },
                    system_context,
                )
                .unwrap();

            operations.push(BatchOperation::SetAssetContent({
                SetAssetContentArguments {
                    key: asset.name.clone(),
                    content_encoding: enc,
                    chunk_ids,
                    last_chunk: None,
                    sha256: None,
                }
            }));
        }
    }
    operations
}

fn lookup_header<'a>(response: &'a HttpResponse, header: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find_map(|(h, v)| h.eq_ignore_ascii_case(header).then_some(v.as_str()))
}

impl State {
    fn fake_http_request(&self, host: &str, path: &str) -> HttpResponse {
        let fake_cert = [0xca, 0xfe];
        self.http_request(
            RequestBuilder::get(path).with_header("Host", host).build(),
            &fake_cert,
            unused_callback(),
        )
    }

    fn create_test_asset(&mut self, asset: AssetBuilder) {
        create_assets(self, &mock_system_context(), vec![asset]);
    }
}

#[test]
fn can_create_assets_using_batch_api() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    let batch_id = create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/contents.html", "text/html").with_encoding("identity", vec![BODY])],
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), BODY);

    // Try to update a completed batch.
    let error_msg = state
        .create_chunks(
            CreateChunksArg {
                batch_id,
                content: vec![ByteBuf::new()],
            },
            &system_context,
        )
        .unwrap_err();

    let expected = "batch not found";
    assert!(
        error_msg.contains(expected),
        "expected '{expected}' error, got: {error_msg}"
    );
}

#[test]
fn serve_correct_encoding() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const IDENTITY_BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    const GZIP_BODY: &[u8] = b"this is 'gzipped' content";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![IDENTITY_BODY])
                .with_encoding("gzip", vec![GZIP_BODY]),
            AssetBuilder::new("/no-encoding.html", "text/html"),
        ],
    );

    let identity_response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(identity_response.status_code, 200);
    assert_eq!(identity_response.body.as_ref(), IDENTITY_BODY);
    assert!(lookup_header(&identity_response, "IC-Certificate").is_some());

    let gzip_response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "gzip")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(gzip_response.status_code, 200);
    assert_eq!(gzip_response.body.as_ref(), GZIP_BODY);
    assert!(lookup_header(&gzip_response, "IC-Certificate").is_some());

    let no_encoding_response = certified_http_request(
        &state,
        RequestBuilder::get("/no-encoding.html")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(no_encoding_response.status_code, 404);
    assert_eq!(no_encoding_response.body.as_ref(), "not found".as_bytes());
    assert!(lookup_header(&no_encoding_response, "IC-Certificate").is_some());
}

#[test]
fn serve_fallback() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const INDEX_BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    const OTHER_BODY: &[u8] = b"<!DOCTYPE html><html>other content</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![INDEX_BODY]),
            AssetBuilder::new("/deep/nested/folder/index.html", "text/html")
                .with_encoding("identity", vec![OTHER_BODY]),
            AssetBuilder::new("/deep/nested/folder/a_file.html", "text/html")
                .with_encoding("identity", vec![OTHER_BODY]),
            AssetBuilder::new("/deep/nested/sibling/another_file.html", "text/html")
                .with_encoding("identity", vec![OTHER_BODY]),
            AssetBuilder::new("/deep/nested/sibling/a_file.html", "text/html")
                .with_encoding("identity", vec![OTHER_BODY]),
        ],
    );

    let identity_response = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    let certificate_header = lookup_header(&identity_response, "IC-Certificate").unwrap();
    println!("certificate_header: {certificate_header}");

    assert_eq!(identity_response.status_code, 200);
    assert_eq!(identity_response.body.as_ref(), INDEX_BODY);
    assert!(certificate_header.contains("expr_path=:2dn3g2lodHRwX2V4cHJqaW5kZXguaHRtbGM8JD4=:"));

    let fallback_response = certified_http_request(
        &state,
        RequestBuilder::get("/nonexistent")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    let certificate_header = lookup_header(&fallback_response, "IC-Certificate").unwrap();
    assert_eq!(fallback_response.status_code, 200);
    assert_eq!(fallback_response.body.as_ref(), INDEX_BODY);
    assert!(certificate_header.contains("expr_path=:2dn3gmlodHRwX2V4cHJjPCo+:"));

    let valid_response = certified_http_request(
        &state,
        RequestBuilder::get("/deep/nested/folder/a_file.html")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(valid_response.status_code, 200);
    assert_eq!(valid_response.body.as_ref(), OTHER_BODY);

    let fallback_response = certified_http_request(
        &state,
        RequestBuilder::get("/deep/nested/folder/nonexistent")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(fallback_response.status_code, 200);
    assert_eq!(fallback_response.body.as_ref(), INDEX_BODY);
}

#[test]
fn batches_are_dropped_after_timeout() {
    let mut state = State::default();
    let mut system_context = mock_system_context();

    let batch_1 = state.create_batch(&system_context).unwrap();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    let _chunk_1 = state
        .create_chunks(
            CreateChunksArg {
                batch_id: batch_1.clone(),
                content: vec![ByteBuf::from(BODY.to_vec())],
            },
            &system_context,
        )
        .unwrap();

    system_context.current_timestamp_ns =
        system_context.current_timestamp_ns + BATCH_EXPIRY_NANOS + 1;
    let _batch_2 = state.create_batch(&system_context);

    match state.create_chunks(
        CreateChunksArg {
            batch_id: batch_1,
            content: vec![ByteBuf::from(BODY.to_vec())],
        },
        &system_context,
    ) {
        Err(err) if err.contains("batch not found") => (),
        other => panic!("expected 'batch not found' error, got: {other:?}"),
    }
}

#[test]
fn can_delete_batch_with_chunks() {
    let mut state = State::default();
    let system_context = mock_system_context();

    let batch_1 = state.create_batch(&system_context).unwrap();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    let _chunk_1 = state
        .create_chunks(
            CreateChunksArg {
                batch_id: batch_1.clone(),
                content: vec![ByteBuf::from(BODY.to_vec())],
            },
            &system_context,
        )
        .unwrap();

    let delete_args = DeleteBatchArguments { batch_id: batch_1 };
    assert_eq!(Ok(()), state.delete_batch(delete_args.clone()));
    assert_eq!(
        Err("batch not found".to_string()),
        state.delete_batch(delete_args)
    );
}

#[test]
fn returns_index_file_for_missing_assets() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>Index</html>";
    const OTHER_BODY: &[u8] = b"<!DOCTYPE html><html>Other</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![INDEX_BODY]),
            AssetBuilder::new("/other.html", "text/html")
                .with_encoding("identity", vec![OTHER_BODY]),
        ],
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/missing.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), INDEX_BODY);
}

#[test]
fn preserves_state_on_stable_roundtrip() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>Index</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/index.html", "text/html")
            .with_encoding("identity", vec![INDEX_BODY])],
    );

    let stable_state: StableState = state.into();
    let state: State = stable_state.into();

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), INDEX_BODY);
}

#[test]
fn uses_streaming_for_multichunk_assets() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const INDEX_BODY_CHUNK_1: &[u8] = b"<!DOCTYPE html>";
    const INDEX_BODY_CHUNK_2: &[u8] = b"<html>Index</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/index.html", "text/html")
            .with_encoding("identity", vec![INDEX_BODY_CHUNK_1, INDEX_BODY_CHUNK_2])],
    );

    let streaming_callback = CallbackFunc::new(some_principal(), "stream".to_string());
    let response = state.http_request(
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
        &[],
        streaming_callback.clone(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), INDEX_BODY_CHUNK_1);

    let StreamingStrategy::Callback { callback, token } = response
        .streaming_strategy
        .expect("missing streaming strategy");
    assert_eq!(callback, streaming_callback);

    // sha256 is required
    assert_eq!(
        state
            .http_request_streaming_callback(StreamingCallbackToken {
                key: "/index.html".to_string(),
                content_encoding: "identity".to_string(),
                index: Nat::from(1_u8),
                sha256: None,
            })
            .unwrap_err(),
        "sha256 required"
    );

    let streaming_response = state.http_request_streaming_callback(token).unwrap();
    assert_eq!(streaming_response.body.as_ref(), INDEX_BODY_CHUNK_2);
    assert!(
        streaming_response.token.is_none(),
        "Unexpected streaming response: {streaming_response:?}"
    );
}

#[test]
fn get_and_get_chunk_for_multichunk_assets() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const INDEX_BODY_CHUNK_0: &[u8] = b"<!DOCTYPE html>";
    const INDEX_BODY_CHUNK_1: &[u8] = b"<html>Index</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/index.html", "text/html")
            .with_encoding("identity", vec![INDEX_BODY_CHUNK_0, INDEX_BODY_CHUNK_1])],
    );

    let chunk_0 = state
        .get(GetArg {
            key: "/index.html".to_string(),
            accept_encodings: vec!["identity".to_string()],
        })
        .unwrap();
    assert_eq!(chunk_0.content.as_ref(), INDEX_BODY_CHUNK_0);

    let chunk_1 = state
        .get_chunk(GetChunkArg {
            key: "/index.html".to_string(),
            content_encoding: "identity".to_string(),
            index: Nat::from(1_u8),
            sha256: chunk_0.sha256,
        })
        .unwrap();
    assert_eq!(chunk_1.as_ref(), INDEX_BODY_CHUNK_1);

    // get_chunk fails if we don't pass the sha256
    assert_eq!(
        state
            .get_chunk(GetChunkArg {
                key: "/index.html".to_string(),
                content_encoding: "identity".to_string(),
                index: Nat::from(1_u8),
                sha256: None,
            })
            .unwrap_err(),
        "sha256 required".to_string()
    );
}

#[test]
fn supports_max_age_headers() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html").with_encoding("identity", vec![BODY]),
            AssetBuilder::new("/max-age.html", "text/html")
                .with_max_age(604800)
                .with_encoding("identity", vec![BODY]),
        ],
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), BODY);
    assert!(
        lookup_header(&response, "Cache-Control").is_none(),
        "Unexpected Cache-Control header in response: {response:#?}",
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/max-age.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), BODY);
    assert_eq!(
        lookup_header(&response, "Cache-Control"),
        Some("max-age=604800"),
        "No matching Cache-Control header in response: {response:#?}",
    );
}

#[test]
fn check_url_decode() {
    assert_eq!(url_decode("/%"), Ok("/%".to_string()));
    assert_eq!(url_decode("/%%"), Ok("/%%".to_string()));
    assert_eq!(url_decode("/%e%"), Ok("/%e%".to_string()));

    assert_eq!(url_decode("/%20%a"), Ok("/ %a".to_string()));
    assert_eq!(url_decode("/%%+a%20+%@"), Ok("/%%+a +%@".to_string()));
    assert_eq!(
        url_decode("/has%percent.txt"),
        Ok("/has%percent.txt".to_string())
    );

    assert_eq!(url_decode("/%%2"), Ok("/%%2".to_string()));
    assert_eq!(url_decode("/%C3%A6"), Ok("/æ".to_string()));
    assert_eq!(url_decode("/%c3%a6"), Ok("/æ".to_string()));

    assert_eq!(url_decode("/a+b+c%20d"), Ok("/a+b+c d".to_string()));

    assert_eq!(
        url_decode("/capture-d%E2%80%99e%CC%81cran-2023-10-26-a%CC%80.txt"),
        Ok("/capture-d’écran-2023-10-26-à.txt".to_string())
    );

    assert_eq!(
        url_decode("/%FF%FF"),
        Err(UrlDecodeError::InvalidPercentEncoding)
    );
}

#[test]
fn check_url_encode() {
    assert_eq!(url_encode("/"), "%2F");
    assert_eq!(url_encode("/%"), "%2F%25");
    assert_eq!(url_encode("/%%"), "%2F%25%25");
    assert_eq!(url_encode("/%e%"), "%2F%25e%25");
    assert_eq!(url_encode("/ %a"), "%2F%20%25a");
    assert_eq!(url_encode("%%+a +%@"), "%25%25%2Ba%20%2B%25%40");
    assert_eq!(url_encode("has%percent.txt"), "has%25percent%2Etxt");
    assert_eq!(url_encode("%%2"), "%25%252");
    assert_eq!(url_encode("a+b+c d"), "a%2Bb%2Bc%20d");
    assert_eq!(url_encode("key=value"), "key%3Dvalue");
    assert_eq!(
        url_encode("key=value&key2=value2"),
        "key%3Dvalue%26key2%3Dvalue2"
    );
    assert_eq!(url_encode("KEY=VALUE"), "KEY%3DVALUE");
    assert_eq!(
        url_encode("KEY=VALUE&KEY2=VALUE2"),
        "KEY%3DVALUE%26KEY2%3DVALUE2"
    );
    assert_eq!(
        url_encode("capture-d’écran-2023-10-26-à.txt"),
        "capture%2Dd%E2%80%99e%CC%81cran%2D2023%2D10%2D26%2Da%CC%80%2Etxt"
    );
}

#[test]
fn supports_custom_http_headers() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![BODY])
                .with_header("Access-Control-Allow-Origin", "*"),
            AssetBuilder::new("/max-age.html", "text/html")
                .with_max_age(604800)
                .with_encoding("identity", vec![BODY])
                .with_header("X-Content-Type-Options", "nosniff"),
        ],
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), BODY);
    assert!(
        lookup_header(&response, "Access-Control-Allow-Origin").is_some(),
        "Missing Access-Control-Allow-Origin header in response: {response:#?}",
    );
    assert!(
        lookup_header(&response, "Access-Control-Allow-Origin") == Some("*"),
        "Incorrect value for Access-Control-Allow-Origin header in response: {response:#?}",
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/max-age.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), BODY);
    assert_eq!(
        lookup_header(&response, "Cache-Control"),
        Some("max-age=604800"),
        "No matching Cache-Control header in response: {response:#?}",
    );
    assert!(
        lookup_header(&response, "X-Content-Type-Options").is_some(),
        "Missing X-Content-Type-Options header in response: {response:#?}",
    );
    assert!(
        lookup_header(&response, "X-Content-Type-Options") == Some("nosniff"),
        "Incorrect value for X-Content-Type-Options header in response: {response:#?}",
    );
}

#[test]
fn supports_getting_and_setting_asset_properties() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    let set_cookie_header = ("Set-Cookie".into(), DEFAULT_IC_ENV_COOKIE_VALUE.into());

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![BODY])
                .with_header("Access-Control-Allow-Origin", "*"),
            AssetBuilder::new("/max-age.html", "text/html")
                .with_max_age(604800)
                .with_encoding("identity", vec![BODY])
                .with_header("X-Content-Type-Options", "nosniff"),
        ],
    );

    assert_eq!(
        state.get_asset_properties("/contents.html".into()),
        Ok(AssetProperties {
            max_age: None,
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("Access-Control-Allow-Origin".into(), "*".into())
            ])),
            allow_raw_access: None,
            is_aliased: None
        })
    );
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(604800),
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("X-Content-Type-Options".into(), "nosniff".into())
            ])),
            allow_raw_access: None,
            is_aliased: None
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: Some(Some(1)),
            headers: Some(Some(BTreeMap::from([(
                "X-Content-Type-Options".into(),
                "nosniff".into()
            )]))),
            allow_raw_access: None,
            is_aliased: None
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(1),
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("X-Content-Type-Options".into(), "nosniff".into())
            ])),
            allow_raw_access: None,
            is_aliased: None
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: Some(None),
            headers: Some(None),
            allow_raw_access: None,
            is_aliased: None
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: None,
            headers: Some(BTreeMap::from([set_cookie_header.clone()])),
            allow_raw_access: None,
            is_aliased: None
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: Some(Some(1)),
            headers: Some(Some(BTreeMap::from([(
                "X-Content-Type-Options".into(),
                "nosniff".into()
            )]))),
            allow_raw_access: None,
            is_aliased: None
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(1),
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("X-Content-Type-Options".into(), "nosniff".into())
            ])),
            allow_raw_access: None,
            is_aliased: None
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: None,
            headers: Some(Some(BTreeMap::from([(
                "new-header".into(),
                "value".into()
            )]))),
            allow_raw_access: None,
            is_aliased: None
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(1),
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("new-header".into(), "value".into())
            ])),
            allow_raw_access: None,
            is_aliased: None
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: Some(Some(2)),
            headers: None,
            allow_raw_access: None,
            is_aliased: None
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(2),
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("new-header".into(), "value".into())
            ])),
            allow_raw_access: None,
            is_aliased: None
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: None,
            headers: None,
            allow_raw_access: None,
            is_aliased: Some(Some(false))
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(2),
            headers: Some(BTreeMap::from([
                set_cookie_header.clone(),
                ("new-header".into(), "value".into())
            ])),
            allow_raw_access: None,
            is_aliased: Some(false)
        })
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/max-age.html".into(),
            max_age: None,
            headers: Some(None),
            allow_raw_access: None,
            is_aliased: Some(None)
        })
        .is_ok());
    assert_eq!(
        state.get_asset_properties("/max-age.html".into()),
        Ok(AssetProperties {
            max_age: Some(2),
            headers: Some(BTreeMap::from([set_cookie_header.clone()])),
            allow_raw_access: None,
            is_aliased: None
        })
    );
}

#[test]
fn ic_env_cookie_only_for_html_files() {
    let mut state = State::default();
    let system_context = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: vec![0xab, 0xcd],
            icp_public_env_vars: BTreeMap::from([("PUBLIC_TEST".into(), "ok".into())]),
        }),
        100_000_000_000,
    );

    const HTML_BODY: &[u8] = b"<html>hi</html>";
    const JS_BODY: &[u8] = b"console.log('hi')";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![HTML_BODY]),
            AssetBuilder::new("/bundle.js", "application/javascript")
                .with_encoding("identity", vec![JS_BODY]),
        ],
    );

    let html_response = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(html_response.status_code, 200);
    let html_cookie = lookup_header(&html_response, "Set-Cookie").unwrap();
    assert_eq!(
        html_cookie,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=abcd&PUBLIC_TEST=ok")
        )
    );

    let js_response = certified_http_request(
        &state,
        RequestBuilder::get("/bundle.js")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(js_response.status_code, 200);
    let js_cookie = lookup_header(&js_response, "Set-Cookie");
    assert!(js_cookie.is_none());
}

#[test]
fn ic_env_cookie_encodes_root_key_and_public_env_vars_and_updates() {
    let mut state = State::default();
    let ic_root_key = vec![0xab, 0xcd];
    let current_timestamp_ns = 100_000_000_000;

    // First commit with custom env: root_key=abcd, PUBLIC_TEST=ok
    let public_env_vars = BTreeMap::from([("PUBLIC_TEST".into(), "ok".into())]);
    let system_context_1 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: ic_root_key.clone(),
            icp_public_env_vars: public_env_vars,
        }),
        current_timestamp_ns,
    );

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    create_assets(
        &mut state,
        &system_context_1,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );

    let response = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(response.status_code, 200);
    let cookie1 = lookup_header(&response, "Set-Cookie").unwrap();
    assert_eq!(
        cookie1,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=abcd&PUBLIC_TEST=ok")
        )
    );

    // Second commit with updated env: root_key=abcd, PUBLIC_TEST=ok2
    let public_env_vars_2 = BTreeMap::from([("PUBLIC_TEST".into(), "ok2".into())]);
    let system_context_2 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key,
            icp_public_env_vars: public_env_vars_2,
        }),
        current_timestamp_ns,
    );

    create_assets(
        &mut state,
        &system_context_2,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );

    let response2 = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(response2.status_code, 200);
    let cookie2 = lookup_header(&response2, "Set-Cookie").unwrap();
    assert_eq!(
        cookie2,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=abcd&PUBLIC_TEST=ok2")
        )
    );
}

#[test]
fn ic_env_cookie_replaces_old_public_env_vars() {
    let mut state = State::default();
    let ic_root_key = vec![0xaa];
    let current_timestamp_ns = 100_000_000_000;

    // First commit with PUBLIC_OLD=v1 and root_key=aa
    let mut public_env_vars_1 = BTreeMap::new();
    public_env_vars_1.insert("PUBLIC_OLD".to_string(), "v1".to_string());
    let system_context_1 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key,
            icp_public_env_vars: public_env_vars_1,
        }),
        current_timestamp_ns,
    );

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    create_assets(
        &mut state,
        &system_context_1,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );
    let resp1 = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(resp1.status_code, 200);
    let cookie1 = lookup_header(&resp1, "Set-Cookie").unwrap();
    assert_eq!(
        cookie1,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=aa&PUBLIC_OLD=v1")
        )
    );

    // Second commit with PUBLIC_NEW=v2 and root_key=bb
    let mut public_env_vars_2 = BTreeMap::new();
    public_env_vars_2.insert("PUBLIC_NEW".to_string(), "v2".to_string());
    let system_context_2 = SystemContext::new_with_options(
        Some(CanisterEnv {
            // The root key typically doesn't change,
            // but we want to test if the cookie is updated properly
            ic_root_key: vec![0xbb],
            icp_public_env_vars: public_env_vars_2,
        }),
        current_timestamp_ns,
    );

    create_assets(
        &mut state,
        &system_context_2,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );
    let resp2 = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(resp2.status_code, 200);
    let cookie2 = lookup_header(&resp2, "Set-Cookie").unwrap();
    assert_eq!(
        cookie2,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=bb&PUBLIC_NEW=v2")
        )
    );
}

#[test]
fn ic_env_cookie_updates_all_assets() {
    // Test that when env vars are updated, all assets (not just the updated one) get the new cookie
    let mut state = State::default();
    let ic_root_key = vec![0xaa];
    let current_timestamp_ns = 100_000_000_000;

    // First commit with PUBLIC_OLD=v1 and root_key=aa
    let public_env_vars_1 = BTreeMap::from([("PUBLIC_OLD".to_string(), "v1".to_string())]);
    let system_context_1 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: ic_root_key.clone(),
            icp_public_env_vars: public_env_vars_1,
        }),
        current_timestamp_ns,
    );

    create_assets(
        &mut state,
        &system_context_1,
        vec![
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![b"<!DOCTYPE html><html>Index</html>"]),
            AssetBuilder::new("/about.html", "text/html")
                .with_encoding("identity", vec![b"<!DOCTYPE html><html>About</html>"]),
        ],
    );

    // Second commit with PUBLIC_NEW=v2 and root_key=bb, updating only index.html
    let public_env_vars_2 = BTreeMap::from([("PUBLIC_NEW".to_string(), "v2".to_string())]);
    let system_context_2 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: vec![0xbb],
            icp_public_env_vars: public_env_vars_2,
        }),
        current_timestamp_ns,
    );

    create_assets(
        &mut state,
        &system_context_2,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding(
            "identity",
            vec![b"<!DOCTYPE html><html>Index updated</html>"],
        )],
    );

    let updated_cookie_value = url_encode("ic_root_key=bb&PUBLIC_NEW=v2");

    // Verify that the updated asset gets the new cookie
    let resp_index = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    let cookie_index = lookup_header(&resp_index, "Set-Cookie").unwrap();
    assert_eq!(
        cookie_index,
        format!("ic_env={updated_cookie_value}; SameSite=Lax")
    );

    // Verify that an asset that was NOT updated also gets the new cookie
    let resp_about = certified_http_request(
        &state,
        RequestBuilder::get("/about.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    let cookie_about = lookup_header(&resp_about, "Set-Cookie").unwrap();
    assert_eq!(
        cookie_about,
        format!("ic_env={updated_cookie_value}; SameSite=Lax")
    );
}

#[test]
fn ic_env_cookie_multiple_public_env_vars() {
    let mut state = State::default();
    let ic_root_key = vec![0xaa];
    let current_timestamp_ns = 100_000_000_000;

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    // Commit 1: add PUBLIC_A=va, PUBLIC_B=vb
    let env_vars_1 = BTreeMap::from([
        ("PUBLIC_A".into(), "va".into()),
        ("PUBLIC_B".into(), "vb".into()),
    ]);
    let system_context_1 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: ic_root_key.clone(),
            icp_public_env_vars: env_vars_1,
        }),
        current_timestamp_ns,
    );
    create_assets(
        &mut state,
        &system_context_1,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );
    let res_1 = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(res_1.status_code, 200);
    let cookie_1 = lookup_header(&res_1, "Set-Cookie").unwrap();
    assert_eq!(
        cookie_1,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=aa&PUBLIC_A=va&PUBLIC_B=vb")
        )
    );

    // Commit 2: modify PUBLIC_A=va2, keep PUBLIC_B=vb, add PUBLIC_C=vc
    let env_vars_2 = BTreeMap::from([
        ("PUBLIC_A".into(), "va2".into()),
        ("PUBLIC_B".into(), "vb".into()),
        ("PUBLIC_C".into(), "vc".into()),
    ]);
    let system_context_2 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key: ic_root_key.clone(),
            icp_public_env_vars: env_vars_2,
        }),
        current_timestamp_ns,
    );
    create_assets(
        &mut state,
        &system_context_2,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );
    let res_2 = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(res_2.status_code, 200);
    let cookie_2 = lookup_header(&res_2, "Set-Cookie").unwrap();
    assert_eq!(
        cookie_2,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=aa&PUBLIC_A=va2&PUBLIC_B=vb&PUBLIC_C=vc")
        )
    );

    // Commit 3: remove PUBLIC_B, keep PUBLIC_A=va2 and PUBLIC_C=vc
    let env_vars_3 = BTreeMap::from([
        ("PUBLIC_A".into(), "va2".into()),
        ("PUBLIC_C".into(), "vc".into()),
    ]);
    let system_context_3 = SystemContext::new_with_options(
        Some(CanisterEnv {
            ic_root_key,
            icp_public_env_vars: env_vars_3,
        }),
        current_timestamp_ns,
    );
    create_assets(
        &mut state,
        &system_context_3,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])],
    );
    let res_3 = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    assert_eq!(res_3.status_code, 200);
    let cookie_3 = lookup_header(&res_3, "Set-Cookie").unwrap();
    assert_eq!(
        cookie_3,
        format!(
            "ic_env={}; SameSite=Lax",
            url_encode("ic_root_key=aa&PUBLIC_A=va2&PUBLIC_C=vc")
        )
    );
}

#[test]
fn create_asset_fails_if_asset_exists() {
    let mut state = State::default();
    let system_context = mock_system_context();
    const FILE_BODY: &[u8] = b"<!DOCTYPE html><html>file body</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/contents.html", "text/html")
            .with_encoding("identity", vec![FILE_BODY])],
    );

    assert!(
        state
            .create_asset(CreateAssetArguments {
                key: "/contents.html".to_string(),
                content_type: "text/html".to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: None,
                enable_aliasing: None,
            })
            .unwrap_err()
            == "asset already exists"
    );
}

#[test]
fn support_aliases() {
    let mut state = State::default();
    let system_context = mock_system_context();
    const INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>index</html>";
    const SUBDIR_INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>subdir index</html>";
    const FILE_BODY: &[u8] = b"<!DOCTYPE html><html>file body</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![FILE_BODY]),
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![INDEX_BODY]),
            AssetBuilder::new("/subdirectory/index.html", "text/html")
                .with_encoding("identity", vec![SUBDIR_INDEX_BODY]),
        ],
    );

    let normal_request =
        certified_http_request(&state, RequestBuilder::get("/contents.html").build());
    assert_eq!(normal_request.body.as_ref(), FILE_BODY);

    let alias_add_html = certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(alias_add_html.body.as_ref(), FILE_BODY);

    let root_alias = certified_http_request(&state, RequestBuilder::get("/").build());
    assert_eq!(root_alias.body.as_ref(), INDEX_BODY);

    // cannot use certified request because this produces an invalid URL
    let empty_path_alias =
        state.http_request(RequestBuilder::get("").build(), &[], unused_callback());
    assert_eq!(empty_path_alias.body.as_ref(), INDEX_BODY);

    let subdirectory_index_alias =
        certified_http_request(&state, RequestBuilder::get("/subdirectory/index").build());
    assert_eq!(subdirectory_index_alias.body.as_ref(), SUBDIR_INDEX_BODY);

    let subdirectory_index_alias_2 =
        certified_http_request(&state, RequestBuilder::get("/subdirectory/").build());
    assert_eq!(subdirectory_index_alias_2.body.as_ref(), SUBDIR_INDEX_BODY);

    let subdirectory_index_alias_3 =
        certified_http_request(&state, RequestBuilder::get("/subdirectory").build());
    assert_eq!(subdirectory_index_alias_3.body.as_ref(), SUBDIR_INDEX_BODY);
}

#[test]
fn alias_enable_and_disable() {
    let mut state = State::default();
    let system_context = mock_system_context();
    const SUBDIR_INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>subdir index</html>";
    const FILE_BODY: &[u8] = b"<!DOCTYPE html><html>file body</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![FILE_BODY]),
            AssetBuilder::new("/subdirectory/index.html", "text/html")
                .with_encoding("identity", vec![SUBDIR_INDEX_BODY]),
        ],
    );

    let alias_add_html = certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(alias_add_html.body.as_ref(), FILE_BODY);

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/contents.html".into(),
            max_age: None,
            headers: None,
            allow_raw_access: None,
            is_aliased: Some(Some(false)),
        })
        .is_ok());

    let no_more_alias = state.http_request(
        RequestBuilder::get("/contents").build(),
        &[],
        unused_callback(),
    );
    assert_ne!(no_more_alias.body.as_ref(), FILE_BODY);

    let other_alias_still_works =
        certified_http_request(&state, RequestBuilder::get("/subdirectory/index").build());
    assert_eq!(other_alias_still_works.body.as_ref(), SUBDIR_INDEX_BODY);

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/contents.html", "text/html")
            .with_encoding("identity", vec![FILE_BODY])
            .with_aliasing(true)],
    );

    assert!(state
        .set_asset_properties(SetAssetPropertiesArguments {
            key: "/contents.html".into(),
            max_age: None,
            headers: None,
            allow_raw_access: None,
            is_aliased: Some(Some(true)),
        })
        .is_ok());
    let alias_add_html_again =
        certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(alias_add_html_again.body.as_ref(), FILE_BODY);
}

#[test]
fn alias_behavior_persists_through_upgrade() {
    let mut state = State::default();
    let system_context = mock_system_context();
    const SUBDIR_INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>subdir index</html>";
    const FILE_BODY: &[u8] = b"<!DOCTYPE html><html>file body</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![FILE_BODY])
                .with_aliasing(false),
            AssetBuilder::new("/subdirectory/index.html", "text/html")
                .with_encoding("identity", vec![SUBDIR_INDEX_BODY]),
        ],
    );

    let alias_disabled = state.http_request(
        RequestBuilder::get("/contents").build(),
        &[],
        unused_callback(),
    );
    assert_ne!(alias_disabled.body.as_ref(), FILE_BODY);

    let alias_for_other_asset_still_works =
        certified_http_request(&state, RequestBuilder::get("/subdirectory").build());
    assert_eq!(
        alias_for_other_asset_still_works.body.as_ref(),
        SUBDIR_INDEX_BODY
    );

    let stable_state: StableState = state.into();
    let state: State = stable_state.into();

    let alias_stays_turned_off = state.http_request(
        RequestBuilder::get("/contents").build(),
        &[],
        unused_callback(),
    );
    assert_ne!(alias_stays_turned_off.body.as_ref(), FILE_BODY);

    let alias_for_other_asset_still_works =
        certified_http_request(&state, RequestBuilder::get("/subdirectory").build());
    assert_eq!(
        alias_for_other_asset_still_works.body.as_ref(),
        SUBDIR_INDEX_BODY
    );
}

#[test]
fn aliasing_name_clash() {
    let mut state = State::default();
    let system_context = mock_system_context();
    const FILE_BODY: &[u8] = b"<!DOCTYPE html><html>file body</html>";
    const FILE_BODY_2: &[u8] = b"<!DOCTYPE html><html>second body</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/contents.html", "text/html")
            .with_encoding("identity", vec![FILE_BODY])],
    );

    let alias_add_html = certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(alias_add_html.body.as_ref(), FILE_BODY);

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/contents", "text/html")
            .with_encoding("identity", vec![FILE_BODY_2])],
    );

    let alias_doesnt_overwrite_actual_file =
        certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(
        alias_doesnt_overwrite_actual_file.body.as_ref(),
        FILE_BODY_2
    );

    state.delete_asset(DeleteAssetArguments {
        key: "/contents".to_string(),
    });

    let alias_accessible_again =
        certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(alias_accessible_again.body.as_ref(), FILE_BODY);
}

#[test]
fn headers_cbor_deserialize_from_hashmap_to_btreemap() {
    // We want to make sure that deserializing from a HashMap to a BTreeMap works
    // so that frontend canister upgrades don't break
    for i in 0..100 {
        let old_headers: HashMap<String, String> = HashMap::from([
            // Order is not alphabetical on purpose here
            // to check that the BTreeMap orders them correctly
            ("c-name".into(), "c-value".into()),
            ("index".into(), i.to_string()),
            ("d-name".into(), "d-value".into()),
            ("b-name".into(), "b-value".into()),
            ("a-name".into(), "a-value".into()),
        ]);
        let serialized = serde_cbor::to_vec(&old_headers).unwrap();
        let new_headers: BTreeMap<String, String> = serde_cbor::from_slice(&serialized).unwrap();
        // Compare the order to check that the BTreeMap is deterministic
        assert_eq!(
            new_headers.into_iter().collect::<Vec<(String, String)>>(),
            vec![
                ("a-name".into(), "a-value".into()),
                ("b-name".into(), "b-value".into()),
                ("c-name".into(), "c-value".into()),
                ("d-name".into(), "d-value".into()),
                ("index".into(), i.to_string()),
            ]
        );
    }
}

#[test]
fn headers_candid_hashmap_btreemap_roundtrip() {
    for i in 0..100 {
        let old_headers: HashMap<String, String> = HashMap::from([
            ("a-name".into(), "a-value".into()),
            ("b-name".into(), "b-value".into()),
            ("c-name".into(), "c-value".into()),
            ("d-name".into(), "d-value".into()),
            ("index".into(), i.to_string()),
        ]);

        // Deserialize to BTreeMap
        let old_serialized = candid::encode_one(&old_headers).unwrap();
        let new_headers: BTreeMap<String, String> = candid::decode_one(&old_serialized).unwrap();
        assert_eq!(
            new_headers
                .clone()
                .into_iter()
                .collect::<Vec<(String, String)>>(),
            vec![
                ("a-name".into(), "a-value".into()),
                ("b-name".into(), "b-value".into()),
                ("c-name".into(), "c-value".into()),
                ("d-name".into(), "d-value".into()),
                ("index".into(), i.to_string()),
            ]
        );

        // Go back to HashMap
        let new_serialized = candid::encode_one(new_headers).unwrap();
        let old_deserialized: HashMap<String, String> =
            candid::decode_one(&new_serialized).unwrap();
        assert_eq!(
            old_deserialized, old_headers,
            "Old headers don't match, iteration: {i}",
        );
    }
}

#[cfg(test)]
mod allow_raw_access {
    use super::*;

    const FILE_BODY: &[u8] = b"<!DOCTYPE html><html>file body</html>";

    #[test]
    fn redirects_from_raw_to_certified() {
        let mut state = State::default();

        state.create_test_asset(
            AssetBuilder::new("/page.html", "text/html").with_allow_raw_access(Some(false)),
        );
        let response = state.fake_http_request("a-b-c.raw.icp0.io", "/page");
        dbg!(&response);
        assert_eq!(response.status_code, 308);
        assert_eq!(
            lookup_header(&response, "Location").unwrap(),
            "https://a-b-c.icp0.io/page"
        );
        let response = state.fake_http_request("a-b-c.raw.ic0.app", "/page");
        dbg!(&response);
        assert_eq!(response.status_code, 308);
        assert_eq!(
            lookup_header(&response, "Location").unwrap(),
            "https://a-b-c.ic0.app/page"
        );

        state.create_test_asset(
            AssetBuilder::new("/page2.html", "text/html").with_allow_raw_access(Some(false)),
        );
        let response = state.fake_http_request("a-b-c.raw.icp0.io", "/page2");
        dbg!(&response);
        assert_eq!(response.status_code, 308);
        assert_eq!(
            lookup_header(&response, "Location").unwrap(),
            "https://a-b-c.icp0.io/page2"
        );

        state.create_test_asset(
            AssetBuilder::new("/index.html", "text/html").with_allow_raw_access(Some(false)),
        );
        let response = state.fake_http_request("a-b-c.raw.icp0.io", "/");
        dbg!(&response);
        assert_eq!(response.status_code, 308);
        assert_eq!(
            lookup_header(&response, "Location").unwrap(),
            "https://a-b-c.icp0.io/"
        );

        let mut state = State::default();
        state.create_test_asset(
            AssetBuilder::new("/index.html", "text/html").with_allow_raw_access(Some(false)),
        );
        let response = state.fake_http_request("a-b-c.raw.icp0.io", "/");
        dbg!(&response);
        assert_eq!(response.status_code, 308);
        assert_eq!(
            lookup_header(&response, "Location").unwrap(),
            "https://a-b-c.icp0.io/"
        );
    }

    #[test]
    fn wont_redirect_from_raw_to_certified() {
        let mut state = State::default();
        state.create_test_asset(
            AssetBuilder::new("/blog.html", "text/html")
                .with_encoding("identity", vec![FILE_BODY])
                .with_allow_raw_access(Some(true)),
        );
        let response = state.fake_http_request("a-b-c.raw.icp0.io", "/blog.html");
        dbg!(&response);
        assert_eq!(response.status_code, 200);

        let mut state = State::default();
        state.create_test_asset(
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![FILE_BODY])
                .with_allow_raw_access(Some(true)),
        );
        let response = state.fake_http_request("a-b-c.raw.icp0.io", "/index.html");
        dbg!(&response);
        assert_eq!(response.status_code, 200);

        let mut state = State::default();
        state.create_test_asset(
            AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![FILE_BODY])
                .with_allow_raw_access(Some(true)),
        );
        let response = state.fake_http_request("a-b-c.localhost:4444", "/index.html");
        dbg!(&response);
        assert_eq!(response.status_code, 200);
    }
}

#[cfg(test)]
mod certificate_expression {
    use super::*;
    use crate::certification::build_ic_certificate_expression_from_headers_and_encoding;
    use ic_representation_independent_hash::Value;

    #[test]
    fn ic_certificate_expression_value_from_headers() {
        let h = [
            ("a".into(), Value::String("".into())),
            ("b".into(), Value::String("".into())),
            ("c".into(), Value::String("".into())),
        ]
        .to_vec();
        let c = build_ic_certificate_expression_from_headers_and_encoding(&h, Some("not identity"));
        assert_eq!(
            c.expression,
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "a", "b", "c"]}}}})"#
        );
        let c2 = build_ic_certificate_expression_from_headers_and_encoding(&h, Some("identity"));
        assert_eq!(
            c2.expression,
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "a", "b", "c"]}}}})"#
        );
    }

    #[test]
    fn ic_certificate_expression_present_for_new_assets() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![BODY])
                .with_max_age(604800)
                .with_header("Access-Control-Allow-Origin", "*")],
        );

        let response = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "gzip,identity")
                .build(),
        );

        assert!(
            lookup_header(&response, "ic-certificateexpression").is_some(),
            "Missing ic-certifiedexpression header in response: {response:#?}",
        );
        assert_eq!(
            lookup_header(&response, "ic-certificateexpression").unwrap(),
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "cache-control", "Access-Control-Allow-Origin", "Set-Cookie"]}}}})"#,
            "Missing ic-certifiedexpression header in response: {response:#?}",
        );
    }

    #[test]
    fn ic_certificate_expression_gets_updated_on_asset_properties_update() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("gzip", vec![BODY])
                .with_max_age(604800)
                .with_header("Access-Control-Allow-Origin", "*")],
        );

        let response = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "gzip,identity")
                .with_certificate_version(2)
                .build(),
        );

        assert!(
            lookup_header(&response, "ic-certificateexpression").is_some(),
            "Missing ic-certificateexpression header in response: {response:#?}",
        );
        assert_eq!(
            lookup_header(&response, "ic-certificateexpression").unwrap(),
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "cache-control", "Access-Control-Allow-Origin", "Set-Cookie"]}}}})"#,
            "Missing ic-certificateexpression header in response: {response:#?}",
        );

        state
            .set_asset_properties(SetAssetPropertiesArguments {
                key: "/contents.html".into(),
                max_age: Some(None),
                headers: Some(Some(BTreeMap::from([(
                    "custom-header".into(),
                    "value".into(),
                )]))),
                allow_raw_access: None,
                is_aliased: None,
            })
            .unwrap();
        let response = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "gzip,identity")
                .with_certificate_version(2)
                .build(),
        );
        assert!(
            lookup_header(&response, "ic-certificateexpression").is_some(),
            "Missing ic-certificateexpression header in response: {response:#?}",
        );
        assert_eq!(
            lookup_header(&response, "ic-certificateexpression").unwrap(),
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "Set-Cookie", "custom-header"]}}}})"#,
            "Missing ic-certifiedexpression header in response: {response:#?}",
        );
    }
}

#[cfg(test)]
mod certification {
    use super::*;

    #[test]
    fn proper_header_structure() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
        const UPDATED_BODY: &[u8] = b"<!DOCTYPE html><html>lots of content!</html>";

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![BODY])
                .with_max_age(604800)
                .with_header("Access-Control-Allow-Origin", "*")],
        );

        let response = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "gzip,identity")
                .with_certificate_version(2)
                .build(),
        );

        let cert_header =
            lookup_header(&response, "ic-certificate").expect("ic-certificate header missing");

        assert!(
            cert_header.contains("version=2"),
            "cert is missing version indicator or has wrong version",
        );
        assert!(cert_header.contains("certificate=:"), "cert is missing",);
        assert!(cert_header.contains("tree=:"), "tree is missing",);
        assert!(!cert_header.contains("tree=::"), "tree is empty",);
        assert!(cert_header.contains("expr_path=:"), "expr_path is missing",);
        assert!(!cert_header.contains("expr_path=::"), "expr_path is empty",);

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![UPDATED_BODY])
                .with_max_age(604800)
                .with_header("Access-Control-Allow-Origin", "*")],
        );

        let response = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "gzip,identity")
                .with_certificate_version(2)
                .build(),
        );

        assert!(lookup_header(&response, "ic-certificate").is_some());
    }

    #[test]
    fn etag() {
        // For now only checks that defining a custom etag doesn't break certification.
        // Serving HTTP 304 responses if the etag matches is part of https://dfinity.atlassian.net/browse/SDK-191

        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![BODY])
                .with_header("etag", "my-etag")],
        );

        let response = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "gzip,identity")
                .build(),
        );
        assert_eq!(
            lookup_header(&response, "etag").expect("ic-certificate header missing"),
            "my-etag"
        );
    }
}

#[cfg(test)]
mod configuration_methods {
    use super::*;
    use crate::types::ConfigureArguments;

    #[test]
    fn empty_config() {
        let state = State::default();

        let x = state.get_configuration();
        assert!(x.max_batches.is_none());
        assert!(x.max_chunks.is_none());
        assert!(x.max_bytes.is_none());
    }

    #[test]
    fn set_only_max_batches() {
        let mut state = State::default();

        state.configure(ConfigureArguments {
            max_batches: Some(Some(47)),
            max_chunks: None,
            max_bytes: None,
        });

        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, None);
        assert_eq!(x.max_bytes, None);
    }

    #[test]
    fn unset_only_max_batches() {
        let mut state = State::default();
        state.configure(ConfigureArguments {
            max_batches: Some(Some(47)),
            max_chunks: Some(Some(67)),
            max_bytes: Some(Some(77)),
        });
        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, Some(67));
        assert_eq!(x.max_bytes, Some(77));

        state.configure(ConfigureArguments {
            max_batches: Some(None),
            max_chunks: None,
            max_bytes: None,
        });

        let x = state.get_configuration();
        assert_eq!(x.max_batches, None);
        assert_eq!(x.max_chunks, Some(67));
        assert_eq!(x.max_bytes, Some(77));
    }

    #[test]
    fn change_only_max_batches() {
        let mut state = State::default();
        state.configure(ConfigureArguments {
            max_batches: Some(Some(47)),
            max_chunks: Some(Some(67)),
            max_bytes: Some(Some(77)),
        });
        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, Some(67));
        assert_eq!(x.max_bytes, Some(77));

        state.configure(ConfigureArguments {
            max_batches: Some(Some(35)),
            max_chunks: None,
            max_bytes: None,
        });

        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(35));
        assert_eq!(x.max_chunks, Some(67));
        assert_eq!(x.max_bytes, Some(77));
    }

    #[test]
    fn set_only_max_chunks() {
        let mut state = State::default();

        state.configure(ConfigureArguments {
            max_batches: None,
            max_chunks: Some(Some(23)),
            max_bytes: None,
        });

        let x = state.get_configuration();
        assert_eq!(x.max_batches, None);
        assert_eq!(x.max_chunks, Some(23));
        assert_eq!(x.max_bytes, None);
    }

    #[test]
    fn unset_only_max_chunks() {
        let mut state = State::default();
        state.configure(ConfigureArguments {
            max_batches: Some(Some(47)),
            max_chunks: Some(Some(67)),
            max_bytes: Some(Some(77)),
        });
        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, Some(67));
        assert_eq!(x.max_bytes, Some(77));

        state.configure(ConfigureArguments {
            max_batches: None,
            max_chunks: Some(None),
            max_bytes: None,
        });

        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, None);
        assert_eq!(x.max_bytes, Some(77));
    }

    #[test]
    fn change_only_max_chunks() {
        let mut state = State::default();
        state.configure(ConfigureArguments {
            max_batches: Some(Some(47)),
            max_chunks: Some(Some(67)),
            max_bytes: Some(Some(77)),
        });
        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, Some(67));
        assert_eq!(x.max_bytes, Some(77));

        state.configure(ConfigureArguments {
            max_batches: None,
            max_chunks: Some(Some(54)),
            max_bytes: None,
        });

        let x = state.get_configuration();
        assert_eq!(x.max_batches, Some(47));
        assert_eq!(x.max_chunks, Some(54));
        assert_eq!(x.max_bytes, Some(77));
    }
}

#[cfg(test)]
mod enforce_limits {
    use super::*;
    use crate::types::ConfigureArguments;

    #[test]
    fn max_batches() {
        let mut state = State::default();
        let system_context = mock_system_context();

        state.configure(ConfigureArguments {
            max_batches: Some(Some(3)),
            max_chunks: None,
            max_bytes: None,
        });
        state.create_batch(&system_context).unwrap();
        state.create_batch(&system_context).unwrap();
        state.create_batch(&system_context).unwrap();
        assert_eq!(
            state.create_batch(&system_context).unwrap_err(),
            "batch limit exceeded"
        );
    }

    #[test]
    fn max_chunks() {
        let mut state = State::default();
        let system_context = mock_system_context();

        state.configure(ConfigureArguments {
            max_batches: None,
            max_chunks: Some(Some(3)),
            max_bytes: None,
        });
        let batch_1 = state.create_batch(&system_context).unwrap();
        let batch_2 = state.create_batch(&system_context).unwrap();

        state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_1.clone(),
                    content: vec![ByteBuf::new()],
                },
                &system_context,
            )
            .unwrap();
        state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_2.clone(),
                    content: vec![ByteBuf::new()],
                },
                &system_context,
            )
            .unwrap();
        assert_eq!(
            state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_2.clone(),
                        content: vec![ByteBuf::new(), ByteBuf::new()]
                    },
                    &system_context,
                )
                .unwrap_err(),
            "chunk limit exceeded"
        );
        state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_2.clone(),
                    content: vec![ByteBuf::new()],
                },
                &system_context,
            )
            .unwrap();

        assert_eq!(
            state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_1,
                        content: vec![ByteBuf::new()],
                    },
                    &system_context,
                )
                .unwrap_err(),
            "chunk limit exceeded"
        );
        assert_eq!(
            state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_2.clone(),
                        content: vec![ByteBuf::new()],
                    },
                    &system_context,
                )
                .unwrap_err(),
            "chunk limit exceeded"
        );
    }

    #[test]
    fn max_bytes() {
        let mut state = State::default();
        let system_context = mock_system_context();

        state.configure(ConfigureArguments {
            max_batches: None,
            max_chunks: None,
            max_bytes: Some(Some(289)),
        });
        let c0 = vec![0u8; 100];
        let c1 = vec![1u8; 100];
        let c2 = vec![2u8; 90];
        let c3 = vec![3u8; 89];
        let c4 = vec![4u8; 1];

        let batch_1 = state.create_batch(&system_context).unwrap();
        let batch_2 = state.create_batch(&system_context).unwrap();
        assert_eq!(
            state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_1.clone(),
                        content: vec![
                            ByteBuf::from(c0.clone()),
                            ByteBuf::from(c1.clone()),
                            ByteBuf::from(c2.clone())
                        ]
                    },
                    &system_context,
                )
                .unwrap_err(),
            "byte limit exceeded"
        );
        state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_1.clone(),
                    content: vec![ByteBuf::from(c0), ByteBuf::from(c1)],
                },
                &system_context,
            )
            .unwrap();
        assert_eq!(
            state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_2.clone(),
                        content: vec![ByteBuf::from(c2)],
                    },
                    &system_context,
                )
                .unwrap_err(),
            "byte limit exceeded"
        );
        state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_2.clone(),
                    content: vec![ByteBuf::from(c3)],
                },
                &system_context,
            )
            .unwrap();
        assert_eq!(
            state
                .create_chunks(
                    CreateChunksArg {
                        batch_id: batch_1,
                        content: vec![ByteBuf::from(c4)],
                    },
                    &system_context,
                )
                .unwrap_err(),
            "byte limit exceeded"
        );
    }
}

#[cfg(test)]
mod last_state_update_timestamp {
    use super::*;
    use crate::types::StoreArg;

    #[test]
    fn timestamp_updates_on_commit_batch() {
        let mut state = State::default();
        let system_context = mock_system_context();

        // Initial timestamp should be 0
        assert_eq!(state.last_state_update_timestamp_ns(), 0);

        // Create and commit a batch with asset operations
        let batch_id = state.create_batch(&system_context).unwrap();

        run_computation_until_completion(|progress| {
            state.commit_batch(
                &CommitBatchArguments {
                    batch_id: batch_id.clone(),
                    operations: vec![BatchOperation::CreateAsset(CreateAssetArguments {
                        key: "/test.txt".to_string(),
                        content_type: "text/plain".to_string(),
                        max_age: None,
                        headers: None,
                        enable_aliasing: None,
                        allow_raw_access: None,
                    })],
                },
                progress,
                &system_context,
            )
        })
        .unwrap();

        // Timestamp should be updated to system context timestamp
        assert_eq!(
            state.last_state_update_timestamp_ns(),
            system_context.current_timestamp_ns
        );
    }

    #[test]
    fn timestamp_updates_on_store() {
        let mut state = State::default();
        let system_context = mock_system_context();

        // Initial timestamp should be 0
        assert_eq!(state.last_state_update_timestamp_ns(), 0);

        // Store an asset
        state
            .store(
                StoreArg {
                    key: "/test.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    content_encoding: "identity".to_string(),
                    content: ByteBuf::from(b"test content".to_vec()),
                    sha256: None,
                    aliased: None,
                },
                &system_context,
            )
            .unwrap();

        // Timestamp should be updated
        assert_eq!(
            state.last_state_update_timestamp_ns(),
            system_context.current_timestamp_ns
        );
    }

    #[test]
    fn timestamp_updates_on_multiple_operations() {
        let mut state = State::default();
        let mut system_context = mock_system_context();

        // Initial timestamp should be 0
        assert_eq!(state.last_state_update_timestamp_ns(), 0);

        // First operation at time T1
        let initial_time = system_context.current_timestamp_ns;
        state
            .store(
                StoreArg {
                    key: "/test.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    content_encoding: "identity".to_string(),
                    content: ByteBuf::from(b"test content".to_vec()),
                    sha256: None,
                    aliased: None,
                },
                &system_context,
            )
            .unwrap();
        assert_eq!(state.last_state_update_timestamp_ns(), initial_time);

        // Second operation at time T2 (advanced)
        system_context.current_timestamp_ns += 1_000_000_000;
        let updated_time = system_context.current_timestamp_ns;

        let batch_id = state.create_batch(&system_context).unwrap();
        run_computation_until_completion(|progress| {
            state.commit_batch(
                &CommitBatchArguments {
                    batch_id: batch_id.clone(),
                    operations: vec![BatchOperation::SetAssetProperties(
                        SetAssetPropertiesArguments {
                            key: "/test.txt".to_string(),
                            headers: Some(Some(BTreeMap::from([(
                                "x-custom".to_string(),
                                "value".to_string(),
                            )]))),
                            max_age: None,
                            is_aliased: None,
                            allow_raw_access: None,
                        },
                    )],
                },
                progress,
                &system_context,
            )
        })
        .unwrap();

        // Timestamp should be updated to new time
        assert_eq!(state.last_state_update_timestamp_ns(), updated_time);
        assert!(state.last_state_update_timestamp_ns() > initial_time);
    }

    #[test]
    fn timestamp_persists_in_stable_state() {
        let mut state = State::default();
        let system_context = mock_system_context();

        // Store an asset to update timestamp
        state
            .store(
                StoreArg {
                    key: "/test.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    content_encoding: "identity".to_string(),
                    content: ByteBuf::from(b"test content".to_vec()),
                    sha256: None,
                    aliased: None,
                },
                &system_context,
            )
            .unwrap();

        let expected_timestamp = state.last_state_update_timestamp_ns();
        assert_eq!(expected_timestamp, system_context.current_timestamp_ns);

        // Convert to stable state and back
        let stable_state: StableState = state.into();
        let restored_state: State = stable_state.into();

        // Timestamp should be preserved
        assert_eq!(
            restored_state.last_state_update_timestamp_ns(),
            expected_timestamp
        );
    }
}

#[cfg(test)]
mod list_assets {
    use super::*;

    #[test]
    fn list_pagination_starts_from_beginning_by_default() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"content";

        // Create 10 assets
        let assets: Vec<_> = (0..10)
            .map(|i| {
                AssetBuilder::new(format!("/asset{i:02}.txt"), "text/plain")
                    .with_encoding("identity", vec![BODY])
            })
            .collect();

        create_assets(&mut state, &system_context, assets);

        // List with None should start from beginning
        let list = state.list_assets(ListRequest::default());
        assert_eq!(list.len(), 10);

        // List with Some(0) should be the same
        let list_from_zero = state.list_assets(ListRequest {
            start: Some(Nat::from(0u8)),
            length: None,
        });
        assert_eq!(list_from_zero.len(), 10);

        // Results should be sorted by key
        for i in 0..9 {
            assert!(list[i].key < list[i + 1].key);
        }
    }

    #[test]
    fn list_pagination_with_start_index() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"content";

        // Create 20 assets
        let assets: Vec<_> = (0..20)
            .map(|i| {
                AssetBuilder::new(format!("/asset{i:02}.txt"), "text/plain")
                    .with_encoding("identity", vec![BODY])
            })
            .collect();

        create_assets(&mut state, &system_context, assets);

        // Get first page
        let first_page = state.list_assets(ListRequest::default());
        assert_eq!(first_page.len(), 20);

        // Get second page starting at index 10
        let second_page = state.list_assets(ListRequest {
            start: Some(Nat::from(10u8)),
            length: None,
        });
        assert_eq!(second_page.len(), 10);

        // Verify no overlap
        let first_page_keys: Vec<_> = first_page.iter().take(10).map(|a| &a.key).collect();
        let second_page_keys: Vec<_> = second_page.iter().map(|a| &a.key).collect();

        for key in &second_page_keys {
            assert!(!first_page_keys.contains(key));
        }

        // Concat the two pages and verify ordering
        let mut combined: Vec<_> = first_page.iter().take(10).collect();
        combined.extend(second_page.iter());

        for i in 0..combined.len() - 1 {
            assert!(
                combined[i].key < combined[i + 1].key,
                "Keys not in order at index {}: {} >= {}",
                i,
                combined[i].key,
                combined[i + 1].key
            );
        }
    }

    #[test]
    fn list_pagination_limits_to_100_assets() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"content";

        // Create 150 assets
        let assets: Vec<_> = (0..150)
            .map(|i| {
                AssetBuilder::new(format!("/asset{i:03}.txt"), "text/plain")
                    .with_encoding("identity", vec![BODY])
            })
            .collect();

        create_assets(&mut state, &system_context, assets);

        // First page should have exactly 100 assets
        let first_page = state.list_assets(ListRequest::default());
        assert_eq!(first_page.len(), 100);

        // Second page starting at 100 should have 50 assets
        let second_page = state.list_assets(ListRequest {
            start: Some(Nat::from(100u8)),
            length: None,
        });
        assert_eq!(second_page.len(), 50);

        // Third page starting at 150 should be empty
        let third_page = state.list_assets(ListRequest {
            start: Some(Nat::from(150u8)),
            length: None,
        });
        assert_eq!(third_page.len(), 0);
    }

    #[test]
    fn list_returns_empty_for_no_assets() {
        let state = State::default();
        let list = state.list_assets(ListRequest::default());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn list_respects_custom_length_limit() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"content";

        // Create 50 assets
        let assets: Vec<_> = (0..50)
            .map(|i| {
                AssetBuilder::new(format!("/asset{i:02}.txt"), "text/plain")
                    .with_encoding("identity", vec![BODY])
            })
            .collect();

        create_assets(&mut state, &system_context, assets);

        // Request only 5 assets
        let list = state.list_assets(ListRequest {
            start: None,
            length: Some(Nat::from(5u8)),
        });
        assert_eq!(list.len(), 5);

        // Request 20 assets starting at index 10
        let list = state.list_assets(ListRequest {
            start: Some(Nat::from(10u8)),
            length: Some(Nat::from(20u8)),
        });
        assert_eq!(list.len(), 20);

        // Request more than available (should return all remaining)
        let list = state.list_assets(ListRequest {
            start: Some(Nat::from(45u8)),
            length: Some(Nat::from(20u8)),
        });
        assert_eq!(list.len(), 5);
    }

    #[test]
    fn list_length_limit_capped_at_page_size() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"content";

        // Create 150 assets
        let assets: Vec<_> = (0..150)
            .map(|i| {
                AssetBuilder::new(format!("/asset{i:03}.txt"), "text/plain")
                    .with_encoding("identity", vec![BODY])
            })
            .collect();

        create_assets(&mut state, &system_context, assets);

        // Request 150 assets, but should be capped at PAGE_SIZE (100)
        let list = state.list_assets(ListRequest {
            start: None,
            length: Some(Nat::from(150u8)),
        });
        assert_eq!(list.len(), 100);

        // Request with length smaller than PAGE_SIZE should be respected
        let list = state.list_assets(ListRequest {
            start: None,
            length: Some(Nat::from(50u8)),
        });
        assert_eq!(list.len(), 50);
    }
}

#[cfg(test)]
mod set_asset_content_sha256_verification {
    use super::*;

    #[test]
    fn verifies_correct_sha256() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const CONTENT: &[u8] = b"Hello, World!";
        let correct_hash = sha2::Sha256::digest(CONTENT);

        // Create asset first
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: None,
                enable_aliasing: None,
            })
            .unwrap();

        // Create batch and chunk
        let batch_id = state.create_batch(&system_context).unwrap();
        let chunk_ids = state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_id.clone(),
                    content: vec![ByteBuf::from(CONTENT)],
                },
                &system_context,
            )
            .unwrap();

        // set_asset_content with correct hash should succeed
        let result = state.set_asset_content(
            SetAssetContentArguments {
                key: "/test.txt".to_string(),
                content_encoding: "identity".to_string(),
                chunk_ids,
                last_chunk: None,
                sha256: Some(ByteBuf::from(correct_hash.as_slice())),
            },
            &system_context,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_incorrect_sha256() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const CONTENT: &[u8] = b"Hello, World!";
        let incorrect_hash = sha2::Sha256::digest(b"Different content");

        // Create asset first
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: None,
                enable_aliasing: None,
            })
            .unwrap();

        // Create batch and chunk
        let batch_id = state.create_batch(&system_context).unwrap();
        let chunk_ids = state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_id.clone(),
                    content: vec![ByteBuf::from(CONTENT)],
                },
                &system_context,
            )
            .unwrap();

        // set_asset_content with incorrect hash should fail
        let result = state.set_asset_content(
            SetAssetContentArguments {
                key: "/test.txt".to_string(),
                content_encoding: "identity".to_string(),
                chunk_ids,
                last_chunk: None,
                sha256: Some(ByteBuf::from(incorrect_hash.as_slice())),
            },
            &system_context,
        );

        assert_eq!(result.unwrap_err(), "sha256 mismatch");
    }

    #[test]
    fn computes_sha256_when_not_provided() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const CONTENT: &[u8] = b"Hello, World!";
        let expected_hash = sha2::Sha256::digest(CONTENT);

        // Create asset first
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: None,
                enable_aliasing: None,
            })
            .unwrap();

        // Create batch and chunk
        let batch_id = state.create_batch(&system_context).unwrap();
        let chunk_ids = state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_id.clone(),
                    content: vec![ByteBuf::from(CONTENT)],
                },
                &system_context,
            )
            .unwrap();

        // set_asset_content without hash should succeed and compute it
        let result = state.set_asset_content(
            SetAssetContentArguments {
                key: "/test.txt".to_string(),
                content_encoding: "identity".to_string(),
                chunk_ids,
                last_chunk: None,
                sha256: None,
            },
            &system_context,
        );

        assert!(result.is_ok());

        // Verify the hash was computed correctly by retrieving the asset
        let retrieved = state
            .get(GetArg {
                key: "/test.txt".to_string(),
                accept_encodings: vec!["identity".to_string()],
            })
            .unwrap();
        assert_eq!(retrieved.sha256.unwrap().as_ref(), expected_hash.as_slice());
    }

    #[test]
    fn verifies_sha256_with_multiple_chunks() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const CHUNK_1: &[u8] = b"Hello, ";
        const CHUNK_2: &[u8] = b"World!";
        let mut hasher = sha2::Sha256::new();
        hasher.update(CHUNK_1);
        hasher.update(CHUNK_2);
        let correct_hash = hasher.finalize();

        // Create asset first
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: None,
                enable_aliasing: None,
            })
            .unwrap();

        // Create batch and chunks
        let batch_id = state.create_batch(&system_context).unwrap();
        let chunk_ids = state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_id.clone(),
                    content: vec![ByteBuf::from(CHUNK_1), ByteBuf::from(CHUNK_2)],
                },
                &system_context,
            )
            .unwrap();

        // set_asset_content with correct hash for combined chunks should succeed
        let result = state.set_asset_content(
            SetAssetContentArguments {
                key: "/test.txt".to_string(),
                content_encoding: "identity".to_string(),
                chunk_ids,
                last_chunk: None,
                sha256: Some(ByteBuf::from(correct_hash.as_slice())),
            },
            &system_context,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn verifies_sha256_with_last_chunk() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const CHUNK_1: &[u8] = b"Hello, ";
        const LAST_CHUNK: &[u8] = b"World!";
        let mut hasher = sha2::Sha256::new();
        hasher.update(CHUNK_1);
        hasher.update(LAST_CHUNK);
        let correct_hash = hasher.finalize();

        // Create asset first
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                max_age: None,
                headers: None,
                allow_raw_access: None,
                enable_aliasing: None,
            })
            .unwrap();

        // Create batch and chunk
        let batch_id = state.create_batch(&system_context).unwrap();
        let chunk_ids = state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_id.clone(),
                    content: vec![ByteBuf::from(CHUNK_1)],
                },
                &system_context,
            )
            .unwrap();

        // set_asset_content with last_chunk and correct hash should succeed
        let result = state.set_asset_content(
            SetAssetContentArguments {
                key: "/test.txt".to_string(),
                content_encoding: "identity".to_string(),
                chunk_ids,
                last_chunk: Some(ByteBuf::from(LAST_CHUNK)),
                sha256: Some(ByteBuf::from(correct_hash.as_slice())),
            },
            &system_context,
        );

        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod compute_state_hash {
    use super::*;

    #[test]
    fn test_compute_state_hash_interruption() {
        let mut state = State::default();
        let system_context = mock_system_context();

        // Setup state
        let batch_id = state.create_batch(&system_context).unwrap();
        let chunk_ids = state
            .create_chunks(
                CreateChunksArg {
                    batch_id: batch_id.clone(),
                    content: vec![ByteBuf::from(b"content1")],
                },
                &system_context,
            )
            .unwrap();

        let args = CommitBatchArguments {
            batch_id: batch_id.clone(),
            operations: vec![
                BatchOperation::CreateAsset(CreateAssetArguments {
                    key: "asset1".to_string(),
                    content_type: "text/plain".to_string(),
                    max_age: None,
                    headers: None,
                    enable_aliasing: None,
                    allow_raw_access: None,
                }),
                BatchOperation::SetAssetContent(SetAssetContentArguments {
                    key: "asset1".to_string(),
                    content_encoding: "identity".to_string(),
                    chunk_ids,
                    last_chunk: None,
                    sha256: None,
                }),
            ],
        };
        run_computation_until_completion(|progress| {
            state.commit_batch(&args, progress, &system_context)
        })
        .unwrap();

        // Reset computation
        run_computation_until_completion(|_progress| state.compute_state_hash()).unwrap(); // Ensure it's done or started

        // Update state using commit_batch to ensure timestamp is updated
        // We need a new system context with a later timestamp
        let canister_env = crate::system_context::CanisterEnv {
            ic_root_key: vec![0, 1, 2, 3],
            icp_public_env_vars: BTreeMap::new(),
        };
        let system_context_later =
            crate::system_context::SystemContext::new_with_options(Some(canister_env), 200);

        let batch_id = state.create_batch(&system_context_later).unwrap();
        let args = CommitBatchArguments {
            batch_id: batch_id.clone(),
            operations: vec![BatchOperation::CreateAsset(CreateAssetArguments {
                key: "asset2".to_string(),
                content_type: "text/plain".to_string(),
                max_age: None,
                headers: None,
                enable_aliasing: None,
                allow_raw_access: None,
            })],
        };
        run_computation_until_completion(|progress| {
            state.commit_batch(&args, progress, &system_context_later)
        })
        .unwrap();

        // Since the new API doesn't allow controlling instruction counter per call,
        // we can't easily test interruption. This test now just verifies completion.
        let result = run_computation_until_completion(|_progress| state.compute_state_hash());
        assert!(result.is_ok());

        // Verify we can call it again
        let result = run_computation_until_completion(|_progress| state.compute_state_hash());
        assert!(result.is_ok());
    }
}

mod redirect_rules {
    use super::*;
    use crate::redirect::{RedirectRule, RulePattern};
    use crate::types::SetRedirectRulesArguments;

    fn commit(state: &mut State, ops: Vec<BatchOperation>) -> Result<(), String> {
        let system_context = mock_system_context();
        let batch_id = state.create_batch(&system_context).unwrap();
        run_computation_until_completion(|progress| {
            state.commit_batch(
                &CommitBatchArguments {
                    batch_id: batch_id.clone(),
                    operations: ops.clone(),
                },
                progress,
                &system_context,
            )
        })
    }

    fn sample_rules() -> Vec<RedirectRule> {
        vec![
            RedirectRule {
                from: RulePattern::Exact("/old".into()),
                to: "/new".into(),
                status: 301,
                headers: None,
            },
            RedirectRule {
                from: RulePattern::Subtree("/legacy/".into()),
                to: "/home".into(),
                status: 308,
                headers: Some(vec![("X-Reason".into(), "moved".into())]),
            },
        ]
    }

    #[test]
    fn commit_set_redirect_rules_round_trips_through_get() {
        let mut state = State::default();
        let rules = sample_rules();

        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: rules.clone(),
            })],
        )
        .unwrap();

        assert_eq!(state.get_redirect_rules(), rules);
    }

    #[test]
    fn invalid_rule_fails_op_without_mutating_state() {
        let mut state = State::default();
        // Seed an initial valid set so we can confirm it is preserved.
        let initial = vec![RedirectRule {
            from: RulePattern::Exact("/seed".into()),
            to: "/dest".into(),
            status: 301,
            headers: None,
        }];
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: initial.clone(),
            })],
        )
        .unwrap();

        // One valid + one invalid (status 418) — the whole op must fail.
        let mixed = vec![
            RedirectRule {
                from: RulePattern::Exact("/a".into()),
                to: "/b".into(),
                status: 301,
                headers: None,
            },
            RedirectRule {
                from: RulePattern::Exact("/c".into()),
                to: "/d".into(),
                status: 418,
                headers: None,
            },
        ];
        let err = commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: mixed,
            })],
        )
        .unwrap_err();
        assert!(err.contains("unsupported status code"), "got: {err}");

        assert_eq!(
            state.get_redirect_rules(),
            initial,
            "rules must be unchanged after a failed SetRedirectRules"
        );
    }

    #[test]
    fn rules_persist_through_upgrade() {
        let mut state = State::default();
        let rules = sample_rules();

        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: rules.clone(),
            })],
        )
        .unwrap();

        let stable: StableState = state.into();
        let state: State = stable.into();

        assert_eq!(state.get_redirect_rules(), rules);
    }

    #[test]
    fn empty_rules_replace_existing() {
        let mut state = State::default();

        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: sample_rules(),
            })],
        )
        .unwrap();
        assert!(!state.get_redirect_rules().is_empty());

        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![],
            })],
        )
        .unwrap();
        assert!(state.get_redirect_rules().is_empty());
    }

    #[test]
    fn exact_3xx_rule_serves_redirect_with_certificate() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/old".into()),
                    to: "/new".into(),
                    status: 301,
                    headers: None,
                }],
            })],
        )
        .unwrap();

        let response = certified_http_request(&state, RequestBuilder::get("/old").build());
        assert_eq!(response.status_code, 301);
        assert_eq!(lookup_header(&response, "Location"), Some("/new"));
    }

    #[test]
    fn subtree_3xx_rule_fires_for_descendants_and_verifies() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Subtree("/legacy/".into()),
                    to: "/home".into(),
                    status: 308,
                    headers: None,
                }],
            })],
        )
        .unwrap();

        let response =
            certified_http_request(&state, RequestBuilder::get("/legacy/anything/here").build());
        assert_eq!(response.status_code, 308);
        assert_eq!(lookup_header(&response, "Location"), Some("/home"));
    }

    #[test]
    fn rule_4xx_404_and_410_serve_certified_bodies() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![
                    RedirectRule {
                        from: RulePattern::Exact("/missing.html".into()),
                        to: String::new(),
                        status: 404,
                        headers: None,
                    },
                    RedirectRule {
                        from: RulePattern::Exact("/gone".into()),
                        to: String::new(),
                        status: 410,
                        headers: None,
                    },
                ],
            })],
        )
        .unwrap();

        let not_found =
            certified_http_request(&state, RequestBuilder::get("/missing.html").build());
        assert_eq!(not_found.status_code, 404);
        assert_eq!(not_found.body.as_ref(), b"Not Found");

        let gone = certified_http_request(&state, RequestBuilder::get("/gone").build());
        assert_eq!(gone.status_code, 410);
        assert_eq!(gone.body.as_ref(), b"Gone");
    }

    #[test]
    fn first_match_wins_across_multiple_3xx_rules() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![
                    RedirectRule {
                        from: RulePattern::Exact("/dup".into()),
                        to: "/first".into(),
                        status: 301,
                        headers: None,
                    },
                    RedirectRule {
                        from: RulePattern::Exact("/dup".into()),
                        to: "/second".into(),
                        status: 302,
                        headers: None,
                    },
                ],
            })],
        )
        .unwrap();

        let response = certified_http_request(&state, RequestBuilder::get("/dup").build());
        assert_eq!(response.status_code, 301);
        assert_eq!(lookup_header(&response, "Location"), Some("/first"));
    }

    #[test]
    fn rules_survive_post_upgrade_and_witnesses_still_validate() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: sample_rules(),
            })],
        )
        .unwrap();
        // Sanity: rules fire pre-upgrade.
        let pre =
            certified_http_request(&state, RequestBuilder::get("/legacy/anything").build());
        assert_eq!(pre.status_code, 308);

        let stable: StableState = state.into();
        let state: State = stable.into();

        let post =
            certified_http_request(&state, RequestBuilder::get("/legacy/anything").build());
        assert_eq!(post.status_code, 308);
        assert_eq!(lookup_header(&post, "Location"), Some("/home"));
    }

    #[test]
    fn status_200_target_coupling() {
        // Install rule before the target exists → rule is inert.
        let mut state = State::default();
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/foo".into()),
                    to: "/foo.html".into(),
                    status: 200,
                    headers: None,
                }],
            })],
        )
        .unwrap();
        let inert =
            state.http_request(RequestBuilder::get("/foo").build(), &[], unused_callback());
        assert_eq!(inert.status_code, 404);

        // Add the asset → rule fires.
        const BODY_V1: &[u8] = b"<!DOCTYPE html><html>v1</html>";
        create_assets(
            &mut state,
            &mock_system_context(),
            vec![AssetBuilder::new("/foo.html", "text/html")
                .with_encoding("identity", vec![BODY_V1])],
        );
        let v1 = certified_http_request(&state, RequestBuilder::get("/foo").build());
        assert_eq!(v1.status_code, 200);
        assert_eq!(v1.body.as_ref(), BODY_V1);

        // Modify the asset → rule still fires with the new content.
        const BODY_V2: &[u8] = b"<!DOCTYPE html><html>v2 different</html>";
        create_assets(
            &mut state,
            &mock_system_context(),
            vec![AssetBuilder::new("/foo.html", "text/html")
                .with_encoding("identity", vec![BODY_V2])],
        );
        let v2 = certified_http_request(&state, RequestBuilder::get("/foo").build());
        assert_eq!(v2.body.as_ref(), BODY_V2);

        // Delete the target → rule goes inert again.
        delete_asset_via_batch(&mut state, "/foo.html");
        let after_delete = state.http_request(
            RequestBuilder::get("/foo").build(),
            &[],
            unused_callback(),
        );
        assert_eq!(after_delete.status_code, 404);
    }

    fn delete_asset_via_batch(state: &mut State, key: &str) {
        commit(
            state,
            vec![BatchOperation::DeleteAsset(DeleteAssetArguments {
                key: key.to_string(),
            })],
        )
        .unwrap();
    }

    #[test]
    fn asset_shadows_exact_rule_at_same_path() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const RULE_TARGET: &[u8] = b"rule-target";
        const SOURCE_ASSET: &[u8] = b"source-asset";
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/bar.html", "text/html")
                .with_encoding("identity", vec![RULE_TARGET])],
        );
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/foo".into()),
                    to: "/bar.html".into(),
                    status: 200,
                    headers: None,
                }],
            })],
        )
        .unwrap();

        // Without an asset at /foo, the rule fires.
        let via_rule = certified_http_request(&state, RequestBuilder::get("/foo").build());
        assert_eq!(via_rule.body.as_ref(), RULE_TARGET);

        // Upload an asset at /foo → asset wins.
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/foo", "text/html")
                .with_encoding("identity", vec![SOURCE_ASSET])],
        );
        let via_asset = certified_http_request(&state, RequestBuilder::get("/foo").build());
        assert_eq!(via_asset.body.as_ref(), SOURCE_ASSET);

        // Delete the source asset → rule reappears.
        delete_asset_via_batch(&mut state, "/foo");
        let back_to_rule = certified_http_request(&state, RequestBuilder::get("/foo").build());
        assert_eq!(back_to_rule.body.as_ref(), RULE_TARGET);
    }

    #[test]
    fn subtree_200_rule_fires_for_unshadowed_children() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>index</html>";
        const REAL_BODY: &[u8] = b"<!DOCTYPE html><html>real</html>";
        create_assets(
            &mut state,
            &system_context,
            vec![
                AssetBuilder::new("/index.html", "text/html")
                    .with_encoding("identity", vec![INDEX_BODY]),
                AssetBuilder::new("/real-page", "text/html")
                    .with_encoding("identity", vec![REAL_BODY]),
            ],
        );
        commit(
            &mut state,
            vec![BatchOperation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Subtree("/".into()),
                    to: "/index.html".into(),
                    status: 200,
                    headers: None,
                }],
            })],
        )
        .unwrap();

        // Real asset still wins for its own path.
        let real = certified_http_request(&state, RequestBuilder::get("/real-page").build());
        assert_eq!(real.body.as_ref(), REAL_BODY);

        // Unshadowed path falls back to the rule → /index.html content.
        let fallback = certified_http_request(&state, RequestBuilder::get("/anything").build());
        assert_eq!(fallback.body.as_ref(), INDEX_BODY);
    }
}
