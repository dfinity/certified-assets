use crate::http::{
    CallbackFunc, HttpRequest, HttpResponse, StreamingCallbackToken, StreamingStrategy,
};
use crate::state::State;
use crate::sync::{ComputationStatus, SYNC_IDLE_TIMEOUT_NANOS};
use crate::system_context::SystemContext;
use crate::types::{
    CreateAssetArguments, DeleteAssetArguments, Encoding, ExecuteOperationsArguments, Operation,
    SessionId, SetAssetContentArguments, SetAssetHeadersArguments, StartSyncResult,
};
use crate::url::{url_decode, UrlDecodeError};
use crate::UploadChunksArguments;
use candid::{Nat, Principal};
use ic_certification_testing::CertificateBuilder;
use ic_crypto_tree_hash::Digest;
use ic_http_certification::{Method, StatusCode};
use ic_response_verification_test_utils::{
    base64_encode, create_canister_id, get_current_timestamp,
};
use ic_stable_structures::DefaultMemoryImpl;
use serde_bytes::ByteBuf;
use sha2::Digest as Sha2Digest;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

// from ic-response-verification tests
const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

fn some_principal() -> Principal {
    Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap()
}

fn unused_callback() -> CallbackFunc {
    CallbackFunc::new(some_principal(), "unused".to_string())
}

/// Simulates a canister upgrade: drop the live `State` and rebuild a fresh one
/// over the same stable memory, running the post-upgrade derived-state rebuild —
/// exactly what the canister's `post_upgrade` does. Off-wasm `DefaultMemoryImpl`
/// is a shared `Rc<RefCell<Vec<u8>>>` handle, so the rebuilt state reads back the
/// data the original persisted. Roundtrip tests build their `State` with
/// `State::new(memory.clone())` so they can hand the same handle here.
fn upgrade(state: State, memory: DefaultMemoryImpl) -> State {
    drop(state);
    let mut restored = State::new(memory);
    restored.post_upgrade_rebuild();
    restored
}

fn mock_system_context() -> SystemContext {
    SystemContext::new_with_options(100_000_000_000)
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
    encodings: Vec<(Encoding, Vec<ByteBuf>)>,
    headers: Vec<(String, String)>,
}

impl AssetBuilder {
    fn new(name: impl AsRef<str>, content_type: impl AsRef<str>) -> Self {
        Self {
            name: name.as_ref().to_string(),
            content_type: content_type.as_ref().to_string(),
            encodings: vec![],
            headers: vec![],
        }
    }

    fn with_encoding(mut self, name: impl AsRef<str>, chunks: Vec<impl AsRef<[u8]>>) -> Self {
        let encoding = Encoding::from_token(name.as_ref())
            .unwrap_or_else(|| panic!("unsupported test encoding {:?}", name.as_ref()));
        self.encodings.push((
            encoding,
            chunks
                .into_iter()
                .map(|c| ByteBuf::from(c.as_ref().to_vec()))
                .collect(),
        ));
        self
    }

    fn with_header(mut self, header_key: &str, header_value: &str) -> Self {
        self.headers
            .push((header_key.to_string(), header_value.to_string()));
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

/// Starts a sync and returns its session id, panicking if the canister reports
/// `Busy` (no concurrent sync is expected in these single-threaded tests).
fn start_session(state: &mut State, ctx: &SystemContext) -> SessionId {
    match state.start_sync(some_principal(), ctx) {
        StartSyncResult::Started { session_id } => session_id,
        other => panic!("expected Started, got {other:?}"),
    }
}

/// Runs `operations` to completion in a single finalizing `execute_operations`
/// (`is_final: true`), the way a small sync would.
fn execute_all(
    state: &mut State,
    session_id: SessionId,
    operations: Vec<Operation>,
    ctx: &SystemContext,
) {
    run_computation_until_completion(|progress| {
        state.execute_operations(
            &ExecuteOperationsArguments {
                session_id,
                operations: operations.clone(),
                is_final: true,
            },
            progress,
            ctx,
        )
    })
    .unwrap();
}

fn create_assets(
    state: &mut State,
    system_context: &SystemContext,
    assets: Vec<AssetBuilder>,
) -> SessionId {
    let session_id = start_session(state, system_context);

    let operations = assemble_create_assets_and_set_contents_operations(
        state,
        system_context,
        assets,
        session_id,
    );

    execute_all(state, session_id, operations, system_context);

    session_id
}

fn assemble_create_assets_and_set_contents_operations(
    state: &mut State,
    system_context: &SystemContext,
    assets: Vec<AssetBuilder>,
    session_id: SessionId,
) -> Vec<Operation> {
    let mut operations = vec![];

    for asset in assets {
        if state.contains_asset(&asset.name) {
            operations.push(Operation::DeleteAsset(DeleteAssetArguments {
                key: asset.name.clone(),
            }));
        }
        operations.push(Operation::CreateAsset(CreateAssetArguments {
            key: asset.name.clone(),
            content_type: asset.content_type,
            headers: asset.headers,
        }));

        for (enc, chunks) in asset.encodings {
            // Chunk ids are not returned; they're the slot indices the canister
            // assigns in upload order. Mirror that: ids run from the current
            // staging length for as many chunks as we upload.
            let base = state.chunks.len() as u64;
            let chunk_ids: Vec<u64> = (base..base + chunks.len() as u64).collect();
            let mut hasher = sha2::Sha256::new();
            for chunk in &chunks {
                hasher.update(chunk);
            }
            let sha256 = ByteBuf::from(hasher.finalize().to_vec());
            state
                .upload_chunks(UploadChunksArguments { session_id, chunks }, system_context)
                .unwrap();

            operations.push(Operation::SetAssetContent({
                SetAssetContentArguments {
                    key: asset.name.clone(),
                    encoding: enc,
                    chunk_ids,
                    sha256,
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

#[test]
fn can_create_assets_using_batch_api() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    let session_id = create_assets(
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

    // The finalizing execute_operations ended the sync, so the session id is no
    // longer valid for further chunk uploads.
    let error_msg = state
        .upload_chunks(
            UploadChunksArguments {
                session_id,
                chunks: vec![ByteBuf::new()],
            },
            &system_context,
        )
        .unwrap_err();

    let expected = "no active sync";
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
    const BROTLI_BODY: &[u8] = b"this is 'brotli' content";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![IDENTITY_BODY])
                .with_encoding("gzip", vec![GZIP_BODY])
                .with_encoding("br", vec![BROTLI_BODY]),
            AssetBuilder::new("/no-encoding.html", "text/html"),
        ],
    );

    // Identity is served verbatim and carries NO `content-encoding` header (the
    // `identity` token is not a valid response value).
    let identity_response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(identity_response.status_code, 200);
    assert_eq!(identity_response.body.as_ref(), IDENTITY_BODY);
    assert_eq!(lookup_header(&identity_response, "content-encoding"), None);
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
    assert_eq!(
        lookup_header(&gzip_response, "content-encoding"),
        Some("gzip")
    );
    assert!(lookup_header(&gzip_response, "IC-Certificate").is_some());

    // Brotli is selected and labelled `br`, including from a weighted, multi-coding
    // Accept-Encoding header (the `;q=` parsing that previously matched nothing).
    let brotli_response = certified_http_request(
        &state,
        RequestBuilder::get("/contents.html")
            .with_header("Accept-Encoding", "br;q=1.0, gzip;q=0.8")
            .with_certificate_version(2)
            .build(),
    );
    assert_eq!(brotli_response.status_code, 200);
    assert_eq!(brotli_response.body.as_ref(), BROTLI_BODY);
    assert_eq!(
        lookup_header(&brotli_response, "content-encoding"),
        Some("br")
    );
    assert!(lookup_header(&brotli_response, "IC-Certificate").is_some());

    // An asset with no encodings has nothing to serve → the built-in certified
    // 404 (no rule occupies `<*>`, so the fallback is certified there).
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
fn serve_fallback_via_rule() {
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

    // SPA-style catch-all: a single root subtree rule replaces what used to
    // be the built-in `FALLBACK_FILE` mechanism.
    set_root_spa_rule(&mut state, "/index.html");

    let identity_response = certified_http_request(
        &state,
        RequestBuilder::get("/index.html")
            .with_header("Accept-Encoding", "identity")
            .with_certificate_version(2)
            .build(),
    );
    let certificate_header = lookup_header(&identity_response, "IC-Certificate").unwrap();

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
    // The rule lives at the root `<*>`, matching the previous built-in
    // fallback's expr_path.
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

fn set_root_spa_rule(state: &mut State, target: &str) {
    use crate::redirect::{RedirectRule, RulePattern};
    use crate::types::SetRedirectRulesArguments;
    let system_context = mock_system_context();
    let session_id = start_session(state, &system_context);
    let ops = vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
        rules: vec![RedirectRule {
            from: RulePattern::Subtree("/".into()),
            to: target.into(),
            status: 200,
            headers: vec![],
        }],
    })];
    execute_all(state, session_id, ops, &system_context);
}

fn set_exact_rewrite_rule(state: &mut State, from: &str, to: &str) {
    set_exact_rewrite_rules(state, &[(from, to)]);
}

fn set_exact_rewrite_rules(state: &mut State, pairs: &[(&str, &str)]) {
    use crate::redirect::{RedirectRule, RulePattern};
    use crate::types::SetRedirectRulesArguments;
    let system_context = mock_system_context();
    let session_id = start_session(state, &system_context);
    let rules = pairs
        .iter()
        .map(|(from, to)| RedirectRule {
            from: RulePattern::Exact((*from).into()),
            to: (*to).into(),
            status: 200,
            headers: vec![],
        })
        .collect();
    let ops = vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
        rules,
    })];
    execute_all(state, session_id, ops, &system_context);
}

#[test]
fn second_sync_rejected_while_first_is_active() {
    // A different principal cannot start a sync while another's is in progress
    // and not yet stale.
    let mut state = State::default();
    let system_context = mock_system_context();

    let owner_a = some_principal();
    let owner_b = Principal::from_text("aaaaa-aa").unwrap();
    assert_ne!(owner_a, owner_b);

    let StartSyncResult::Started { .. } = state.start_sync(owner_a, &system_context) else {
        panic!("first start_sync should succeed");
    };

    match state.start_sync(owner_b, &system_context) {
        StartSyncResult::Busy { owner, .. } => assert_eq!(owner, owner_a),
        other => panic!("expected Busy, got {other:?}"),
    }
}

#[test]
fn owner_can_reclaim_their_own_sync_immediately() {
    // The same principal restarting (e.g. retrying a failed deploy) reclaims
    // its own non-stale sync and gets a fresh, monotonically larger id.
    let mut state = State::default();
    let system_context = mock_system_context();
    let owner = some_principal();

    let id1 = start_session(&mut state, &system_context);
    let id2 = match state.start_sync(owner, &system_context) {
        StartSyncResult::Started { session_id } => session_id,
        other => panic!("expected Started, got {other:?}"),
    };
    assert!(id2 > id1, "session ids must be monotonic: {id2} > {id1}");
}

#[test]
fn stale_sync_can_be_reclaimed_by_another_principal() {
    // After the idle timeout, a different principal may take over an abandoned
    // sync. Reclaiming clears the previous session's staged chunks.
    let mut state = State::default();
    let mut system_context = mock_system_context();
    let owner_b = Principal::from_text("aaaaa-aa").unwrap();

    let id1 = start_session(&mut state, &system_context);

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    state
        .upload_chunks(
            UploadChunksArguments {
                session_id: id1,
                chunks: vec![ByteBuf::from(BODY.to_vec())],
            },
            &system_context,
        )
        .unwrap();
    assert!(!state.chunks.is_empty(), "chunk should be staged");

    // Advance past the idle timeout, then a different principal reclaims it.
    system_context.current_timestamp_ns += SYNC_IDLE_TIMEOUT_NANOS + 1;
    match state.start_sync(owner_b, &system_context) {
        StartSyncResult::Started { session_id } => assert!(session_id > id1),
        other => panic!("expected Started, got {other:?}"),
    }
    assert!(
        state.chunks.is_empty(),
        "reclaim must drop the previous session's chunks"
    );

    // The old session id is no longer valid.
    let err = state
        .upload_chunks(
            UploadChunksArguments {
                session_id: id1,
                chunks: vec![ByteBuf::from(BODY.to_vec())],
            },
            &system_context,
        )
        .unwrap_err();
    assert!(err.contains("no active sync"), "got: {err}");
}

#[test]
fn active_sync_idle_clock_resets_on_each_call() {
    // Staleness is measured from the last call, not from sync start: a deploy
    // that keeps making calls must never become reclaimable, however long it
    // runs in total. Without the touch_session reset a different principal
    // could steal an actively-progressing sync mid-flight.
    let mut state = State::default();
    let mut system_context = mock_system_context();
    let owner_b = Principal::from_text("aaaaa-aa").unwrap();

    let session_id = start_session(&mut state, &system_context);

    // Advance to just under the timeout, then make a call that touches the
    // session and resets its idle clock.
    system_context.current_timestamp_ns += SYNC_IDLE_TIMEOUT_NANOS - 1;
    state
        .upload_chunks(
            UploadChunksArguments {
                session_id,
                chunks: vec![ByteBuf::from(b"x".to_vec())],
            },
            &system_context,
        )
        .unwrap();

    // Advance again by just under the timeout. Total elapsed since start now
    // far exceeds the timeout, but only `TIMEOUT - 1` has passed since the
    // last call, so the sync is still active and a different principal is
    // refused rather than allowed to reclaim it.
    system_context.current_timestamp_ns += SYNC_IDLE_TIMEOUT_NANOS - 1;
    match state.start_sync(owner_b, &system_context) {
        StartSyncResult::Busy { owner, .. } => assert_eq!(owner, some_principal()),
        other => panic!("expected Busy while the sync is being actively touched, got {other:?}"),
    }
}

#[test]
fn reclaim_boundary_is_inclusive_at_the_idle_timeout() {
    // The reclaim guard is `idle >= SYNC_IDLE_TIMEOUT_NANOS`: a different
    // principal is refused one nanosecond before the timeout and reclaims at
    // exactly the timeout.
    let owner_b = Principal::from_text("aaaaa-aa").unwrap();

    // Just under the timeout: still Busy.
    {
        let mut state = State::default();
        let mut system_context = mock_system_context();
        start_session(&mut state, &system_context);
        system_context.current_timestamp_ns += SYNC_IDLE_TIMEOUT_NANOS - 1;
        match state.start_sync(owner_b, &system_context) {
            StartSyncResult::Busy { .. } => {}
            other => panic!("expected Busy one ns before the timeout, got {other:?}"),
        }
    }

    // Exactly at the timeout: reclaimable.
    {
        let mut state = State::default();
        let mut system_context = mock_system_context();
        let id1 = start_session(&mut state, &system_context);
        system_context.current_timestamp_ns += SYNC_IDLE_TIMEOUT_NANOS;
        match state.start_sync(owner_b, &system_context) {
            StartSyncResult::Started { session_id } => assert!(session_id > id1),
            other => panic!("expected Started at exactly the timeout, got {other:?}"),
        }
    }
}

#[test]
fn busy_reports_holders_idle_seconds() {
    // The Busy variant reports how long the holder has been idle, in whole
    // seconds (sub-second nanos truncated toward zero).
    let mut state = State::default();
    let mut system_context = mock_system_context();
    let owner_b = Principal::from_text("aaaaa-aa").unwrap();

    start_session(&mut state, &system_context);

    // 5.5s of idle time, still under the timeout; the reported value truncates
    // to whole seconds.
    system_context.current_timestamp_ns += 5_500_000_000;
    match state.start_sync(owner_b, &system_context) {
        StartSyncResult::Busy {
            owner,
            idle_for_secs,
        } => {
            assert_eq!(owner, some_principal());
            assert_eq!(idle_for_secs, 5);
        }
        other => panic!("expected Busy, got {other:?}"),
    }
}

#[test]
fn returns_index_file_for_missing_assets_via_rule() {
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
    // Without a rule the canister no longer auto-falls-back to /index.html.
    set_root_spa_rule(&mut state, "/index.html");

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
fn no_implicit_aliasing_without_rules() {
    let mut state = State::default();
    let system_context = mock_system_context();
    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/foo.html", "text/html").with_encoding("identity", vec![BODY]),
            AssetBuilder::new("/blog/index.html", "text/html")
                .with_encoding("identity", vec![BODY]),
        ],
    );

    for missing in &["/foo", "/foo/", "/blog", "/blog/"] {
        let response = state.http_request(
            RequestBuilder::get(*missing).build(),
            &[],
            unused_callback(),
        );
        assert_eq!(
            response.status_code, 404,
            "expected 404 for {missing}, got {}",
            response.status_code
        );
    }
    let response = certified_http_request(&state, RequestBuilder::get("/foo.html").build());
    assert_eq!(response.status_code, 200);
}

#[test]
fn preserves_state_on_stable_roundtrip() {
    let memory = DefaultMemoryImpl::default();
    let mut state = State::new(memory.clone());
    let system_context = mock_system_context();

    const INDEX_BODY: &[u8] = b"<!DOCTYPE html><html>Index</html>";

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/index.html", "text/html")
            .with_encoding("identity", vec![INDEX_BODY])],
    );

    let state = upgrade(state, memory.clone());

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
fn authorize_and_deauthorize_toggle_membership() {
    let mut state = State::default();
    let p = some_principal();

    assert!(!state.is_authorized(&p));

    state.authorize(p);
    assert!(state.is_authorized(&p));
    assert_eq!(state.list_authorized(), vec![p]);

    // Re-authorizing is idempotent (set semantics).
    state.authorize(p);
    assert_eq!(state.list_authorized().len(), 1);

    state.deauthorize(&p);
    assert!(!state.is_authorized(&p));
    assert!(state.list_authorized().is_empty());
}

#[test]
fn authorized_set_survives_stable_roundtrip() {
    let memory = DefaultMemoryImpl::default();
    let mut state = State::new(memory.clone());
    let p = some_principal();
    state.authorize(p);

    let restored = upgrade(state, memory.clone());

    assert!(restored.is_authorized(&p));
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

    // A token carrying the wrong hash is rejected.
    assert_eq!(
        state
            .http_request_streaming_callback(StreamingCallbackToken {
                key: "/index.html".to_string(),
                encoding: Encoding::Identity,
                index: Nat::from(1_u8),
                sha256: ByteBuf::from([0u8; 32].as_slice()),
            })
            .unwrap_err(),
        "sha256 mismatch"
    );

    let streaming_response = state.http_request_streaming_callback(token).unwrap();
    assert_eq!(streaming_response.body.as_ref(), INDEX_BODY_CHUNK_2);
    assert!(
        streaming_response.token.is_none(),
        "Unexpected streaming response: {streaming_response:?}"
    );
}

#[test]
fn supports_cache_control_via_headers() {
    let mut state = State::default();
    let system_context = mock_system_context();

    const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

    create_assets(
        &mut state,
        &system_context,
        vec![
            AssetBuilder::new("/contents.html", "text/html").with_encoding("identity", vec![BODY]),
            AssetBuilder::new("/cached.html", "text/html")
                .with_header("Cache-Control", "max-age=604800")
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
        RequestBuilder::get("/cached.html")
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
            AssetBuilder::new("/other.html", "text/html")
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
        RequestBuilder::get("/other.html")
            .with_header("Accept-Encoding", "gzip,identity")
            .build(),
    );

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body.as_ref(), BODY);
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
fn supports_getting_and_setting_asset_headers() {
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
            AssetBuilder::new("/props.html", "text/html")
                .with_encoding("identity", vec![BODY])
                .with_header("X-Content-Type-Options", "nosniff"),
        ],
    );

    // Headers are reported by `list`, so read them back from there rather than
    // through a dedicated per-asset query.
    let headers_of = |state: &State, key: &str| {
        state
            .get_asset_details(None)
            .into_iter()
            .find(|d| d.key == key)
            .expect("asset should exist")
            .headers
    };

    assert_eq!(
        headers_of(&state, "/contents.html"),
        vec![("Access-Control-Allow-Origin".to_string(), "*".to_string())],
    );
    assert_eq!(
        headers_of(&state, "/props.html"),
        vec![("X-Content-Type-Options".to_string(), "nosniff".to_string())],
    );

    // A non-empty `headers` replaces the headers map.
    assert!(state
        .set_asset_headers(SetAssetHeadersArguments {
            key: "/props.html".into(),
            headers: vec![("new-header".into(), "value".into())],
        })
        .is_ok());
    assert_eq!(
        headers_of(&state, "/props.html"),
        vec![("new-header".to_string(), "value".to_string())],
    );

    // An empty `headers` clears the headers map.
    assert!(state
        .set_asset_headers(SetAssetHeadersArguments {
            key: "/props.html".into(),
            headers: vec![],
        })
        .is_ok());
    assert!(headers_of(&state, "/props.html").is_empty());
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
                headers: vec![],
            })
            .unwrap_err()
            == "asset already exists"
    );
}

#[test]
fn aliases_via_explicit_rules() {
    // Migrated from `support_aliases`: what used to be built-in `.html` /
    // `index.html` aliasing is now expressed as user-supplied 200 rules.
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
    set_exact_rewrite_rules(
        &mut state,
        &[
            ("/contents", "/contents.html"),
            ("/", "/index.html"),
            ("/subdirectory/index", "/subdirectory/index.html"),
            ("/subdirectory/", "/subdirectory/index.html"),
            ("/subdirectory", "/subdirectory/index.html"),
        ],
    );

    let normal_request =
        certified_http_request(&state, RequestBuilder::get("/contents.html").build());
    assert_eq!(normal_request.body.as_ref(), FILE_BODY);

    let alias_add_html = certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(alias_add_html.body.as_ref(), FILE_BODY);

    let root_alias = certified_http_request(&state, RequestBuilder::get("/").build());
    assert_eq!(root_alias.body.as_ref(), INDEX_BODY);

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
fn rule_aliasing_persists_through_upgrade() {
    // Migrated from `alias_behavior_persists_through_upgrade`: rules survive
    // the upgrade and serve correctly afterward.
    let memory = DefaultMemoryImpl::default();
    let mut state = State::new(memory.clone());
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
    // No rule for /contents → no alias to /contents.html (used to be the
    // "aliasing disabled" path); still install one for the subdirectory.
    set_exact_rewrite_rule(&mut state, "/subdirectory", "/subdirectory/index.html");

    let no_alias = state.http_request(
        RequestBuilder::get("/contents").build(),
        &[],
        unused_callback(),
    );
    assert_eq!(no_alias.status_code, 404);

    let other = certified_http_request(&state, RequestBuilder::get("/subdirectory").build());
    assert_eq!(other.body.as_ref(), SUBDIR_INDEX_BODY);

    let state = upgrade(state, memory.clone());

    let no_alias = state.http_request(
        RequestBuilder::get("/contents").build(),
        &[],
        unused_callback(),
    );
    assert_eq!(no_alias.status_code, 404);
    let other = certified_http_request(&state, RequestBuilder::get("/subdirectory").build());
    assert_eq!(other.body.as_ref(), SUBDIR_INDEX_BODY);
}

#[test]
fn rule_aliasing_name_clash() {
    // Migrated from `aliasing_name_clash`: an asset at the rule's source
    // shadows the rule.
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
    set_exact_rewrite_rule(&mut state, "/contents", "/contents.html");

    let via_rule = certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(via_rule.body.as_ref(), FILE_BODY);

    create_assets(
        &mut state,
        &system_context,
        vec![AssetBuilder::new("/contents", "text/html")
            .with_encoding("identity", vec![FILE_BODY_2])],
    );

    let asset_wins = certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(asset_wins.body.as_ref(), FILE_BODY_2);

    state.delete_asset(DeleteAssetArguments {
        key: "/contents".to_string(),
    });
    state.on_redirect_rules_change();

    let rule_visible_again =
        certified_http_request(&state, RequestBuilder::get("/contents").build());
    assert_eq!(rule_visible_again.body.as_ref(), FILE_BODY);
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
        // `Some(value)` certifies a `content-encoding` header (a real encoding,
        // e.g. `Encoding::Gzip.header_name()` == `Some("gzip")`).
        let c = build_ic_certificate_expression_from_headers_and_encoding(&h, Some("gzip"));
        assert_eq!(
            c.expression,
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "a", "b", "c"]}}}})"#
        );
        // `None` — which identity maps to via `Encoding::header_name` —
        // omits the `content-encoding` header.
        let c2 = build_ic_certificate_expression_from_headers_and_encoding(&h, None);
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
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "Access-Control-Allow-Origin"]}}}})"#,
            "Missing ic-certifiedexpression header in response: {response:#?}",
        );
    }

    #[test]
    fn ic_certificate_expression_gets_updated_on_asset_headers_update() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("gzip", vec![BODY])
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
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "Access-Control-Allow-Origin"]}}}})"#,
            "Missing ic-certificateexpression header in response: {response:#?}",
        );

        state
            .set_asset_headers(SetAssetHeadersArguments {
                key: "/contents.html".into(),
                headers: vec![("custom-header".into(), "value".into())],
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
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "custom-header"]}}}})"#,
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
mod get_asset_details {
    use super::*;

    #[test]
    fn list_starts_from_beginning_when_no_cursor() {
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

        // `None` lists from the beginning, ordered by key.
        let list = state.get_asset_details(None);
        assert_eq!(list.len(), 10);
        for i in 0..9 {
            assert!(list[i].key < list[i + 1].key);
        }
    }

    #[test]
    fn list_start_after_is_exclusive() {
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

        // All 20 fit in a single page.
        let first_page = state.get_asset_details(None);
        assert_eq!(first_page.len(), 20);

        // Resume strictly after the 10th key. The cursor is exclusive, so this
        // returns the remaining 10 assets and never the cursor key itself.
        let cursor = first_page[9].key.clone();
        let second_page = state.get_asset_details(Some(cursor.clone()));
        assert_eq!(second_page.len(), 10);
        assert!(second_page.iter().all(|a| a.key > cursor));

        // Concatenating the first 10 with the resumed page reproduces the order.
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
    fn list_pages_are_capped_at_page_size() {
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

        // First page holds exactly PAGE_SIZE (100).
        let first_page = state.get_asset_details(None);
        assert_eq!(first_page.len(), 100);

        // Resuming after the 100th key yields the remaining 50.
        let second_page = state.get_asset_details(Some(first_page[99].key.clone()));
        assert_eq!(second_page.len(), 50);

        // Nothing remains after the last key.
        let third_page = state.get_asset_details(Some(second_page[49].key.clone()));
        assert!(third_page.is_empty());
    }

    #[test]
    fn list_returns_empty_for_no_assets() {
        let state = State::default();
        assert!(state.get_asset_details(None).is_empty());
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
                headers: vec![],
            })
            .unwrap();

        // Create batch and chunk
        let session_id = start_session(&mut state, &system_context);
        let chunks = vec![ByteBuf::from(CONTENT)];
        let chunk_ids: Vec<u64> = (0..chunks.len() as u64).collect();
        state
            .upload_chunks(
                UploadChunksArguments { session_id, chunks },
                &system_context,
            )
            .unwrap();

        // set_asset_content with correct hash should succeed
        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(correct_hash.as_slice()),
        });

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
                headers: vec![],
            })
            .unwrap();

        // Create batch and chunk
        let session_id = start_session(&mut state, &system_context);
        let chunks = vec![ByteBuf::from(CONTENT)];
        let chunk_ids: Vec<u64> = (0..chunks.len() as u64).collect();
        state
            .upload_chunks(
                UploadChunksArguments { session_id, chunks },
                &system_context,
            )
            .unwrap();

        // set_asset_content with incorrect hash should fail
        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(incorrect_hash.as_slice()),
        });

        assert_eq!(result.unwrap_err(), "sha256 mismatch");
    }

    #[test]
    fn stores_computed_sha256() {
        let mut state = State::default();
        let system_context = mock_system_context();

        const CONTENT: &[u8] = b"Hello, World!";
        let expected_hash = sha2::Sha256::digest(CONTENT);

        // Create asset first
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                headers: vec![],
            })
            .unwrap();

        // Create batch and chunk
        let session_id = start_session(&mut state, &system_context);
        let chunks = vec![ByteBuf::from(CONTENT)];
        let chunk_ids: Vec<u64> = (0..chunks.len() as u64).collect();
        state
            .upload_chunks(
                UploadChunksArguments { session_id, chunks },
                &system_context,
            )
            .unwrap();

        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(expected_hash.as_slice()),
        });

        assert!(result.is_ok());

        // Verify the hash was computed correctly by inspecting the listed encoding.
        let details = state.get_asset_details(None);
        let encoding = details
            .iter()
            .find(|a| a.key == "/test.txt")
            .and_then(|a| {
                a.encodings
                    .iter()
                    .find(|e| e.encoding == Encoding::Identity)
            })
            .expect("identity encoding should be listed");
        assert_eq!(encoding.sha256.as_ref(), expected_hash.as_slice());
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
                headers: vec![],
            })
            .unwrap();

        // Create batch and chunks
        let session_id = start_session(&mut state, &system_context);
        let chunks = vec![ByteBuf::from(CHUNK_1), ByteBuf::from(CHUNK_2)];
        let chunk_ids: Vec<u64> = (0..chunks.len() as u64).collect();
        state
            .upload_chunks(
                UploadChunksArguments { session_id, chunks },
                &system_context,
            )
            .unwrap();

        // set_asset_content with correct hash for combined chunks should succeed
        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(correct_hash.as_slice()),
        });

        assert!(result.is_ok());
    }
}

mod redirect_rules {
    use super::*;
    use crate::redirect::{RedirectRule, RulePattern};
    use crate::types::SetRedirectRulesArguments;

    fn commit(state: &mut State, ops: Vec<Operation>) -> Result<(), String> {
        let system_context = mock_system_context();
        let session_id = start_session(state, &system_context);
        run_computation_until_completion(|progress| {
            state.execute_operations(
                &ExecuteOperationsArguments {
                    session_id,
                    operations: ops.clone(),
                    is_final: true,
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
                headers: vec![],
            },
            RedirectRule {
                from: RulePattern::Subtree("/legacy/".into()),
                to: "/home".into(),
                status: 308,
                headers: vec![("X-Reason".into(), "moved".into())],
            },
        ]
    }

    #[test]
    fn commit_set_redirect_rules_round_trips_through_get() {
        let mut state = State::default();
        let rules = sample_rules();

        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: rules.clone(),
            })],
        )
        .unwrap();

        assert_eq!(state.get_redirect_rules(0), rules);
    }

    #[test]
    fn get_redirect_rules_paginates_by_index() {
        // Paging is a pure read over the rule vec, so populate it directly
        // rather than committing (and certifying) 200+ rules — the write path
        // and certification are exercised by the round-trip tests. Each rule's
        // `to` encodes its index so we can assert order and offset.
        let mut state = State::default();
        let total = crate::state::PAGE_SIZE * 2 + 37; // two full pages + a partial third
        state.set_redirect_rules(
            (0..total)
                .map(|i| RedirectRule {
                    from: RulePattern::Exact(format!("/from-{i}")),
                    to: format!("/to-{i}"),
                    status: 301,
                    headers: vec![],
                })
                .collect(),
        );

        // A page is capped at PAGE_SIZE and begins exactly at the cursor.
        let first = state.get_redirect_rules(0);
        assert_eq!(first.len(), crate::state::PAGE_SIZE);
        assert_eq!(first[0].to, "/to-0");

        // The page at an offset begins at that index.
        let mid = state.get_redirect_rules(crate::state::PAGE_SIZE as u64);
        assert_eq!(mid[0].to, format!("/to-{}", crate::state::PAGE_SIZE));

        // The final page is the short remainder; a cursor at or past the end is
        // empty, terminating a caller's walk.
        let last = state.get_redirect_rules((crate::state::PAGE_SIZE * 2) as u64);
        assert_eq!(last.len(), 37);
        assert!(state.get_redirect_rules(total as u64).is_empty());
        assert!(state.get_redirect_rules(total as u64 + 1000).is_empty());

        // Walking the cursor reassembles the full list in order.
        let mut collected = Vec::new();
        let mut start = 0u64;
        loop {
            let page = state.get_redirect_rules(start);
            if page.is_empty() {
                break;
            }
            start += page.len() as u64;
            collected.extend(page);
        }
        assert_eq!(collected.len(), total);
        assert!(collected
            .iter()
            .enumerate()
            .all(|(i, r)| r.to == format!("/to-{i}")));
    }

    #[test]
    fn invalid_rule_fails_op_without_mutating_state() {
        let mut state = State::default();
        // Seed an initial valid set so we can confirm it is preserved.
        let initial = vec![RedirectRule {
            from: RulePattern::Exact("/seed".into()),
            to: "/dest".into(),
            status: 301,
            headers: vec![],
        }];
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
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
                headers: vec![],
            },
            RedirectRule {
                from: RulePattern::Exact("/c".into()),
                to: "/d".into(),
                status: 418,
                headers: vec![],
            },
        ];
        let err = commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: mixed,
            })],
        )
        .unwrap_err();
        assert!(err.contains("unsupported status code"), "got: {err}");

        assert_eq!(
            state.get_redirect_rules(0),
            initial,
            "rules must be unchanged after a failed SetRedirectRules"
        );
    }

    #[test]
    fn rules_persist_through_upgrade() {
        let memory = DefaultMemoryImpl::default();
        let mut state = State::new(memory.clone());
        let rules = sample_rules();

        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: rules.clone(),
            })],
        )
        .unwrap();

        let state = upgrade(state, memory.clone());

        assert_eq!(state.get_redirect_rules(0), rules);
    }

    #[test]
    fn empty_rules_replace_existing() {
        let mut state = State::default();

        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: sample_rules(),
            })],
        )
        .unwrap();
        assert!(!state.get_redirect_rules(0).is_empty());

        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![],
            })],
        )
        .unwrap();
        assert!(state.get_redirect_rules(0).is_empty());
    }

    #[test]
    fn exact_3xx_rule_serves_redirect_with_certificate() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/old".into()),
                    to: "/new".into(),
                    status: 301,
                    headers: vec![],
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
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Subtree("/legacy/".into()),
                    to: "/home".into(),
                    status: 308,
                    headers: vec![],
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
    fn first_match_wins_across_multiple_3xx_rules() {
        let mut state = State::default();
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![
                    RedirectRule {
                        from: RulePattern::Exact("/dup".into()),
                        to: "/first".into(),
                        status: 301,
                        headers: vec![],
                    },
                    RedirectRule {
                        from: RulePattern::Exact("/dup".into()),
                        to: "/second".into(),
                        status: 302,
                        headers: vec![],
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
        let memory = DefaultMemoryImpl::default();
        let mut state = State::new(memory.clone());
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: sample_rules(),
            })],
        )
        .unwrap();
        // Sanity: rules fire pre-upgrade.
        let pre = certified_http_request(&state, RequestBuilder::get("/legacy/anything").build());
        assert_eq!(pre.status_code, 308);

        let state = upgrade(state, memory.clone());

        let post = certified_http_request(&state, RequestBuilder::get("/legacy/anything").build());
        assert_eq!(post.status_code, 308);
        assert_eq!(lookup_header(&post, "Location"), Some("/home"));
    }

    #[test]
    fn status_200_target_coupling() {
        // Install rule before the target exists → rule is inert.
        let mut state = State::default();
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/foo".into()),
                    to: "/foo.html".into(),
                    status: 200,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();
        let inert = state.http_request(RequestBuilder::get("/foo").build(), &[], unused_callback());
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
        let after_delete =
            state.http_request(RequestBuilder::get("/foo").build(), &[], unused_callback());
        assert_eq!(after_delete.status_code, 404);
    }

    fn delete_asset_via_batch(state: &mut State, key: &str) {
        commit(
            state,
            vec![Operation::DeleteAsset(DeleteAssetArguments {
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
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/foo".into()),
                    to: "/bar.html".into(),
                    status: 200,
                    headers: vec![],
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
    fn custom_404_page_serves_target_with_4xx_status() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const PAGE_BODY: &[u8] =
            b"<!DOCTYPE html><html><body>This page is not found.</body></html>";
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/404.html", "text/html")
                .with_encoding("identity", vec![PAGE_BODY])],
        );
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Subtree("/legacy/".into()),
                    to: "/404.html".into(),
                    status: 404,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();

        let response =
            certified_http_request(&state, RequestBuilder::get("/legacy/anything").build());
        assert_eq!(response.status_code, 404);
        assert_eq!(response.body.as_ref(), PAGE_BODY);
        // The target's content-type carries over verbatim.
        assert_eq!(lookup_header(&response, "Content-Type"), Some("text/html"));
    }

    #[test]
    fn custom_410_page_serves_target_with_4xx_status() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const PAGE_BODY: &[u8] =
            b"<!DOCTYPE html><html><body>The content here has been removed.</body></html>";
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/410.html", "text/html")
                .with_encoding("identity", vec![PAGE_BODY])],
        );
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/retired".into()),
                    to: "/410.html".into(),
                    status: 410,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();

        let response = certified_http_request(&state, RequestBuilder::get("/retired").build());
        assert_eq!(response.status_code, 410);
        assert_eq!(response.body.as_ref(), PAGE_BODY);
    }

    #[test]
    fn validate_rejects_4xx_with_empty_target() {
        // `_redirects` always supplies a target — the canister rejects 4xx
        // rules without one (the catch-all 404 covers the empty case).
        let mut state = State::default();
        let err = commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/missing".into()),
                    to: String::new(),
                    status: 404,
                    headers: vec![],
                }],
            })],
        )
        .unwrap_err();
        assert!(err.contains("must be an absolute asset path"), "got: {err}");
    }

    #[test]
    fn no_rules_falls_through_to_builtin_404() {
        // No `_redirects` rules at all: missing paths return the canister's
        // built-in *certified* 404 ("not found" body). With no rule occupying
        // the `<*>` slot, `on_redirect_rules_change` certifies the fallback
        // there, so the response verifies (via `certified_http_request`).
        let mut state = State::default();
        let system_context = mock_system_context();
        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
        create_assets(
            &mut state,
            &system_context,
            vec![
                AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![BODY])
            ],
        );

        let response = certified_http_request(&state, RequestBuilder::get("/missing").build());
        assert_eq!(response.status_code, 404);
        assert_eq!(response.body.as_ref(), b"not found");
    }

    #[test]
    fn builtin_404_yields_to_root_rule_then_returns_when_removed() {
        // The built-in 404 and a root `/*` rule are mutually exclusive
        // occupants of `<*>`. Adding a root rule must hand the slot to the
        // rule; removing it must restore the *certified* built-in 404. Both
        // directions verify, which guards the rebuild ordering in
        // `on_redirect_rules_change`.
        let mut state = State::default();
        let system_context = mock_system_context();
        const INDEX: &[u8] = b"<!DOCTYPE html><html>spa</html>";
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/index.html", "text/html")
                .with_encoding("identity", vec![INDEX])],
        );

        // No rule → certified built-in 404 on a missing path.
        let before = certified_http_request(&state, RequestBuilder::get("/missing").build());
        assert_eq!(before.status_code, 404);
        assert_eq!(before.body.as_ref(), b"not found");

        // Root `/*` 200 rule takes over `<*>` → the missing path serves the SPA
        // index (certified), not the built-in 404.
        set_root_spa_rule(&mut state, "/index.html");
        let via_rule = certified_http_request(&state, RequestBuilder::get("/missing").build());
        assert_eq!(via_rule.status_code, 200);
        assert_eq!(via_rule.body.as_ref(), INDEX);

        // Remove all rules → the certified built-in 404 returns.
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![],
            })],
        )
        .unwrap();
        let after = certified_http_request(&state, RequestBuilder::get("/missing").build());
        assert_eq!(after.status_code, 404);
        assert_eq!(after.body.as_ref(), b"not found");
    }

    #[test]
    fn rule_4xx_with_missing_target_stays_inert() {
        // Matches the 200 behavior: pointing `to` at an asset that doesn't
        // exist yet leaves the rule inert until the asset shows up.
        let mut state = State::default();
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/missing".into()),
                    to: "/404.html".into(),
                    status: 404,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();
        // Target doesn't exist → rule inert → built-in fall-through 404.
        let inert = state.http_request(
            RequestBuilder::get("/missing").build(),
            &[],
            unused_callback(),
        );
        assert_eq!(inert.status_code, 404);
        // The body is the built-in "not found", not the (missing) /404.html.
        assert_eq!(inert.body.as_ref(), b"not found");

        // Now create the target — the rule starts firing.
        const PAGE: &[u8] = b"<html>Custom 404</html>";
        create_assets(
            &mut state,
            &mock_system_context(),
            vec![AssetBuilder::new("/404.html", "text/html").with_encoding("identity", vec![PAGE])],
        );
        let response = certified_http_request(&state, RequestBuilder::get("/missing").build());
        assert_eq!(response.status_code, 404);
        assert_eq!(response.body.as_ref(), PAGE);
    }

    #[test]
    fn custom_4xx_target_updates_refresh_the_rule() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const V1: &[u8] = b"<html>404 v1</html>";
        const V2: &[u8] = b"<html>404 v2 redesigned</html>";
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/404.html", "text/html").with_encoding("identity", vec![V1])],
        );
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Subtree("/old/".into()),
                    to: "/404.html".into(),
                    status: 404,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();
        let v1 = certified_http_request(&state, RequestBuilder::get("/old/x").build());
        assert_eq!(v1.body.as_ref(), V1);
        assert_eq!(v1.status_code, 404);

        // Update the target page — the rule keeps firing with the new content.
        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/404.html", "text/html").with_encoding("identity", vec![V2])],
        );
        let v2 = certified_http_request(&state, RequestBuilder::get("/old/x").build());
        assert_eq!(v2.body.as_ref(), V2);
        assert_eq!(v2.status_code, 404);
    }

    #[test]
    fn validate_rejects_4xx_relative_target() {
        let mut state = State::default();
        let err = commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/missing".into()),
                    to: "404.html".into(), // missing leading '/'
                    status: 404,
                    headers: vec![],
                }],
            })],
        )
        .unwrap_err();
        assert!(err.contains("must be an absolute asset path"), "got: {err}");
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
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Subtree("/".into()),
                    to: "/index.html".into(),
                    status: 200,
                    headers: vec![],
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
