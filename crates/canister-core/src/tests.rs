use crate::http::{HttpRequest, HttpResponse};
use crate::protection::ProtectionStatus;
use crate::runtime::SystemContext;
use crate::state::sync::{ComputationStatus, SYNC_IDLE_TIMEOUT_NANOS};
use crate::state::State;
use crate::UploadChunksArguments;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use candid::Principal;
use ic_certification_testing::CertificateBuilder;
use ic_crypto_tree_hash::Digest;
use ic_http_certification::{Method, StatusCode};
use ic_stable_structures::DefaultMemoryImpl;
use serde_bytes::ByteBuf;
use sha2::Digest as Sha2Digest;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use wire_types::{
    CreateAssetArguments, DeleteAssetArguments, Encoding, ExecuteOperationsArguments, Operation,
    SessionId, SetAssetContentArguments, SetAssetHeadersArguments, StartSyncResult,
};

// from ic-response-verification tests
const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

/// Fixed "now" (ns) used as the `http_request` time argument in tests. Matches
/// [`mock_system_context`]; access protection compares token expiry
/// against it.
const TEST_NOW: u64 = 100_000_000_000;

fn some_principal() -> Principal {
    Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap()
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
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
    let min_requested_verification_version: u16 = 2;

    // inject certificate into IC-Certificate header with 'certificate=::'
    let data = CertificateBuilder::new(
        &canister_id.to_string(),
        Digest(state.root_hash()).as_bytes(),
    )?
    .with_time(current_time)
    .build()?;
    let replacement_cert_value = BASE64.encode(&data.cbor_encoded_certificate);
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
    certified_http_request_at(state, request, TEST_NOW)
}

/// Like [`certified_http_request`] but with an explicit access-protection "now" (ns), for
/// exercising token expiry. The certificate itself is still minted at real
/// wall-clock time inside [`verify_response`].
fn certified_http_request_at(state: &State, request: HttpRequest, now: u64) -> HttpResponse {
    let response = state.http_request(request.clone(), &[], now);
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

    fn post(resource: impl AsRef<str>) -> Self {
        Self {
            method: "POST".to_string(),
            ..Self::get(resource)
        }
    }

    fn with_body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = ByteBuf::from(body.as_ref().to_vec());
        self
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
            // The canister trusts client-supplied hashes, so the helper plays the
            // plugin's role: hash the whole encoding and each chunk before upload.
            let chunk_sha256: Vec<ByteBuf> = chunks
                .iter()
                .map(|c| ByteBuf::from(sha2::Sha256::digest(c).to_vec()))
                .collect();
            state
                .upload_chunks(UploadChunksArguments { session_id, chunks }, system_context)
                .unwrap();

            operations.push(Operation::SetAssetContent({
                SetAssetContentArguments {
                    key: asset.name.clone(),
                    encoding: enc,
                    chunk_ids,
                    sha256,
                    chunk_sha256,
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

// ───────── state hash ─────────

/// Whole-encoding SHA-256 over `chunks` concatenated, as the plugin computes it.
fn whole_sha(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

fn chunk_sha(chunk: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(chunk).into()
}

#[test]
fn state_hash_is_zero_before_any_sync() {
    let state = State::default();
    assert_eq!(state.cached_state_hash(), [0u8; 32]);
}

#[test]
fn state_hash_matches_manifest_digest_single_chunk() {
    use state_hash::{digest, Manifest, ManifestAsset, ManifestEncoding};

    let mut state = State::default();
    let ctx = mock_system_context();

    const BODY: &[u8] = b"hello world";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/index.html", "text/html")
            .with_header("Cache-Control", "max-age=60")
            .with_encoding("identity", vec![BODY])],
    );

    let cached = state.cached_state_hash();
    assert_ne!(cached, [0u8; 32], "the hash is cached after a final sync");

    // Independently rebuild the manifest the offline verifier would and digest
    // it with the `state-hash` crate. This is the cross-implementation contract:
    // the canister's streamed hash over stored state must equal the one-shot
    // digest over the same logical content.
    let expected = digest(&Manifest {
        assets: vec![ManifestAsset {
            key: "/index.html".to_string(),
            content_type: "text/html".to_string(),
            headers: vec![("Cache-Control".to_string(), "max-age=60".to_string())],
            encodings: vec![ManifestEncoding::single_chunk(
                Encoding::Identity,
                whole_sha(&[BODY]),
                BODY.len() as u64,
            )],
        }],
        redirect_rules: vec![],
    });
    assert_eq!(cached, expected);

    // Staged finalization (HashingState) and the one-shot recompute agree.
    assert_eq!(state.recompute_state_hash(), cached);
}

#[test]
fn state_hash_folds_per_chunk_hashes_for_multi_chunk() {
    use state_hash::{digest, Manifest, ManifestAsset, ManifestChunk, ManifestEncoding};

    let mut state = State::default();
    let ctx = mock_system_context();

    const C0: &[u8] = b"first-chunk-bytes";
    const C1: &[u8] = b"second-chunk";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );

    let cached = state.cached_state_hash();
    let expected = digest(&Manifest {
        assets: vec![ManifestAsset {
            key: "/big.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            headers: vec![],
            encodings: vec![ManifestEncoding::multi_chunk(
                Encoding::Identity,
                whole_sha(&[C0, C1]),
                vec![
                    ManifestChunk {
                        len: C0.len() as u32,
                        sha256: chunk_sha(C0),
                    },
                    ManifestChunk {
                        len: C1.len() as u32,
                        sha256: chunk_sha(C1),
                    },
                ],
            )],
        }],
        redirect_rules: vec![],
    });
    assert_eq!(cached, expected);
}

#[test]
fn state_hash_changes_when_content_changes() {
    let mut state = State::default();
    let ctx = mock_system_context();

    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/a.txt", "text/plain").with_encoding("identity", vec![b"v1"])],
    );
    let before = state.cached_state_hash();

    // Re-sync the same key with different bytes.
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/a.txt", "text/plain")
            .with_encoding("identity", vec![b"v2-different"])],
    );
    let after = state.cached_state_hash();

    assert_ne!(
        before, after,
        "different content yields a different state hash"
    );
}

#[test]
fn state_hash_survives_upgrade() {
    let memory = DefaultMemoryImpl::default();
    let mut state = State::new(memory.clone());
    let ctx = mock_system_context();

    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/index.html", "text/html").with_encoding("identity", vec![b"hi"])],
    );
    let before = state.cached_state_hash();
    assert_ne!(before, [0u8; 32]);

    // The cached hash lives in stable memory, so it survives the upgrade without
    // a recompute (no sync runs during post_upgrade_rebuild).
    let restored = upgrade(state, memory);
    assert_eq!(restored.cached_state_hash(), before);
}

/// Drives an `asset-prep` `PreparedProject` into `state` the way a real sync
/// does: CreateAsset + per-encoding upload/SetAssetContent + SetRedirectRules,
/// in one finalizing call. Mirrors the sync plugin's build_operations/pack so
/// the resulting stored state is what a real deploy would leave.
fn apply_prepared(state: &mut State, ctx: &SystemContext, prepared: &asset_prep::PreparedProject) {
    let session_id = start_session(state, ctx);
    let mut operations = vec![];
    for pa in &prepared.assets {
        operations.push(Operation::CreateAsset(CreateAssetArguments {
            key: pa.key.clone(),
            content_type: pa.content_type.clone(),
            headers: pa.headers.clone(),
        }));
        for enc in &pa.encodings {
            // Stage this encoding's chunks; ids are their staging slots.
            let base = state.chunks.len() as u64;
            let chunk_ids: Vec<u64> = (base..base + enc.chunks.len() as u64).collect();
            let chunks: Vec<ByteBuf> = enc
                .chunks
                .iter()
                .map(|c| ByteBuf::from(c.data.clone()))
                .collect();
            state
                .upload_chunks(UploadChunksArguments { session_id, chunks }, ctx)
                .unwrap();
            operations.push(Operation::SetAssetContent(SetAssetContentArguments {
                key: pa.key.clone(),
                encoding: enc.encoding,
                chunk_ids,
                sha256: ByteBuf::from(enc.sha256.to_vec()),
                chunk_sha256: enc
                    .chunks
                    .iter()
                    .map(|c| ByteBuf::from(c.sha256.to_vec()))
                    .collect(),
            }));
        }
    }
    operations.push(Operation::SetRedirectRules(
        wire_types::SetRedirectRulesArguments {
            rules: prepared.redirect_rules.clone(),
        },
    ));
    execute_all(state, session_id, operations, ctx);
}

/// The decisive cross-implementation contract: a canister populated by a sync of
/// `dist/` reports the **same** state hash the offline verifier computes from
/// that same `dist/`. Covers real compressed encodings, a multi-file project,
/// redirect rules, and the injected branded 404 — the cases the unit tests of
/// each side don't exercise together.
#[test]
fn state_hash_matches_asset_prep_over_a_real_dist() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let write = |rel: &str, bytes: &[u8]| {
        let path = dir.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    };
    // A compressible HTML page (gets gzip + brotli), a CSS file, an
    // incompressible binary, plus `_headers` and `_redirects`.
    write(
        "index.html",
        "<!DOCTYPE html><h1>hello</h1>\n".repeat(50).as_bytes(),
    );
    write("assets/app.css", "body{color:red}\n".repeat(80).as_bytes());
    write(
        "img/logo.png",
        &(0u8..=255).cycle().take(4096).collect::<Vec<u8>>(),
    );
    write("_headers", b"/*\n  X-Frame-Options: DENY\n");
    write("_redirects", b"/old /new 301\n");

    let dir_str = dir.path().to_str().unwrap();
    let prepared = asset_prep::prepare_project(dir_str).expect("prepare project");

    let mut state = State::default();
    let ctx = mock_system_context();
    apply_prepared(&mut state, &ctx, &prepared);

    let canister_hash = state.cached_state_hash();
    let verifier_hash = asset_prep::state_hash_for_dir(dir_str).expect("verifier hash");
    assert_eq!(
        hex::encode(canister_hash),
        hex::encode(verifier_hash),
        "canister state hash must equal the offline verifier's hash of the same dist/"
    );
    assert_ne!(canister_hash, [0u8; 32]);
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
    use wire_types::{RedirectRule, RulePattern, SetRedirectRulesArguments};
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
    use wire_types::{RedirectRule, RulePattern, SetRedirectRulesArguments};
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
        let response = state.http_request(RequestBuilder::get(*missing).build(), &[], TEST_NOW);
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

// ───────── HTTP 206 range serving ─────────

/// A plain GET (no Range) of a multi-chunk asset returns chunk 0 as a 206 — this
/// is what drives the gateway's reassembly into a full 200.
#[test]
fn multichunk_plain_get_serves_206_first_chunk() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"first-chunk-bytes--";
    const C1: &[u8] = b"second-chunk";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );

    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), C0);
    let total = C0.len() + C1.len();
    let cr = format!("bytes 0-{}/{}", C0.len() - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// A Range request whose start is a chunk boundary returns exactly that chunk.
#[test]
fn range_request_returns_containing_chunk() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    const C2: &[u8] = b"CCC";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1, C2])],
    );
    let total = C0.len() + C1.len() + C2.len();

    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", format!("bytes={}-", C0.len()))
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), C1);
    let cr = format!("bytes {}-{}/{}", C0.len(), C0.len() + C1.len() - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// A Range start in the middle of a chunk snaps down to that chunk's boundary:
/// the whole containing chunk is returned (sub-chunk slices can't be certified).
#[test]
fn range_request_mid_chunk_snaps_to_chunk_start() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );
    let total = C0.len() + C1.len();

    // Ask for a byte 2 into chunk 1; expect the whole of chunk 1 back.
    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", format!("bytes={}-", C0.len() + 2))
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), C1);
    let cr = format!("bytes {}-{}/{}", C0.len(), total - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// A range that spans multiple chunks returns only the chunk containing its
/// start; the client (or gateway) fetches the rest with follow-up requests.
#[test]
fn range_spanning_chunks_returns_single_chunk() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );
    let total = C0.len() + C1.len();

    // Closed range covering the whole asset → still just chunk 0.
    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", format!("bytes=0-{}", total - 1))
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), C0);
    let cr = format!("bytes 0-{}/{}", C0.len() - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// An unsatisfiable range (start past the end) ignores the Range and serves the
/// asset as a 206 chunk 0 — never a truncated 200.
#[test]
fn out_of_range_serves_full_asset_via_206() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );
    let total = C0.len() + C1.len();

    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", format!("bytes={}-", total + 100))
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), C0);
    let cr = format!("bytes 0-{}/{}", C0.len() - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// A conditional request takes precedence over Range: a matching `If-None-Match`
/// yields a 304 even when a `Range` header is present.
#[test]
fn conditional_request_with_range_returns_304() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );

    // First request: read the canister-managed etag off the 206.
    let first = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .build(),
    );
    let etag = lookup_header(&first, "etag")
        .expect("206 carries an etag")
        .to_string();

    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .with_header("If-None-Match", &etag)
            .with_header("Range", "bytes=10-")
            .build(),
    );

    assert_eq!(resp.status_code, 304);
    assert!(resp.body.as_ref().is_empty());
}

/// A single-chunk asset ignores Range and serves the full body as a 200.
#[test]
fn single_chunk_asset_ignores_range() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const BODY: &[u8] = b"a small body that fits in one chunk";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/small.txt", "text/plain").with_encoding("identity", vec![BODY])],
    );

    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/small.txt")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", "bytes=5-")
            .build(),
    );

    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body.as_ref(), BODY);
    assert_eq!(lookup_header(&resp, "content-range"), None);
}

/// Range serving works for a non-identity encoding: the 206 carries
/// `content-encoding` and ranges over the *encoded* bytes.
#[test]
fn range_request_non_identity_encoding() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const G0: &[u8] = b"\x1f\x8b\x08\x00gzip-chunk-0";
    const G1: &[u8] = b"gzip-chunk-1";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/app.js", "text/javascript").with_encoding("gzip", vec![G0, G1])],
    );
    let total = G0.len() + G1.len();

    let resp = certified_http_request(
        &state,
        RequestBuilder::get("/app.js")
            .with_header("Accept-Encoding", "gzip")
            .with_header("Range", format!("bytes={}-", G0.len()))
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), G1);
    assert_eq!(lookup_header(&resp, "content-encoding"), Some("gzip"));
    let cr = format!("bytes {}-{}/{}", G0.len(), total - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// After an upgrade, multi-chunk assets still serve 206s with correct
/// `Content-Range` — proof the per-chunk cert data (`chunk_certs` + `content_len`)
/// is persisted and `post_upgrade_rebuild` re-certifies the 206s content-free.
#[test]
fn range_serving_survives_upgrade() {
    let memory = DefaultMemoryImpl::default();
    let mut state = State::new(memory.clone());
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );
    let total = C0.len() + C1.len();

    let restored = upgrade(state, memory.clone());

    let resp = certified_http_request(
        &restored,
        RequestBuilder::get("/big.bin")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", format!("bytes={}-", C0.len()))
            .build(),
    );

    assert_eq!(resp.status_code, 206);
    assert_eq!(resp.body.as_ref(), C1);
    let cr = format!("bytes {}-{}/{}", C0.len(), total - 1, total);
    assert_eq!(lookup_header(&resp, "content-range"), Some(cr.as_str()));
}

/// Range forms the canister doesn't honour — a suffix range (`bytes=-N`), a
/// multi-range list, and a syntactically broken spec — all parse to "no range"
/// and serve the asset as a certified 206 chunk 0 (never a truncated 200), which
/// the gateway reassembles into the full 200.
#[test]
fn unhonoured_range_forms_serve_certified_206_chunk_0() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const C0: &[u8] = b"AAAAAAAAAA";
    const C1: &[u8] = b"BBBBBBB";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/big.bin", "application/octet-stream")
            .with_encoding("identity", vec![C0, C1])],
    );
    let total = C0.len() + C1.len();
    let cr = format!("bytes 0-{}/{}", C0.len() - 1, total);

    for range in ["bytes=-500", "bytes=0-1,5-6", "bytes=abc-", "kingdoms=0-"] {
        let resp = certified_http_request(
            &state,
            RequestBuilder::get("/big.bin")
                .with_header("Accept-Encoding", "identity")
                .with_header("Range", range)
                .build(),
        );
        assert_eq!(resp.status_code, 206, "range {range:?}");
        assert_eq!(resp.body.as_ref(), C0, "range {range:?}");
        assert_eq!(
            lookup_header(&resp, "content-range"),
            Some(cr.as_str()),
            "range {range:?}"
        );
    }
}

/// Range/chunk behaviour follows the *selected* encoding, not the asset. A file
/// stored as a 2-chunk identity plus a 1-chunk (compressed-below-threshold) gzip
/// serves a 206 when identity is chosen but a plain 200 when gzip is chosen —
/// both certified.
#[test]
fn range_follows_selected_encoding_chunk_count() {
    let mut state = State::default();
    let ctx = mock_system_context();
    const I0: &[u8] = b"identity-chunk-0--";
    const I1: &[u8] = b"identity-chunk-1";
    const GZ: &[u8] = b"\x1f\x8b\x08\x00small-gzip";
    create_assets(
        &mut state,
        &ctx,
        vec![AssetBuilder::new("/app.js", "text/javascript")
            .with_encoding("identity", vec![I0, I1])
            .with_encoding("gzip", vec![GZ])],
    );

    // gzip is single-chunk → Range ignored, full 200.
    let gz = certified_http_request(
        &state,
        RequestBuilder::get("/app.js")
            .with_header("Accept-Encoding", "gzip")
            .with_header("Range", "bytes=4-")
            .build(),
    );
    assert_eq!(gz.status_code, 200);
    assert_eq!(gz.body.as_ref(), GZ);
    assert_eq!(lookup_header(&gz, "content-encoding"), Some("gzip"));
    assert_eq!(lookup_header(&gz, "content-range"), None);

    // identity is two chunks → Range honoured, certified 206.
    let id = certified_http_request(
        &state,
        RequestBuilder::get("/app.js")
            .with_header("Accept-Encoding", "identity")
            .with_header("Range", format!("bytes={}-", I0.len()))
            .build(),
    );
    assert_eq!(id.status_code, 206);
    assert_eq!(id.body.as_ref(), I1);
    assert_eq!(lookup_header(&id, "content-encoding"), None);
    let total = I0.len() + I1.len();
    let cr = format!("bytes {}-{}/{}", I0.len(), total - 1, total);
    assert_eq!(lookup_header(&id, "content-range"), Some(cr.as_str()));
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

    let no_alias = state.http_request(RequestBuilder::get("/contents").build(), &[], TEST_NOW);
    assert_eq!(no_alias.status_code, 404);

    let other = certified_http_request(&state, RequestBuilder::get("/subdirectory").build());
    assert_eq!(other.body.as_ref(), SUBDIR_INDEX_BODY);

    let state = upgrade(state, memory.clone());

    let no_alias = state.http_request(RequestBuilder::get("/contents").build(), &[], TEST_NOW);
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
        let mut serialized = Vec::new();
        ciborium::into_writer(&old_headers, &mut serialized).unwrap();
        let new_headers: BTreeMap<String, String> = ciborium::from_reader(&serialized[..]).unwrap();
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
    use crate::cert::build_ic_certificate_expression_from_headers_and_encoding;
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
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "Access-Control-Allow-Origin", "etag"]}}}})"#,
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
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "Access-Control-Allow-Origin", "etag"]}}}})"#,
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
            r#"default_certification(ValidationArgs{certification: Certification{no_request_certification: Empty{}, response_certification: ResponseCertification{certified_response_headers: ResponseHeaderList{headers: ["content-type", "content-encoding", "custom-header", "etag"]}}}})"#,
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
        // The canister owns the `ETag`: it emits a certified `"<hex sha256>"`,
        // and a custom `etag` smuggled into the asset headers is stripped (it
        // does not appear on the wire) rather than served.
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
        let expected_etag = format!("\"{}\"", hex::encode(sha2::Sha256::digest(BODY)));

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
        assert_eq!(response.status_code, 200);
        assert_eq!(
            lookup_header(&response, "etag").expect("etag header missing"),
            expected_etag,
            "canister must serve its content-hash etag, not the custom one"
        );
    }

    #[test]
    fn conditional_request_serves_certified_304() {
        // A request whose `If-None-Match` carries the asset's current etag gets a
        // certified 304 with an empty body; `certified_http_request` verifies the
        // certificate, so this also proves the 304 is cryptographically valid (as
        // a real HTTP gateway would require).
        let mut state = State::default();
        let system_context = mock_system_context();

        const BODY: &[u8] = b"<!DOCTYPE html><html></html>";
        let etag = format!("\"{}\"", hex::encode(sha2::Sha256::digest(BODY)));

        create_assets(
            &mut state,
            &system_context,
            vec![AssetBuilder::new("/contents.html", "text/html")
                .with_encoding("identity", vec![BODY])],
        );

        // Matching etag -> certified 304, empty body, no streaming.
        let not_modified = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "identity")
                .with_header("If-None-Match", &etag)
                .build(),
        );
        assert_eq!(not_modified.status_code, 304);
        assert!(not_modified.body.is_empty());
        assert_eq!(lookup_header(&not_modified, "etag").unwrap(), etag);

        // A stale etag still serves the full, certified 200.
        let modified = certified_http_request(
            &state,
            RequestBuilder::get("/contents.html")
                .with_header("Accept-Encoding", "identity")
                .with_header(
                    "If-None-Match",
                    "\"0000000000000000000000000000000000000000000000000000000000000000\"",
                )
                .build(),
        );
        assert_eq!(modified.status_code, 200);
        assert_eq!(modified.body.as_ref(), BODY);
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
mod set_asset_content_sha256_trust {
    use super::*;

    // The canister no longer recomputes the content hash on commit — it trusts
    // the client-supplied `sha256` / `chunk_sha256` and certifies them directly.
    // (The HTTP gateway re-verifies the body hash end-to-end, so a wrong hash
    // only makes the asset unservable; it can never serve forged content.) These
    // tests pin that trust behaviour and the shape validation that remains.

    /// Creates `/test.txt` and stages `chunks` under a fresh session, returning
    /// the chunk ids the canister assigned (0-based, since staging starts empty).
    fn create_and_stage(
        state: &mut State,
        system_context: &SystemContext,
        chunks: Vec<ByteBuf>,
    ) -> Vec<u64> {
        state
            .create_asset(CreateAssetArguments {
                key: "/test.txt".to_string(),
                content_type: "text/plain".to_string(),
                headers: vec![],
            })
            .unwrap();
        let session_id = start_session(state, system_context);
        let chunk_ids: Vec<u64> = (0..chunks.len() as u64).collect();
        state
            .upload_chunks(UploadChunksArguments { session_id, chunks }, system_context)
            .unwrap();
        chunk_ids
    }

    /// The identity encoding's stored sha256, as the details query reports it.
    fn stored_sha256(state: &State) -> Vec<u8> {
        state
            .get_asset_details(None)
            .iter()
            .find(|a| a.key == "/test.txt")
            .and_then(|a| {
                a.encodings
                    .iter()
                    .find(|e| e.encoding == Encoding::Identity)
            })
            .expect("identity encoding should be listed")
            .sha256
            .to_vec()
    }

    #[test]
    fn stores_provided_sha256_verbatim() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const CONTENT: &[u8] = b"Hello, World!";
        let hash = sha2::Sha256::digest(CONTENT);
        let chunk_ids = create_and_stage(&mut state, &system_context, vec![ByteBuf::from(CONTENT)]);

        state
            .set_asset_content(SetAssetContentArguments {
                key: "/test.txt".to_string(),
                encoding: Encoding::Identity,
                chunk_ids,
                sha256: ByteBuf::from(hash.as_slice()),
                chunk_sha256: vec![ByteBuf::from(hash.as_slice())],
            })
            .unwrap();

        assert_eq!(stored_sha256(&state), hash.as_slice());
    }

    #[test]
    fn trusts_sha256_without_recomputing() {
        // A hash that does NOT match the content is accepted and stored as-is:
        // the canister does no verification (the gateway does, end-to-end).
        let mut state = State::default();
        let system_context = mock_system_context();
        const CONTENT: &[u8] = b"Hello, World!";
        let wrong = sha2::Sha256::digest(b"Different content");
        let chunk_ids = create_and_stage(&mut state, &system_context, vec![ByteBuf::from(CONTENT)]);

        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(wrong.as_slice()),
            chunk_sha256: vec![ByteBuf::from(wrong.as_slice())],
        });

        assert!(result.is_ok(), "a wrong hash is trusted, not rejected");
        assert_eq!(stored_sha256(&state), wrong.as_slice());
    }

    #[test]
    fn multi_chunk_stores_provided_hashes() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const CHUNK_1: &[u8] = b"Hello, ";
        const CHUNK_2: &[u8] = b"World!";
        let mut hasher = sha2::Sha256::new();
        hasher.update(CHUNK_1);
        hasher.update(CHUNK_2);
        let full = hasher.finalize();
        let chunk_ids = create_and_stage(
            &mut state,
            &system_context,
            vec![ByteBuf::from(CHUNK_1), ByteBuf::from(CHUNK_2)],
        );

        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(full.as_slice()),
            chunk_sha256: vec![
                ByteBuf::from(sha2::Sha256::digest(CHUNK_1).as_slice()),
                ByteBuf::from(sha2::Sha256::digest(CHUNK_2).as_slice()),
            ],
        });

        assert!(result.is_ok());
        assert_eq!(stored_sha256(&state), full.as_slice());
    }

    #[test]
    fn rejects_chunk_sha256_length_mismatch() {
        let mut state = State::default();
        let system_context = mock_system_context();
        const CHUNK_1: &[u8] = b"Hello, ";
        const CHUNK_2: &[u8] = b"World!";
        let chunk_ids = create_and_stage(
            &mut state,
            &system_context,
            vec![ByteBuf::from(CHUNK_1), ByteBuf::from(CHUNK_2)],
        );

        // Two chunks, but only one per-chunk hash supplied.
        let result = state.set_asset_content(SetAssetContentArguments {
            key: "/test.txt".to_string(),
            encoding: Encoding::Identity,
            chunk_ids,
            sha256: ByteBuf::from(vec![0u8; 32]),
            chunk_sha256: vec![ByteBuf::from(sha2::Sha256::digest(CHUNK_1).as_slice())],
        });

        assert_eq!(
            result.unwrap_err(),
            "chunk_sha256 length must match chunk_ids"
        );
    }
}

mod redirect_rules {
    use super::*;
    use wire_types::{RedirectRule, RulePattern, SetRedirectRulesArguments};

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
        let inert = state.http_request(RequestBuilder::get("/foo").build(), &[], TEST_NOW);
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
        let after_delete = state.http_request(RequestBuilder::get("/foo").build(), &[], TEST_NOW);
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
        let inert = state.http_request(RequestBuilder::get("/missing").build(), &[], TEST_NOW);
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
    fn rejects_4xx_rule_to_existing_multichunk_target() {
        // A 404/410 custom error page is served as a single inline body, so a
        // multi-chunk target can't carry it. Setting such a rule when the target
        // already exists and is multi-chunk must fail the whole op (which traps
        // at the canister boundary).
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![AssetBuilder::new("/404.html", "text/html")
                .with_encoding("identity", vec![b"chunk-zero", b"chunk-one!"])],
        );
        for status in [404u16, 410] {
            let err = commit(
                &mut state,
                vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                    rules: vec![RedirectRule {
                        from: RulePattern::Exact("/missing".into()),
                        to: "/404.html".into(),
                        status,
                        headers: vec![],
                    }],
                })],
            )
            .unwrap_err();
            assert!(err.contains("multi-chunk asset"), "status {status}: {err}");
        }
    }

    #[test]
    fn allows_200_rule_to_existing_multichunk_target() {
        // The 4xx guard must not reject a 200 rewrite to a multi-chunk asset —
        // that path is served as N×206 and is fully supported.
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![AssetBuilder::new("/large.bin", "application/octet-stream")
                .with_encoding("identity", vec![b"chunk-zero", b"chunk-one!"])],
        );
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/landing".into()),
                    to: "/large.bin".into(),
                    status: 200,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();
    }

    #[test]
    fn alias_200_to_multichunk_target_serves_certified_206() {
        // Unit-level coverage of the 200-rewrite → multi-chunk path (otherwise
        // only exercised by the e2e suite): both a plain GET (chunk 0) and a
        // Range request must return a *certified* 206 at the alias location.
        let mut state = State::default();
        let ctx = mock_system_context();
        const C0: &[u8] = b"AAAAAAAAAA";
        const C1: &[u8] = b"BBBBBBB";
        create_assets(
            &mut state,
            &ctx,
            vec![AssetBuilder::new("/large.bin", "application/octet-stream")
                .with_encoding("identity", vec![C0, C1])],
        );
        commit(
            &mut state,
            vec![Operation::SetRedirectRules(SetRedirectRulesArguments {
                rules: vec![RedirectRule {
                    from: RulePattern::Exact("/landing".into()),
                    to: "/large.bin".into(),
                    status: 200,
                    headers: vec![],
                }],
            })],
        )
        .unwrap();

        let plain = certified_http_request(
            &state,
            RequestBuilder::get("/landing")
                .with_header("Accept-Encoding", "identity")
                .build(),
        );
        assert_eq!(plain.status_code, 206);
        assert_eq!(plain.body.as_ref(), C0);

        let ranged = certified_http_request(
            &state,
            RequestBuilder::get("/landing")
                .with_header("Accept-Encoding", "identity")
                .with_header("Range", format!("bytes={}-", C0.len()))
                .build(),
        );
        assert_eq!(ranged.status_code, 206);
        assert_eq!(ranged.body.as_ref(), C1);
    }

    #[test]
    fn alias_4xx_to_multichunk_target_degrades_to_certified_builtin_404() {
        // Defense in depth: even if a 4xx rule pointing at a multi-chunk target
        // slips past the op guard (e.g. the target grew multi-chunk after the
        // rule was set), the rule must go inert rather than emit an
        // unverifiable response. `build_alias_rule_entry` skips multi-chunk
        // encodings for non-200 status, so the path falls through to the
        // built-in certified 404.
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![AssetBuilder::new("/404.html", "text/html")
                .with_encoding("identity", vec![b"chunk-zero", b"chunk-one!"])],
        );
        // Install the rule directly via state (bypassing the op guard) to model
        // the "target grew multi-chunk later" ordering.
        state.set_redirect_rules(vec![RedirectRule {
            from: RulePattern::Subtree("/legacy/".into()),
            to: "/404.html".into(),
            status: 404,
            headers: vec![],
        }]);

        let resp = certified_http_request(&state, RequestBuilder::get("/legacy/x").build());
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.body.as_ref(), b"not found");
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

/// The certified, canister-injected `ic_env` cookie (the IC root key + `PUBLIC_*`
/// env vars, layered onto every `text/html` response).
mod env_cookie {
    use super::*;
    use crate::runtime::CanisterEnv;

    /// A deterministic, correctly-sized (133-byte DER) mock root key. The client
    /// lib asserts exactly this length when hex-decoding `ic_root_key`.
    fn mock_root_key() -> Vec<u8> {
        (0..133u32).map(|i| i as u8).collect()
    }

    /// A mock env snapshot carrying the given (already `PUBLIC_`-filtered) vars.
    fn env_with(vars: &[(&str, &str)]) -> CanisterEnv {
        CanisterEnv {
            root_key: mock_root_key(),
            public_vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// All values of a (case-insensitive) response header, in order.
    fn all_headers<'a>(response: &'a HttpResponse, name: &str) -> Vec<&'a str> {
        response
            .headers
            .iter()
            .filter(|(h, _)| h.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Client-side `decodeURIComponent`, reproduced for assertions: percent-decodes
    /// the visible cookie value exactly as the browser does before the lib parses it.
    fn client_decode(value: &str) -> String {
        percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .unwrap()
            .to_string()
    }

    /// Reproduces the `@icp-sdk/core/agent/canister-env` parse exactly: the
    /// browser exposes only the part of `Set-Cookie` before the first `;` via
    /// `document.cookie`; the lib then strips `ic_env=`, `decodeURIComponent`s,
    /// splits on `&` / first-`=`, and hex-decodes `ic_root_key`.
    fn parse_like_client(set_cookie: &str) -> (Vec<u8>, BTreeMap<String, String>) {
        let visible = set_cookie.split(';').next().unwrap().trim();
        let encoded = visible.strip_prefix("ic_env=").expect("ic_env= prefix");
        let decoded = client_decode(encoded);
        let mut root_key = None;
        let mut vars = BTreeMap::new();
        for entry in decoded.split('&') {
            let eq = entry.find('=').expect("entry has '='");
            let (k, v) = (&entry[..eq], &entry[eq + 1..]);
            if k == "ic_root_key" {
                root_key = Some(hex::decode(v).unwrap());
            } else {
                vars.insert(k.to_string(), v.to_string());
            }
        }
        (root_key.expect("ic_root_key present"), vars)
    }

    /// Mirrors `canister_core::post_upgrade`: a fresh `State` over the same
    /// memory, recapturing the env snapshot *before* the derived-state rebuild.
    fn upgrade_with_env(state: State, memory: DefaultMemoryImpl, env: &CanisterEnv) -> State {
        drop(state);
        let mut restored = State::new(memory);
        restored.store_env(env);
        restored.post_upgrade_rebuild();
        restored
    }

    fn html_asset(key: &str, body: &'static [u8]) -> AssetBuilder {
        AssetBuilder::new(key, "text/html").with_encoding("identity", vec![body])
    }

    #[test]
    fn render_env_cookie_orders_and_encodes() {
        use crate::asset::render_env_cookie;
        let vars = BTreeMap::from([
            ("PUBLIC_B".to_string(), "2".to_string()),
            // A value containing `=` must survive: only the structural `&`/`=`
            // separators are escaped, and the client splits each entry on its
            // first `=` so the rest of the value is preserved verbatim.
            ("PUBLIC_A".to_string(), "v=with=eq".to_string()),
        ]);
        let rendered = render_env_cookie(&[0xab, 0xcd], &vars);

        assert!(rendered.ends_with("; Secure; SameSite=None; Partitioned"));
        let value = rendered
            .strip_prefix("ic_env=")
            .unwrap()
            .strip_suffix("; Secure; SameSite=None; Partitioned")
            .unwrap();
        // Separators are percent-encoded, so the payload rides in one cookie value.
        assert!(!value.contains('&') && !value.contains('='));
        // Decoding restores "ic_root_key=<hex>&<sorted PUBLIC_ vars>", root first.
        assert_eq!(
            client_decode(value),
            "ic_root_key=abcd&PUBLIC_A=v=with=eq&PUBLIC_B=2"
        );
    }

    #[test]
    fn from_raw_keeps_only_public_vars() {
        let env = CanisterEnv::from_raw(
            mock_root_key(),
            [
                ("PUBLIC_A".to_string(), "1".to_string()),
                ("SECRET_KEY".to_string(), "leak".to_string()),
                ("PATH".to_string(), "/bin".to_string()),
            ],
        );
        assert_eq!(env.public_vars.keys().collect::<Vec<_>>(), vec!["PUBLIC_A"]);
    }

    #[test]
    fn no_cookie_before_first_refresh() {
        // A fresh install captures no env (there is no `#[init]`), so HTML
        // responses carry no cookie until the first `refresh_env`.
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![html_asset("/index.html", b"<html></html>")],
        );

        let resp = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        assert_eq!(resp.status_code, 200);
        assert!(all_headers(&resp, "set-cookie").is_empty());
    }

    #[test]
    fn cookie_present_and_certified_on_html() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![html_asset("/page.html", b"<html></html>")],
        );
        state.refresh_env(&env_with(&[("PUBLIC_API_URL", "https://example.com")]));

        // `certified_http_request` panics unless the witness verifies — so it
        // passing *is* the assertion that the cookie is certified.
        let resp = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        assert_eq!(resp.status_code, 200);
        let cookies = all_headers(&resp, "set-cookie");
        assert_eq!(cookies.len(), 1);
        assert!(cookies[0].starts_with("ic_env="), "got: {}", cookies[0]);
        assert!(cookies[0].ends_with("; Secure; SameSite=None; Partitioned"));
    }

    #[test]
    fn cookie_absent_on_non_html() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                AssetBuilder::new("/app.js", "text/javascript")
                    .with_encoding("identity", vec![b"//js".as_ref()]),
                AssetBuilder::new("/style.css", "text/css")
                    .with_encoding("identity", vec![b"body{}".as_ref()]),
                AssetBuilder::new("/logo.png", "application/octet-stream")
                    .with_encoding("identity", vec![b"\x89PNG".as_ref()]),
            ],
        );
        state.refresh_env(&env_with(&[("PUBLIC_X", "1")]));

        for path in ["/app.js", "/style.css", "/logo.png"] {
            let resp = certified_http_request(&state, RequestBuilder::get(path).build());
            assert_eq!(resp.status_code, 200);
            assert!(
                all_headers(&resp, "set-cookie").is_empty(),
                "{path} must carry no cookie"
            );
        }
    }

    #[test]
    fn cookie_on_root_via_200_rewrite() {
        let mut state = State::default();
        let ctx = mock_system_context();
        const INDEX: &[u8] = b"<!DOCTYPE html><html>index</html>";
        create_assets(&mut state, &ctx, vec![html_asset("/index.html", INDEX)]);
        set_root_spa_rule(&mut state, "/index.html");
        state.refresh_env(&env_with(&[("PUBLIC_X", "1")]));

        // `/` is served by the 200-rewrite alias to /index.html — the common SPA
        // entry point, which is not a direct asset hit.
        let root = certified_http_request(&state, RequestBuilder::get("/").build());
        assert_eq!(root.status_code, 200);
        assert_eq!(root.body.as_ref(), INDEX);
        let root_cookies = all_headers(&root, "set-cookie");
        assert_eq!(root_cookies.len(), 1);
        assert!(root_cookies[0].starts_with("ic_env="));

        // The direct hit carries it too.
        let direct = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        assert!(all_headers(&direct, "set-cookie")[0].starts_with("ic_env="));
    }

    #[test]
    fn cookie_roundtrips_client_lib_algorithm() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![html_asset("/index.html", b"<html></html>")],
        );

        // Mix PUBLIC_ and non-PUBLIC vars; only the former reach the cookie.
        let env = CanisterEnv::from_raw(
            mock_root_key(),
            [
                (
                    "PUBLIC_API_URL".to_string(),
                    "https://api.example.com".to_string(),
                ),
                (
                    "PUBLIC_CANISTER_ID:backend".to_string(),
                    "ryjl3-tyaaa-aaaaa-aaaba-cai".to_string(),
                ),
                ("SECRET_KEY".to_string(), "do-not-leak".to_string()),
                ("DATABASE_URL".to_string(), "postgres://nope".to_string()),
            ],
        );
        state.refresh_env(&env);

        let resp = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        let cookie = all_headers(&resp, "set-cookie")[0];

        let (root_key, vars) = parse_like_client(cookie);
        assert_eq!(root_key.len(), 133);
        assert_eq!(root_key, mock_root_key());
        assert_eq!(
            vars.get("PUBLIC_API_URL").map(String::as_str),
            Some("https://api.example.com")
        );
        assert_eq!(
            vars.get("PUBLIC_CANISTER_ID:backend").map(String::as_str),
            Some("ryjl3-tyaaa-aaaaa-aaaba-cai")
        );
        // Non-PUBLIC vars are excluded — the prefix is the security boundary.
        assert!(!vars.contains_key("SECRET_KEY"));
        assert!(!vars.contains_key("DATABASE_URL"));
        assert_eq!(vars.len(), 2);

        // Entries are emitted in sorted order: root key first, then sorted vars.
        let visible = cookie.split(';').next().unwrap().trim();
        let decoded = client_decode(visible.strip_prefix("ic_env=").unwrap());
        let keys: Vec<&str> = decoded
            .split('&')
            .map(|e| &e[..e.find('=').unwrap()])
            .collect();
        assert_eq!(
            keys,
            vec![
                "ic_root_key",
                "PUBLIC_API_URL",
                "PUBLIC_CANISTER_ID:backend"
            ]
        );
    }

    #[test]
    fn refresh_env_swaps_value_and_leaves_non_html_untouched() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/page.html", b"<html></html>"),
                AssetBuilder::new("/app.js", "text/javascript")
                    .with_encoding("identity", vec![b"//js".as_ref()]),
            ],
        );

        state.refresh_env(&env_with(&[("PUBLIC_X", "one")]));
        let html1 = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        let cookie1 = all_headers(&html1, "set-cookie")[0].to_string();
        let js1 = certified_http_request(&state, RequestBuilder::get("/app.js").build());
        assert!(all_headers(&js1, "set-cookie").is_empty());

        // A second snapshot swaps the value; the new cookie is certified.
        state.refresh_env(&env_with(&[("PUBLIC_X", "two")]));
        let html2 = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        let cookie2 = all_headers(&html2, "set-cookie")[0].to_string();
        assert_ne!(cookie1, cookie2);
        let (_, vars2) = parse_like_client(&cookie2);
        assert_eq!(vars2.get("PUBLIC_X").map(String::as_str), Some("two"));

        // The old value is no longer certified: re-serving it fails verification.
        let mut stale = html2.clone();
        for (h, v) in stale.headers.iter_mut() {
            if h.eq_ignore_ascii_case("set-cookie") {
                *v = cookie1.clone();
            }
        }
        let req = RequestBuilder::get("/page.html").build();
        assert!(
            !verify_response(&state, &req, &stale).unwrap_or(false),
            "stale cookie must not verify against the refreshed tree"
        );

        // The JS asset is unaffected: still no cookie, still verifies.
        let js2 = certified_http_request(&state, RequestBuilder::get("/app.js").build());
        assert!(all_headers(&js2, "set-cookie").is_empty());
    }

    #[test]
    fn coexists_with_user_set_cookie() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![html_asset("/page.html", b"<html></html>")
                .with_header("Set-Cookie", "session=xyz; Path=/")],
        );
        state.refresh_env(&env_with(&[("PUBLIC_X", "1")]));

        // Passing certification proves the gateway/`ic-certification` accepts a
        // `set-cookie` listed twice in the certificate expression.
        let resp = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        let cookies = all_headers(&resp, "set-cookie");
        assert_eq!(cookies.len(), 2, "user cookie + env cookie coexist");
        assert!(cookies.iter().any(|c| c.contains("session=xyz")));
        assert!(cookies.iter().any(|c| c.starts_with("ic_env=")));
    }

    #[test]
    fn cookie_survives_upgrade_roundtrip() {
        let memory = DefaultMemoryImpl::default();
        let mut state = State::new(memory.clone());
        let ctx = mock_system_context();
        const INDEX: &[u8] = b"<!DOCTYPE html><html>index</html>";
        create_assets(&mut state, &ctx, vec![html_asset("/index.html", INDEX)]);
        let env = env_with(&[("PUBLIC_X", "kept")]);
        state.refresh_env(&env);

        let before = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        let cookie_before = all_headers(&before, "set-cookie")[0].to_string();

        let state = upgrade_with_env(state, memory.clone(), &env);

        let after = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        let cookie_after = all_headers(&after, "set-cookie")[0].to_string();
        assert_eq!(cookie_before, cookie_after);
        let (rk, vars) = parse_like_client(&cookie_after);
        assert_eq!(rk.len(), 133);
        assert_eq!(vars.get("PUBLIC_X").map(String::as_str), Some("kept"));
    }

    #[test]
    fn capture_at_sync_start_recertifies_only_on_change() {
        // `capture_env_at_sync_start` is what the entry layer calls at the start
        // of every sync. The asset here is never re-synced after the first
        // capture, so it exercises the correctness guarantee: an env change must
        // re-certify even assets the sync doesn't touch, or they'd serve a new
        // cookie against an old-cookie certificate.
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![html_asset("/page.html", b"<html></html>")],
        );

        // First capture (was `None`): the cookie is published and certified.
        state.capture_env_at_sync_start(&env_with(&[("PUBLIC_X", "one")]));
        let r1 = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        let cookie1 = all_headers(&r1, "set-cookie")[0].to_string();
        assert!(parse_like_client(&cookie1)
            .1
            .get("PUBLIC_X")
            .is_some_and(|v| v == "one"));

        // Capturing the *same* env again is a no-op: still certified, unchanged.
        state.capture_env_at_sync_start(&env_with(&[("PUBLIC_X", "one")]));
        let r2 = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        assert_eq!(all_headers(&r2, "set-cookie")[0], cookie1);

        // A *changed* env re-certifies the (untouched) asset: it now serves and
        // certifies the new cookie, and the old value no longer verifies.
        state.capture_env_at_sync_start(&env_with(&[("PUBLIC_X", "two")]));
        let r3 = certified_http_request(&state, RequestBuilder::get("/page.html").build());
        let cookie3 = all_headers(&r3, "set-cookie")[0].to_string();
        assert_ne!(cookie1, cookie3);
        assert!(parse_like_client(&cookie3)
            .1
            .get("PUBLIC_X")
            .is_some_and(|v| v == "two"));

        let mut stale = r3.clone();
        for (h, v) in stale.headers.iter_mut() {
            if h.eq_ignore_ascii_case("set-cookie") {
                *v = cookie1.clone();
            }
        }
        let req = RequestBuilder::get("/page.html").build();
        assert!(
            !verify_response(&state, &req, &stale).unwrap_or(false),
            "the pre-change cookie must not verify after capture re-certified it"
        );
    }
}

// ───────── access protection ─────────
//
// These tests drive real responses through the actual boundary-node verifier
// (`certified_http_request` → `verify_response`), so a passing assertion means
// the gateway would accept the response — the multi-response-per-path scheme the
// feasibility study proved, now exercised end to end against `State`.
mod access_protection {
    use super::*;

    const HTML: &[u8] = b"<!DOCTYPE html><html><body>secret</body></html>";
    const JS: &[u8] = b"console.log(1)";
    const LOGIN: &[u8] = b"<html><body>login form</body></html>";
    const LOGIN_PAGE: &str = "/login.html";

    fn html_asset(name: &str, body: &'static [u8]) -> AssetBuilder {
        AssetBuilder::new(name, "text/html").with_encoding("identity", vec![body])
    }

    fn cookie(value: &str) -> String {
        format!("certified_assets_access={value}")
    }

    /// index.html + app.js + the login page, protection on, one long-lived token
    /// "secret" labelled "owner".
    fn protected_state() -> State {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/index.html", HTML),
                AssetBuilder::new("/app.js", "application/javascript")
                    .with_encoding("identity", vec![JS]),
                html_asset(LOGIN_PAGE, LOGIN),
            ],
        );
        state.enable_protection(LOGIN_PAGE.into());
        state
            .issue_token("secret".into(), "owner".into(), 3600, TEST_NOW)
            .unwrap();
        state
    }

    #[test]
    fn public_app_is_unchanged() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(&mut state, &ctx, vec![html_asset("/index.html", HTML)]);
        let r = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        assert_eq!(r.status_code, 200);
        // No access protection, no forced no-store.
        assert!(lookup_header(&r, "cache-control").is_none());
        assert_eq!(state.check_protection_status(), ProtectionStatus::Disabled);
    }

    #[test]
    fn unauthenticated_html_gets_certified_redirect() {
        let state = protected_state();
        let r = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        assert_eq!(r.status_code, 307);
        assert_eq!(lookup_header(&r, "location"), Some(LOGIN_PAGE));
        assert_eq!(lookup_header(&r, "cache-control"), Some("no-store"));
    }

    #[test]
    fn unauthenticated_non_html_gets_certified_401() {
        let state = protected_state();
        let r = certified_http_request(&state, RequestBuilder::get("/app.js").build());
        assert_eq!(r.status_code, 401);
        assert_eq!(lookup_header(&r, "cache-control"), Some("no-store"));
    }

    #[test]
    fn valid_cookie_serves_asset_with_no_store() {
        let state = protected_state();
        let r = certified_http_request(
            &state,
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("secret"))
                .build(),
        );
        assert_eq!(r.status_code, 200);
        assert_eq!(r.body.as_ref(), HTML);
        assert_eq!(lookup_header(&r, "cache-control"), Some("no-store"));
    }

    #[test]
    fn valid_cookie_among_other_cookies_serves_asset() {
        // The browser concatenates ic_env + analytics + certified_assets_access; access protection picks
        // ours out by plain string parsing.
        let state = protected_state();
        let r = certified_http_request(
            &state,
            RequestBuilder::get("/app.js")
                .with_header(
                    "Cookie",
                    "ic_env=xyz; certified_assets_access=secret; analytics=1",
                )
                .build(),
        );
        assert_eq!(r.status_code, 200);
        assert_eq!(r.body.as_ref(), JS);
    }

    #[test]
    fn wrong_cookie_is_rejected() {
        let state = protected_state();
        let r = certified_http_request(
            &state,
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("WRONG"))
                .build(),
        );
        assert_eq!(r.status_code, 307);
    }

    #[test]
    fn login_page_is_exempt() {
        let state = protected_state();
        // GET the login page with no cookie still serves the page.
        let r = certified_http_request(&state, RequestBuilder::get(LOGIN_PAGE).build());
        assert_eq!(r.status_code, 200);
        assert_eq!(r.body.as_ref(), LOGIN);
    }

    #[test]
    fn redeem_success_sets_cookie() {
        let state = protected_state();
        let r = certified_http_request(
            &state,
            RequestBuilder::post(LOGIN_PAGE)
                .with_body("token=secret")
                .build(),
        );
        assert_eq!(r.status_code, 302);
        assert_eq!(lookup_header(&r, "location"), Some("/"));
        let set_cookie = lookup_header(&r, "set-cookie").expect("Set-Cookie");
        assert!(
            set_cookie.contains("certified_assets_access=secret"),
            "got: {set_cookie}"
        );
        assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
        // Embedding-friendly by default: the credential must survive a cross-site
        // iframe (Caffeine-style preview), so it is a partitioned cross-site cookie.
        assert!(set_cookie.contains("SameSite=None"), "got: {set_cookie}");
        assert!(set_cookie.contains("Partitioned"), "got: {set_cookie}");
    }

    #[test]
    fn redeem_failure_returns_401() {
        let state = protected_state();
        let r = certified_http_request(
            &state,
            RequestBuilder::post(LOGIN_PAGE)
                .with_body("token=nope")
                .build(),
        );
        assert_eq!(r.status_code, 401);
    }

    #[test]
    fn expired_token_is_rejected() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/index.html", HTML),
                html_asset(LOGIN_PAGE, LOGIN),
            ],
        );
        state.enable_protection(LOGIN_PAGE.into());
        state
            .issue_token("secret".into(), "owner".into(), 1, TEST_NOW)
            .unwrap();

        // Valid at issue time.
        let ok = certified_http_request_at(
            &state,
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("secret"))
                .build(),
            TEST_NOW,
        );
        assert_eq!(ok.status_code, 200);

        // Rejected once past expiry (the 307 still verifies).
        let later = TEST_NOW + 5_000_000_000;
        let expired = certified_http_request_at(
            &state,
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("secret"))
                .build(),
            later,
        );
        assert_eq!(expired.status_code, 307);
    }

    #[test]
    fn revoke_is_live() {
        let mut state = protected_state();
        let authed = || {
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("secret"))
                .build()
        };
        assert_eq!(certified_http_request(&state, authed()).status_code, 200);

        state.revoke_token("owner");

        assert_eq!(certified_http_request(&state, authed()).status_code, 307);
        // The redeem response is gone too.
        let redeem = certified_http_request(
            &state,
            RequestBuilder::post(LOGIN_PAGE)
                .with_body("token=secret")
                .build(),
        );
        assert_eq!(redeem.status_code, 401);
    }

    #[test]
    fn spa_route_with_root_rule() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/index.html", HTML),
                html_asset(LOGIN_PAGE, LOGIN),
            ],
        );
        set_root_spa_rule(&mut state, "/index.html");
        state.enable_protection(LOGIN_PAGE.into());
        state
            .issue_token("secret".into(), "owner".into(), 3600, TEST_NOW)
            .unwrap();

        // Unauthenticated SPA route -> certified root-wildcard 307.
        let r = certified_http_request(&state, RequestBuilder::get("/some/spa/route").build());
        assert_eq!(r.status_code, 307);
        assert_eq!(lookup_header(&r, "location"), Some(LOGIN_PAGE));

        // Authenticated SPA route -> the rewrite serves index.html.
        let authed = certified_http_request(
            &state,
            RequestBuilder::get("/some/spa/route")
                .with_header("Cookie", cookie("secret"))
                .build(),
        );
        assert_eq!(authed.status_code, 200);
        assert_eq!(authed.body.as_ref(), HTML);
    }

    #[test]
    fn exact_rewrite_rule_path() {
        // `/ -> /index.html` (200 rewrite): an unauthenticated GET `/` must get a
        // certified 307 at the exact rule location (a root wildcard would be
        // rejected for a path that has an exact entry).
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/index.html", HTML),
                html_asset(LOGIN_PAGE, LOGIN),
            ],
        );
        set_exact_rewrite_rule(&mut state, "/", "/index.html");
        state.enable_protection(LOGIN_PAGE.into());
        state
            .issue_token("secret".into(), "owner".into(), 3600, TEST_NOW)
            .unwrap();

        let r = certified_http_request(&state, RequestBuilder::get("/").build());
        assert_eq!(r.status_code, 307);
        let authed = certified_http_request(
            &state,
            RequestBuilder::get("/")
                .with_header("Cookie", cookie("secret"))
                .build(),
        );
        assert_eq!(authed.status_code, 200);
    }

    #[test]
    fn true_404_redirects_unauthenticated() {
        let state = protected_state();
        let r = certified_http_request(&state, RequestBuilder::get("/does-not-exist").build());
        assert_eq!(r.status_code, 307);
        assert_eq!(lookup_header(&r, "location"), Some(LOGIN_PAGE));
    }

    #[test]
    fn enable_first_then_sync_heals_status() {
        let mut state = State::default();
        let ctx = mock_system_context();

        // Enable on an empty canister (the secure ordering): degraded until synced.
        state.enable_protection(LOGIN_PAGE.into());
        assert_eq!(
            state.check_protection_status(),
            ProtectionStatus::EnabledLoginPageMissing {
                login_page: LOGIN_PAGE.into()
            }
        );
        state
            .issue_token("secret".into(), "owner".into(), 3600, TEST_NOW)
            .unwrap();

        // Sync content including the login page; assets are born protected.
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/index.html", HTML),
                html_asset(LOGIN_PAGE, LOGIN),
            ],
        );
        assert_eq!(
            state.check_protection_status(),
            ProtectionStatus::Enabled {
                login_page: LOGIN_PAGE.into()
            }
        );

        assert_eq!(
            certified_http_request(&state, RequestBuilder::get("/index.html").build()).status_code,
            307
        );
        let authed = certified_http_request(
            &state,
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("secret"))
                .build(),
        );
        assert_eq!(authed.status_code, 200);
        // The redeem cert was re-asserted after the page synced over its subtree.
        let redeem = certified_http_request(
            &state,
            RequestBuilder::post(LOGIN_PAGE)
                .with_body("token=secret")
                .build(),
        );
        assert_eq!(redeem.status_code, 302);
    }

    #[test]
    fn disable_returns_to_public() {
        let mut state = protected_state();
        state.disable_protection();
        assert_eq!(state.check_protection_status(), ProtectionStatus::Disabled);
        let r = certified_http_request(&state, RequestBuilder::get("/index.html").build());
        assert_eq!(r.status_code, 200);
        assert!(lookup_header(&r, "cache-control").is_none());
        assert!(state.list_tokens().is_empty());
    }

    #[test]
    fn protection_survives_upgrade() {
        let memory = DefaultMemoryImpl::default();
        let mut state = State::new(memory.clone());
        let ctx = mock_system_context();
        create_assets(
            &mut state,
            &ctx,
            vec![
                html_asset("/index.html", HTML),
                html_asset(LOGIN_PAGE, LOGIN),
            ],
        );
        state.enable_protection(LOGIN_PAGE.into());
        state
            .issue_token("secret".into(), "owner".into(), 3600, TEST_NOW)
            .unwrap();

        let state = upgrade(state, memory);

        assert_eq!(
            state.check_protection_status(),
            ProtectionStatus::Enabled {
                login_page: LOGIN_PAGE.into()
            }
        );
        assert_eq!(
            certified_http_request(&state, RequestBuilder::get("/index.html").build()).status_code,
            307
        );
        let authed = certified_http_request(
            &state,
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie("secret"))
                .build(),
        );
        assert_eq!(authed.status_code, 200);
        // Redeem leaf re-inserted from its stored path on upgrade.
        let redeem = certified_http_request(
            &state,
            RequestBuilder::post(LOGIN_PAGE)
                .with_body("token=secret")
                .build(),
        );
        assert_eq!(redeem.status_code, 302);
    }

    #[test]
    fn list_tokens_reports_labels() {
        let mut state = protected_state();
        state
            .issue_token("preview-token".into(), "preview".into(), 60, TEST_NOW)
            .unwrap();
        let labels: Vec<String> = state.list_tokens().into_iter().map(|t| t.label).collect();
        assert!(labels.contains(&"owner".to_string()));
        assert!(labels.contains(&"preview".to_string()));
    }

    #[test]
    fn reissuing_a_label_rotates_the_token() {
        // The label is the unique identifier: re-issuing "owner" with a new value
        // replaces the old one — old value stops working (access protection + redeem), new works,
        // and there's still exactly one token under that label.
        let mut state = protected_state(); // token "secret" labelled "owner"
        state
            .issue_token("rotated".into(), "owner".into(), 3600, TEST_NOW)
            .unwrap();

        assert_eq!(state.list_tokens().len(), 1);

        let with = |v: &str| {
            RequestBuilder::get("/index.html")
                .with_header("Cookie", cookie(v))
                .build()
        };
        assert_eq!(
            certified_http_request(&state, with("secret")).status_code,
            307
        );
        assert_eq!(
            certified_http_request(&state, with("rotated")).status_code,
            200
        );

        // The old value's redeem cert was dropped; the new one's was added.
        let redeem = |v: &str| {
            certified_http_request(
                &state,
                RequestBuilder::post(LOGIN_PAGE)
                    .with_body(format!("token={v}"))
                    .build(),
            )
            .status_code
        };
        assert_eq!(redeem("secret"), 401);
        assert_eq!(redeem("rotated"), 302);
    }

    #[test]
    fn expired_tokens_swept_on_issue() {
        let mut state = State::default();
        let ctx = mock_system_context();
        create_assets(&mut state, &ctx, vec![html_asset(LOGIN_PAGE, LOGIN)]);
        state.enable_protection(LOGIN_PAGE.into());
        state
            .issue_token("old".into(), "old".into(), 1, TEST_NOW)
            .unwrap();
        assert_eq!(state.list_tokens().len(), 1);

        // Issuing well after the first expired sweeps it.
        let later = TEST_NOW + 5_000_000_000;
        state
            .issue_token("new".into(), "new".into(), 3600, later)
            .unwrap();
        let labels: Vec<String> = state.list_tokens().into_iter().map(|t| t.label).collect();
        assert_eq!(labels, vec!["new".to_string()]);
    }

    #[test]
    fn issue_token_requires_protection_enabled() {
        let mut state = State::default();
        let err = state
            .issue_token("v".into(), "l".into(), 60, TEST_NOW)
            .unwrap_err();
        assert!(err.contains("not enabled"), "got: {err}");
    }
}
