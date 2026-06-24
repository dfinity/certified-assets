use e2e::{http_fetch_with_headers, icp_cmd, setup_project, LocalNetwork};
use reqwest::StatusCode;
use std::fs;

/// Deterministic, incompressible bytes via a xorshift64 PRNG. Incompressibility
/// matters: it keeps the asset a single `Identity` encoding (the sync plugin
/// only stores a compressed copy when it is actually smaller), so the encoding
/// the gateway serves is unambiguous and the served bytes equal what we wrote.
fn incompressible_bytes(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// A multi-megabyte asset must round-trip byte-for-byte through the HTTP gateway.
///
/// This is the one property the `canister-core` unit tests structurally cannot
/// cover: that an asset larger than a single `http_request` response actually
/// reassembles correctly via the streaming-callback protocol *and* that the
/// reassembled body verifies against the certified hash.
///
/// - The body is ~5 MB, well over 2 × `MAX_CHUNK_SIZE` (1.9 MB), so the canister
///   stores it as three chunks. A single query response is capped far below that,
///   so the full body can only come back intact via streaming callbacks — a
///   broken stream would truncate to the first chunk.
/// - `http_fetch_*` goes through the boundary node, which validates the
///   `IC-Certificate` before returning anything. An exact-match fetch therefore
///   also proves the streamed reassembly matches the certified content hash.
#[test]
fn streams_large_asset_through_gateway() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();

    let body = incompressible_bytes(5_000_000);
    fs::write(project.join("dist/large.bin"), &body).expect("write large asset into fixture");

    let _network = LocalNetwork::start(project);
    icp_cmd(project).arg("deploy").assert().success();

    // `Accept-Encoding: identity` pins the served encoding and stops reqwest /
    // the gateway from negotiating compression, so the bytes we compare are the
    // raw asset bytes.
    let response =
        http_fetch_with_headers(project, "/large.bin", &[("Accept-Encoding", "identity")]);
    assert_eq!(response.status(), StatusCode::OK);

    let fetched = response
        .bytes()
        .expect("read streamed response body")
        .to_vec();
    assert_eq!(
        fetched.len(),
        body.len(),
        "streamed body length mismatch: got {} bytes, expected {} \
         (a truncated body means streaming did not reassemble all chunks)",
        fetched.len(),
        body.len(),
    );
    assert!(
        fetched == body,
        "streamed body bytes differ from the uploaded asset",
    );
}

/// Phase 0 spike (Flow A): a client `Range` request returns a **certified** `206`.
///
/// The asset is ~5 MB → three 1.9 MB chunks. Byte 2_500_000 falls inside chunk 1
/// (`[1_900_000, 3_800_000)`). The canister snaps the range start down to that
/// chunk and returns it as a `206` with `Content-Range: bytes 1900000-3799999/5000000`.
///
/// Crucially, `http_fetch_*` goes through the boundary node, which validates the
/// `IC-Certificate` before returning anything. A `206` with the right bytes
/// therefore proves the **response-only** certification of the chunk verifies
/// end-to-end — the central unknown this spike exists to settle.
#[test]
fn range_request_returns_certified_206() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();

    let body = incompressible_bytes(5_000_000);
    fs::write(project.join("dist/large.bin"), &body).expect("write large asset into fixture");

    let _network = LocalNetwork::start(project);
    icp_cmd(project).arg("deploy").assert().success();

    let response = http_fetch_with_headers(
        project,
        "/large.bin",
        &[("Accept-Encoding", "identity"), ("Range", "bytes=2500000-")],
    );

    assert_eq!(
        response.status(),
        StatusCode::PARTIAL_CONTENT,
        "expected 206; a non-206 (esp. 500) means the response-only certified \
         range response failed gateway verification",
    );

    let content_range = response
        .headers()
        .get("content-range")
        .expect("206 must carry Content-Range")
        .to_str()
        .expect("Content-Range is ascii")
        .to_string();
    assert_eq!(content_range, "bytes 1900000-3799999/5000000");

    let fetched = response.bytes().expect("read 206 body").to_vec();
    assert_eq!(
        fetched,
        body[1_900_000..3_800_000],
        "206 body must equal the containing chunk's bytes",
    );
}
