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
