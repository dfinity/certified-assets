//! Serve every interesting path through the embedded router and verify each
//! response the way the HTTP gateway does (response verification v2), against
//! a test certificate whose certified data is the router's root hash.

use candid::Principal;
use embedded_certified_assets::{HttpRequest, HttpResponse, Router};
use hello::ASSETS;
use ic_certification_testing::CertificateBuilder;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

fn get(router: &Router, url: &str, accept_encoding: Option<&str>) -> HttpResponse<'static> {
    let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let cert = CertificateBuilder::new(&canister_id.to_string(), &router.root_hash())
        .unwrap()
        .with_time(now)
        .build()
        .unwrap();

    let headers = accept_encoding
        .map(|v| vec![("Accept-Encoding".to_string(), v.to_string())])
        .unwrap_or_default();
    let req = HttpRequest::get(url).with_headers(headers).build();
    let resp = router.serve(&req, &cert.cbor_encoded_certificate);

    let verified = ic_response_verification::verify_request_response_pair(
        req,
        resp.clone(),
        canister_id.as_slice(),
        now,
        MAX_CERT_TIME_OFFSET_NS,
        &cert.root_key,
        2,
    )
    .unwrap_or_else(|e| panic!("{url}: verification failed: {e:?}"));
    assert_eq!(verified.verification_version, 2, "{url}");
    let certified = verified
        .response
        .unwrap_or_else(|| panic!("{url}: response not certified"));
    assert_eq!(
        certified.status_code,
        Some(resp.status_code().as_u16()),
        "{url}"
    );
    resp
}

fn header<'a>(resp: &'a HttpResponse, name: &str) -> Option<&'a str> {
    resp.headers()
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn body_contains(resp: &HttpResponse, needle: &str) -> bool {
    String::from_utf8_lossy(resp.body()).contains(needle)
}

#[test]
fn every_route_kind_serves_a_certified_response() {
    let router = Router::new(&ASSETS);

    // Plain asset + html-handling canonical URLs.
    let r = get(&router, "/", None);
    assert_eq!(r.status_code(), 200);
    assert!(body_contains(&r, "Hello from embedded certified assets"));
    assert_eq!(header(&r, "x-embedded"), Some("yes"), "_headers applied");

    let r = get(&router, "/about", None);
    assert_eq!(r.status_code(), 200);
    assert!(body_contains(&r, "About"));

    let r = get(&router, "/blog/", None);
    assert_eq!(r.status_code(), 200);
    assert!(body_contains(&r, "Blog"));

    // html-handling alias redirect.
    let r = get(&router, "/blog", None);
    assert_eq!(r.status_code(), 307);
    assert_eq!(header(&r, "location"), Some("/blog/"));

    // _redirects: exact 301, subtree 200 rewrite (wildcard certification).
    let r = get(&router, "/old-about", None);
    assert_eq!(r.status_code(), 301);
    assert_eq!(header(&r, "location"), Some("/about"));

    let r = get(&router, "/app/some/deep/route", None);
    assert_eq!(r.status_code(), 200);
    assert!(body_contains(&r, "App shell"));

    // Root catch-all → custom 404.html with status 404 (wildcard).
    let r = get(&router, "/does/not/exist", None);
    assert_eq!(r.status_code(), 404);
    assert!(body_contains(&r, "Nothing here"));

    // Percent-encoded paths are decoded before lookup and witnessing.
    let r = get(&router, "/abo%75t", None);
    assert_eq!(r.status_code(), 200);
}

#[test]
fn encoding_negotiation_serves_certified_variants() {
    let router = Router::new(&ASSETS);

    let br = get(&router, "/style.css", Some("gzip, deflate, br"));
    assert_eq!(header(&br, "content-encoding"), Some("br"));
    assert_eq!(
        header(&br, "cache-control"),
        Some("public, max-age=31536000, immutable")
    );

    let gz = get(&router, "/style.css", Some("gzip"));
    assert_eq!(header(&gz, "content-encoding"), Some("gzip"));

    let id = get(&router, "/style.css", None);
    assert_eq!(header(&id, "content-encoding"), None);
    assert!(id.body().len() > br.body().len());

    let refused = get(&router, "/style.css", Some("br;q=0, gzip"));
    assert_eq!(header(&refused, "content-encoding"), Some("gzip"));
}

#[test]
fn tampered_body_fails_verification() {
    let router = Router::new(&ASSETS);
    let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let cert = CertificateBuilder::new(&canister_id.to_string(), &router.root_hash())
        .unwrap()
        .with_time(now)
        .build()
        .unwrap();
    let req = HttpRequest::get("/about").build();
    let resp = router.serve(&req, &cert.cbor_encoded_certificate);
    let tampered = HttpResponse::builder()
        .with_status_code(resp.status_code())
        .with_headers(resp.headers().to_vec())
        .with_body(b"evil".to_vec())
        .build();
    let result = ic_response_verification::verify_request_response_pair(
        req,
        tampered,
        canister_id.as_slice(),
        now,
        MAX_CERT_TIME_OFFSET_NS,
        &cert.root_key,
        2,
    );
    assert!(
        !matches!(result, Ok(ref v) if v.response.is_some()),
        "tampered body must not verify"
    );
}
