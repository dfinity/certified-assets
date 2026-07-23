//! End-to-end test for ETag / conditional requests through the HTTP gateway.
//!
//! The gateway validates the response's `IC-Certificate` before returning it,
//! so a 304 that reaches the caller is proof the canister served a *certified*
//! 304 — exactly the property that lets ETag work without any gateway-side
//! support (BOUN-446 was closed "won't do" for this reason).

use e2e::{LocalNetwork, http_fetch, http_fetch_with_headers, icp_cmd, setup_example};
use reqwest::StatusCode;

fn etag_of(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("response must carry an ETag")
        .to_string()
}

/// Deploy, read an asset's ETag, then revalidate with `If-None-Match`:
/// a matching validator yields a certified 304 with an empty body, while a
/// stale validator still serves the full 200.
#[test]
fn conditional_request_yields_certified_304() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // First load: full body + a canister-minted ETag (the content hash).
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    let etag = etag_of(r.headers());
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "ETag should be a quoted strong validator, got {etag}"
    );
    assert!(!r.bytes().unwrap().is_empty(), "200 should carry a body");

    // Revalidate with the matching ETag: certified 304, empty body. The fetch
    // succeeding at all means the gateway accepted the certified 304.
    let not_modified = http_fetch_with_headers(project, "/index.html", &[("If-None-Match", &etag)]);
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        etag_of(not_modified.headers()),
        etag,
        "304 should echo the ETag (RFC 7232 §4.1)"
    );
    assert!(
        not_modified.bytes().unwrap().is_empty(),
        "304 must have an empty body"
    );

    // A stale validator does not match: full, certified 200 again.
    let stale = "\"0000000000000000000000000000000000000000000000000000000000000000\"";
    let modified = http_fetch_with_headers(project, "/index.html", &[("If-None-Match", stale)]);
    assert_eq!(modified.status(), StatusCode::OK);
    assert!(
        !modified.bytes().unwrap().is_empty(),
        "stale If-None-Match should serve the full body"
    );

    // Regression: the same round-trip against the `/` alias (the `/ →
    // /index.html` 200 rewrite a browser actually navigates to), not just the
    // direct asset path. A normal browser refresh of `/` sends `If-None-Match`,
    // so the alias serves a 304 — which must be certified at the *alias*
    // location or the gateway rejects it with a Response Verification Error. The
    // direct hit above once passed while this failed, masking the bug.
    let root = http_fetch(project, "/");
    assert_eq!(root.status(), StatusCode::OK);
    let root_etag = etag_of(root.headers());
    assert!(
        !root.bytes().unwrap().is_empty(),
        "`/` 200 should carry a body"
    );

    let root_not_modified = http_fetch_with_headers(project, "/", &[("If-None-Match", &root_etag)]);
    assert_eq!(
        root_not_modified.status(),
        StatusCode::NOT_MODIFIED,
        "conditional GET of the `/` alias must yield a certified 304"
    );
    assert!(
        root_not_modified.bytes().unwrap().is_empty(),
        "304 must have an empty body"
    );
}
