//! Integration tests for `_redirects` end-to-end via the WASM plugin.
//!
//! Each test deploys a fixture to a local replica, then fetches paths via the
//! HTTP gateway. The gateway validates the response's `IC-Certificate` before
//! handing it back, so a successful fetch is also proof of certification.

use e2e::{http_fetch, icp_cmd, setup_project, LocalNetwork};
use reqwest::StatusCode;

/// Deploy the `redirects` fixture and exercise every response kind:
/// 3xx redirect (internal + external), 4xx custom error page, 200 rewrite
/// (exact and subtree).
#[test]
fn redirect_rules_honoured_end_to_end() {
    let tmp = setup_project("tests/fixture/redirects");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // ── 301 redirect to an internal path ────────────────────────────────────
    let r = http_fetch(project, "/old");
    assert_eq!(r.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        r.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        Some("/new.html".into()),
    );

    // ── 302 redirect to an external URL ─────────────────────────────────────
    let r = http_fetch(project, "/legacy");
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        r.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        Some("https://example.com/".into()),
    );

    // ── 404 custom error page ───────────────────────────────────────────────
    let r = http_fetch(project, "/missing-page");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let body = r.text().expect("read body");
    assert!(
        body.contains("custom not found"),
        "expected /404.html body, got: {body}"
    );

    // ── 410 custom error page ───────────────────────────────────────────────
    let r = http_fetch(project, "/gone-page");
    assert_eq!(r.status(), StatusCode::GONE);
    let body = r.text().expect("read body");
    assert!(
        body.contains("tombstone"),
        "expected /410.html body, got: {body}"
    );

    // ── 200 rewrite: exact ──────────────────────────────────────────────────
    let r = http_fetch(project, "/about");
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().expect("read body");
    assert!(
        body.contains("about us"),
        "expected /about.html body, got: {body}"
    );

    // ── 200 rewrite: subtree ────────────────────────────────────────────────
    for sub in &["/blog/anything", "/blog/2024/post"] {
        let r = http_fetch(project, sub);
        assert_eq!(r.status(), StatusCode::OK, "fetching {sub}");
        let body = r.text().expect("read body");
        assert!(
            body.contains("blog index"),
            "fetching {sub}: expected blog index body, got: {body}"
        );
    }
}

/// Without `_redirects`, the canister no longer aliases `/foo` → `/foo.html`
/// or `/blog` → `/blog/index.html`. Literal paths still resolve; the
/// would-be aliases return 404.
#[test]
fn no_implicit_aliasing_after_redirects_landed() {
    let tmp = setup_project("tests/fixture/no-implicit-aliasing");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // Literal paths resolve.
    let r = http_fetch(project, "/foo.html");
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().expect("read body");
    assert!(body.contains("foo at literal path"), "body: {body}");

    let r = http_fetch(project, "/blog/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().expect("read body");
    assert!(body.contains("blog index at literal path"), "body: {body}");

    // Would-be aliases return 404 — proves the canister no longer synthesises
    // routes implicitly. `_redirects` is the only mechanism.
    for path in &["/foo", "/foo/", "/blog", "/blog/"] {
        let r = http_fetch(project, path);
        assert_eq!(
            r.status(),
            StatusCode::NOT_FOUND,
            "no-aliasing: GET {path} should 404"
        );
    }
}
