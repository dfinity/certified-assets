//! Integration tests for `_redirects` end-to-end via the WASM plugin.
//!
//! Each test deploys a fixture to a local replica, then fetches paths via the
//! HTTP gateway. The gateway validates the response's `IC-Certificate` before
//! handing it back, so a successful fetch is also proof of certification.

use e2e::{http_fetch, http_fetch_subdomain, icp_cmd, setup_project, LocalNetwork};
use reqwest::StatusCode;

/// Deploy the `redirects` fixture and exercise every response kind:
/// 3xx redirect (internal + external), 4xx custom error page, 200 rewrite
/// (exact and subtree).
#[test]
fn redirect_rules_honoured() {
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

/// Without a user-supplied `_redirects`, the plugin auto-synthesises
/// Cloudflare's `auto-trailing-slash` rule set for every HTML asset (see
/// `sync-core::html_handling`). This test deploys an HTML-only fixture
/// and walks the full CF table for each of the three asset shapes:
/// root index, directory index, and non-index HTML file.
///
/// Two rows of CF's table are knowingly inert: the source-URL 307s from
/// `/foo.html → /foo` and `/blog/index.html → /blog/` (and the root
/// `/index.html → /`). The asset at those keys shadows the rule, so the
/// canister returns the asset's body with a 200 instead of redirecting.
/// The test asserts that observed behaviour rather than CF's strict 307.
#[test]
fn html_handling_auto_synthesis() {
    let tmp = setup_project("tests/fixture/html-handling");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // ── /foo.html (non-index): canonical /foo ───────────────────────────────
    expect_200(project, "/foo", "foo.html body");
    // /foo.html: inert — asset shadows the synthesised 307.
    expect_200(project, "/foo.html", "foo.html body");
    expect_307(project, "/foo/", "/foo");
    expect_307(project, "/foo/index", "/foo");
    expect_307(project, "/foo/index.html", "/foo");

    // ── /blog/index.html (directory index): canonical /blog/ ───────────────
    expect_200(project, "/blog/", "blog index body");
    expect_307(project, "/blog", "/blog/");
    // CF chains: /blog.html -> /blog -> /blog/. The 307 the canister emits
    // points at the bare form; the client follows it to land on /blog/.
    expect_307(project, "/blog.html", "/blog");
    expect_307(project, "/blog/index", "/blog");
    // /blog/index.html: inert — asset shadows the synthesised 307.
    expect_200(project, "/blog/index.html", "blog index body");

    // ── /index.html (root index): canonical / ───────────────────────────────
    expect_200(project, "/", "root index body");
    expect_307(project, "/index", "/");
    // /index.html: inert — asset shadows the synthesised 307.
    expect_200(project, "/index.html", "root index body");
}

/// When a rule is removed from `_redirects` between deploys, the canister
/// must not leave an orphaned cert-tree path behind. The HTTP gateway's
/// verifier rejects wildcard `<*>` witnesses if a "potential exact
/// expression path" is visible at the requested URL, so a dangling Exact
/// entry from a deleted rule will turn the removed path into a 503 for
/// any subsequent request — including ones the user expected the SPA
/// catch-all to handle.
///
/// This test deploys once with a marker rule, verifies it works, removes
/// the rule from `_redirects`, redeploys, and verifies the marker path
/// now falls through cleanly to the catch-all 404 rather than 503-ing.
#[test]
fn removed_redirect_rule_clears_cert_tree() {
    let tmp = setup_project("tests/fixture/html-handling-with-catchall");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    let redirects_path = project.join("dist/_redirects");
    let original = std::fs::read_to_string(&redirects_path).expect("read original");
    // Prepend a marker that can't collide with auto-synth (no matching
    // .html source for this path).
    std::fs::write(
        &redirects_path,
        format!("/marker-path /index.html 307\n{original}"),
    )
    .expect("write augmented _redirects");

    icp_cmd(project).arg("deploy").assert().success();

    let r = http_fetch_subdomain(project, "/marker-path");
    assert_eq!(
        r.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "before removal: /marker-path expected 307, got {}",
        r.status()
    );

    // Remove the marker, leaving only the user's catch-all + synth.
    std::fs::write(&redirects_path, &original).expect("restore _redirects");
    icp_cmd(project).arg("deploy").assert().success();

    let r = http_fetch_subdomain(project, "/marker-path");
    // After the fix, the cert tree no longer has an Exact entry at this
    // path, so the user's `/* /404.html 404` catch-all takes over cleanly.
    // Before the fix, the orphaned subtree confused the verifier and the
    // gateway returned 503 instead.
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "after removal: /marker-path expected 404 from catch-all, got {} \
         (a 503 here means the cert-tree entry wasn't pruned)",
        r.status()
    );
    let body = r.text().expect("read body");
    assert!(
        body.contains("custom 404"),
        "expected /404.html body from catch-all, got: {body}"
    );
}

fn expect_200(project: &std::path::Path, path: &str, body_marker: &str) {
    let r = http_fetch(project, path);
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "html-handling: GET {path} expected 200, got {}",
        r.status()
    );
    let body = r.text().expect("read body");
    assert!(
        body.contains(body_marker),
        "html-handling: GET {path} expected body containing {body_marker:?}, got: {body}"
    );
}

/// Reproduces the in-the-wild bug report: a user `_redirects` with a SPA-style
/// `/* /404.html 404` catch-all combined with auto-synthesised html-handling
/// rules caused the gateway verifier to reject responses with 503
/// "Response Verification Error" — the wildcard expression path the
/// canister returned for paths matched by `/*` conflicted with the Exact
/// expression paths the synthesised rules had certified in the tree.
///
/// The fix prepends synth rules before the user's `_redirects`, so the
/// html-handling defaults claim their paths first and `/* … 404` only fires
/// for paths no HTML asset covers. The verifier then sees consistent
/// expression paths on every response.
///
/// This test exercises both code paths the gateway differentiates between:
/// the subdomain-style URL the browser uses (which forces full v2
/// verification) and the explicit `?canisterId=…` form.
#[test]
fn html_handling_with_catchall_redirect() {
    let tmp = setup_project("tests/fixture/html-handling-with-catchall");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);
    icp_cmd(project).arg("deploy").assert().success();

    // The headline regression: `/` via the browser-style subdomain URL must
    // 200-serve the root index, not 503 with a verification error.
    let r = http_fetch_subdomain(project, "/");
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "root via subdomain expected 200 (was 503 before the fix), got {}",
        r.status()
    );
    let body = r.text().expect("read body");
    assert!(
        body.contains("root index body"),
        "expected /index.html body, got: {body}"
    );

    // `/index` is the other failure mode: the synthesised 307 was certified
    // at `["http_expr", "index", "<$>"]`, but the user's `/*` matched first
    // at request time and returned a `<*>` wildcard witness. The verifier
    // then refused the wildcard because the Exact entry existed in the tree.
    let r = http_fetch_subdomain(project, "/index");
    assert_eq!(
        r.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "/index expected 307, got {}",
        r.status()
    );
    assert_eq!(
        r.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/"),
    );

    // The catch-all still does its job for paths nothing else covers.
    let r = http_fetch_subdomain(project, "/this-path-does-not-exist");
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "catch-all expected 404, got {}",
        r.status()
    );
    let body = r.text().expect("read body");
    assert!(
        body.contains("custom 404"),
        "expected /404.html body, got: {body}"
    );
}

fn expect_307(project: &std::path::Path, path: &str, location: &str) {
    let r = http_fetch(project, path);
    assert_eq!(
        r.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "html-handling: GET {path} expected 307, got {}",
        r.status()
    );
    let actual = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        actual.as_deref(),
        Some(location),
        "html-handling: GET {path} expected Location {location}, got {actual:?}"
    );
}
