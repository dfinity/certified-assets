//! End-to-end tests for the single-page-app fallback (`/* /index.html 200`).
//!
//! A SPA is the shape most exposed to the certification edge cases around
//! rewrite rules: nearly every request is answered from a *wildcard* tree
//! location that borrows another asset's body, rather than from the asset's own
//! exact location. The gateway validates the `IC-Certificate` before handing a
//! response back, so each successful fetch here is also proof the canister
//! certified that alias response — and a regression would surface as a 503
//! "Response Verification Error" rather than a wrong body.
//!
//! Deploys the `spa` example, whose committed `icp.yaml` is used unchanged (see
//! `setup_example`).

use e2e::{
    LocalNetwork, http_fetch_subdomain, http_fetch_subdomain_with_headers, icp_cmd, setup_example,
};
use reqwest::StatusCode;

const SHELL_MARKER: &str = "SPA demo";

fn header_value<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Assert `path` serves the app shell with a 200 through the browser-style
/// subdomain URL, and return the response headers for further assertions.
fn expect_shell(project: &std::path::Path, path: &str) -> reqwest::header::HeaderMap {
    let r = http_fetch_subdomain(project, path);
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "SPA fallback: GET {path} expected 200, got {}",
        r.status()
    );
    let headers = r.headers().clone();
    assert!(
        header_value(&headers, "content-type").is_some_and(|ct| ct.starts_with("text/html")),
        "SPA fallback: GET {path} should serve the HTML shell, got content-type {:?}",
        header_value(&headers, "content-type")
    );
    let body = r.text().expect("read body");
    assert!(
        body.contains(SHELL_MARKER),
        "SPA fallback: GET {path} expected the shell body, got: {body}"
    );
    headers
}

/// The headline behaviour: paths with no asset behind them serve the shell with
/// a certified 200, at any depth, while real files still win.
#[test]
fn spa_fallback_serves_shell_and_files_still_win() {
    let tmp = setup_example("spa");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // The root, served by the synthesised `/ -> /index.html` rewrite.
    expect_shell(project, "/");

    // Client routes: no asset, no synthesised rule — only `/*` can answer these.
    // A full reload of a nested route is the case that breaks on hosts without a
    // SPA fallback.
    expect_shell(project, "/dashboard");
    expect_shell(project, "/dashboard/settings/deep");
    // Not a route the app knows either — the canister still serves the shell and
    // lets the client decide it's a 404.
    expect_shell(project, "/no-such-route");

    // A real file wins over the `/*` rule, via its clean URL.
    let r = http_fetch_subdomain(project, "/legal");
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "/legal expected 200 from the static file, got {}",
        r.status()
    );
    let body = r.text().expect("read body");
    assert!(
        body.contains("Legal (static page)"),
        "/legal should serve legal.html, not the shell; got: {body}"
    );

    // Clean-URL rules are matched before `_redirects`, so aliases of real files
    // still redirect instead of falling through to `/*`.
    let r = http_fetch_subdomain(project, "/index");
    assert_eq!(
        r.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "/index expected 307, got {}",
        r.status()
    );
    assert_eq!(header_value(r.headers(), "location"), Some("/"));

    let r = http_fetch_subdomain(project, "/legal/");
    assert_eq!(
        r.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "/legal/ expected 307, got {}",
        r.status()
    );
    assert_eq!(header_value(r.headers(), "location"), Some("/legal"));
}

/// Declaring a root `/*` suppresses the site-wide 404 convention entirely: the
/// plugin neither injects its branded page nor appends the catch-all rule, so an
/// unknown path is a client route rather than a 404 — even though this project
/// ships a `404.html` of its own (wired only to `/assets/*`, below).
#[test]
fn root_catchall_suppresses_site_wide_404() {
    let tmp = setup_example("spa");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // The observable: nothing routes an unknown page path to a 404 page.
    expect_shell(project, "/no-such-route");
    expect_shell(project, "/deeply/nested/unknown");

    // The project's own 404.html is untouched — not overwritten by the branded
    // default the plugin injects when there is no root catch-all.
    let r = http_fetch_subdomain(project, "/404.html");
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().expect("read body");
    assert!(
        body.contains("404 — asset not found"),
        "/404.html should be the project's own page, got: {body}"
    );
    assert!(
        !body.contains("default page served by the assets canister"),
        "the branded default must not be injected when a root `/*` rule exists"
    );

    // Being a real file, it also gets a clean URL — and a *200*, since nothing
    // routes it as an error page site-wide. The example README says so.
    let r = http_fetch_subdomain(project, "/404");
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "/404 is the clean URL of a real file, so it 200s; got {}",
        r.status()
    );
    assert!(
        r.text()
            .expect("read body")
            .contains("404 — asset not found"),
        "/404 should serve 404.html's contents"
    );
}

/// A 4xx rule scoped above the catch-all gives build output an honest 404 instead
/// of the HTML shell, without disturbing real files under the same subtree. This
/// is the snippet `docs/routing.md` recommends for the "missing asset returns
/// HTML" caveat.
#[test]
fn scoped_4xx_rule_shields_asset_subtree_from_the_catchall() {
    let tmp = setup_example("spa");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // A stale or typo'd bundle URL: a real, certified 404 — not the shell.
    for path in [
        "/assets/app-old.js",
        "/assets/typo.js",
        "/assets/nested/x.json",
    ] {
        let r = http_fetch_subdomain(project, path);
        assert_eq!(
            r.status(),
            StatusCode::NOT_FOUND,
            "{path} expected 404 from the scoped rule, got {}",
            r.status()
        );
        let body = r.text().expect("read body");
        assert!(
            body.contains("404 — asset not found"),
            "{path} should serve /404.html, got: {body}"
        );
    }

    // The real file under the same subtree still wins over both rules.
    let r = http_fetch_subdomain(project, "/assets/app.js");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.text().expect("read body").contains("client-side router"),
        "/assets/app.js must still serve the script itself"
    );

    // And the scoped rule doesn't leak: page routes outside /assets/ still get
    // the shell, because the catch-all is matched after it.
    expect_shell(project, "/dashboard");
}

/// `_headers` patterns match the asset key, and a 200 rewrite reuses its
/// target's certified headers — so the shell carries the `Cache-Control`
/// declared for `/*.html` at every client route, not just at `/index.html`.
#[test]
fn shell_headers_reach_client_routes() {
    let tmp = setup_example("spa");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    const SHELL_CACHE: &str = "public, max-age=0, must-revalidate";
    for path in ["/", "/dashboard", "/dashboard/settings/deep"] {
        let headers = expect_shell(project, path);
        assert_eq!(
            header_value(&headers, "cache-control"),
            Some(SHELL_CACHE),
            "{path} should inherit /index.html's Cache-Control through the rewrite"
        );
    }

    // The bundle is a direct asset hit and keeps its own long-lived policy.
    let r = http_fetch_subdomain(project, "/assets/app.js");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        header_value(r.headers(), "cache-control"),
        Some("public, max-age=31536000, immutable"),
    );
    // Served as a script, not as the HTML shell — the `/*` rule never sees it.
    assert!(
        header_value(r.headers(), "content-type").is_some_and(|ct| ct.contains("javascript")),
        "/assets/app.js should be served as a script, got content-type {:?}",
        header_value(r.headers(), "content-type")
    );
}

/// A browser reload of a client route sends `If-None-Match`. The 304 must be
/// certified *at the wildcard alias location*, not only at `/index.html` — the
/// gateway rejects an uncertified 304, which showed up in the wild as a 503 on
/// refresh of any aliased path.
#[test]
fn conditional_request_on_client_route_yields_certified_304() {
    let tmp = setup_example("spa");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    for path in ["/", "/dashboard", "/dashboard/settings/deep"] {
        let headers = expect_shell(project, path);
        let etag = header_value(&headers, "etag")
            .unwrap_or_else(|| panic!("{path} must carry an ETag"))
            .to_string();

        let r = http_fetch_subdomain_with_headers(project, path, &[("If-None-Match", &etag)]);
        assert_eq!(
            r.status(),
            StatusCode::NOT_MODIFIED,
            "revalidating {path} expected a certified 304, got {} \
             (a 503 here means the 304 wasn't certified at the alias location)",
            r.status()
        );
        assert!(
            r.bytes().expect("read body").is_empty(),
            "304 for {path} must have an empty body"
        );
    }

    // A stale validator still serves the full shell.
    let stale = "\"0000000000000000000000000000000000000000000000000000000000000000\"";
    let r = http_fetch_subdomain_with_headers(project, "/dashboard", &[("If-None-Match", stale)]);
    assert_eq!(r.status(), StatusCode::OK);
    assert!(!r.bytes().expect("read body").is_empty());
}
