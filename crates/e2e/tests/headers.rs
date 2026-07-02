//! Integration tests for `_headers` end-to-end via the WASM plugin.
//!
//! Each test deploys a fixture to a local replica, then fetches paths via the
//! HTTP gateway. The gateway validates the response's `IC-Certificate` before
//! handing it back, so a successful fetch is also proof of certification —
//! and proof that the headers we set are the same ones the canister certified.

use e2e::{http_fetch, icp_cmd, list_assets, setup_example, LocalNetwork};
use reqwest::StatusCode;
use std::fs;

fn header_value<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Deploy the `custom-headers` example and check that exact, subtree, and global
/// header rules all reach the canister and survive certification.
#[test]
fn header_rules_honoured() {
    let tmp = setup_example("custom-headers");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // ── exact + global rules layer on /index.html ───────────────────────────
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers();
    assert_eq!(header_value(h, "x-frame-options"), Some("DENY"));
    assert_eq!(header_value(h, "x-content-type-options"), Some("nosniff"));
    assert_eq!(header_value(h, "x-robots-tag"), Some("noindex"));

    // ── subtree + global rules layer on /_astro/app.js ──────────────────────
    let r = http_fetch(project, "/_astro/app.js");
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers();
    assert_eq!(
        header_value(h, "cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(header_value(h, "x-robots-tag"), Some("noindex"));
    // No exact-rule headers leaked from /index.html.
    assert!(h.get("x-frame-options").is_none());
}

/// Edit `_headers` and redeploy. Expectation: new headers propagate without
/// re-uploading content (drift detected via `SetAssetHeaders`).
#[test]
fn header_edit_propagates_via_set_asset_headers() {
    let tmp = setup_example("custom-headers");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // Sanity-check the initial headers landed on the canister. `list` reports
    // per-asset headers, so read them from there.
    let before = list_assets(project)
        .into_iter()
        .find(|a| a.key == "/index.html")
        .expect("/index.html should be listed");
    let headers_before = before.headers;
    assert!(
        !headers_before.is_empty(),
        "/index.html should carry headers"
    );
    assert!(headers_before
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-frame-options") && v == "DENY"));

    // Bump the global X-Robots-Tag without touching any asset bytes.
    fs::write(
        project.join("dist/_headers"),
        b"/index.html\n  X-Frame-Options: DENY\n  X-Content-Type-Options: nosniff\n\n/_astro/*\n  Cache-Control: public, max-age=31536000, immutable\n\n/*\n  X-Robots-Tag: none\n",
    )
    .expect("rewrite _headers");

    icp_cmd(project).arg("deploy").assert().success();

    // Drift propagated: /index.html now serves the new X-Robots-Tag value.
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        header_value(r.headers(), "x-robots-tag"),
        Some("none"),
        "edited X-Robots-Tag should reach the canister via SetAssetHeaders",
    );
}
