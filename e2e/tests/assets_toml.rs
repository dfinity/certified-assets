//! Integration tests for `assets.toml` end-to-end via the WASM plugin.
//!
//! Each test deploys a fixture to a local replica, then fetches assets via
//! the HTTP gateway. The gateway validates the response's `IC-Certificate`
//! before handing it back, so a successful fetch is also proof that the
//! content-type the plugin sent to the canister is the one that ended up
//! in the certified response.

use e2e::{http_fetch, icp_cmd, setup_project, LocalNetwork};
use reqwest::StatusCode;
use std::fs;

fn content_type(headers: &reqwest::header::HeaderMap) -> &str {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// Deploy the `assets-toml` fixture and verify every per-glob `content_type`
/// override survives certification and reaches the HTTP gateway.
#[test]
fn content_type_overrides_land_on_canister() {
    let tmp = setup_project("tests/fixture/assets-toml");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // .did → text/plain; charset=utf-8 (mime_guess has no entry, so the
    // pre-override default would have been application/octet-stream).
    let r = http_fetch(project, "/ic.did");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(content_type(r.headers()), "text/plain; charset=utf-8");

    // .sh → text/plain; charset=utf-8 (mime_guess returns application/x-sh
    // by default; the override replaces it).
    let r = http_fetch(project, "/install.sh");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(content_type(r.headers()), "text/plain; charset=utf-8");

    // Exact-path override: llms.txt — mime_guess returns plain text/plain
    // without a charset; the override adds the charset parameter.
    let r = http_fetch(project, "/llms.txt");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(content_type(r.headers()), "text/plain; charset=utf-8");

    // No override → mime_guess default applies (index.html stays text/html).
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        content_type(r.headers()).starts_with("text/html"),
        "expected text/html for index.html, got: {}",
        content_type(r.headers())
    );
}

/// Edit `assets.toml` and redeploy. Expectation: the new content-type lands
/// on the canister (via delete-then-recreate triggered by content-type
/// drift), and the gateway serves the updated value.
#[test]
fn content_type_edit_propagates_on_redeploy() {
    let tmp = setup_project("tests/fixture/assets-toml");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // Sanity check the initial value.
    let r = http_fetch(project, "/ic.did");
    assert_eq!(content_type(r.headers()), "text/plain; charset=utf-8");

    // Flip the .did mapping to a different MIME without touching the file.
    fs::write(
        project.join("assets.toml"),
        b"[[asset]]\nmatch = \"/*.did\"\ncontent_type = \"application/json\"\n",
    )
    .expect("rewrite assets.toml");

    icp_cmd(project).arg("deploy").assert().success();

    let r = http_fetch(project, "/ic.did");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        content_type(r.headers()),
        "application/json",
        "edited assets.toml should propagate the new Content-Type via delete-then-recreate",
    );
}
