//! Integration test for the certified `ic_env` cookie, end-to-end via the WASM
//! plugin and the HTTP gateway.
//!
//! A plain `icp deploy` runs a sync, and the canister recaptures its env
//! snapshot when the sync finalizes — so an HTML response served afterwards
//! carries the certified `Set-Cookie: ic_env=…` with no explicit `refresh_env`
//! call. Going through the gateway validates the `IC-Certificate` before the
//! response reaches the test, so a successful fetch that also carries the
//! cookie is proof the cookie is part of the certified response.

use e2e::{LocalNetwork, http_fetch, icp_cmd, setup_example};
use reqwest::StatusCode;

fn set_cookies(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect()
}

/// Deploy the `static-site` example and confirm the sync publishes the certified
/// `ic_env` cookie on the HTML response (and only there).
#[test]
fn sync_publishes_certified_ic_env_cookie_on_html() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // HTML carries the env cookie, set automatically when the sync finalized —
    // no explicit `refresh_env` call. The root key is always available from the
    // system API, so the cookie is present even with no `PUBLIC_*` vars.
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    let cookies = set_cookies(r.headers());
    let ic_env: Vec<&String> = cookies
        .iter()
        .filter(|c| c.starts_with("ic_env="))
        .collect();
    assert_eq!(
        ic_env.len(),
        2,
        "expected both ic_env variants on /index.html, got: {cookies:?}"
    );
    // Readable in every context: the `Lax` variant for clients that reject
    // `SameSite=None` outright, and `SameSite=None; Secure; Partitioned` (CHIPS)
    // so page scripts can read it inside a cross-site iframe (Caffeine-style
    // preview). See `canister_core::asset::render_env_cookies`.
    assert!(
        ic_env[0].contains("SameSite=Lax") && ic_env[0].contains("Secure"),
        "first ic_env cookie should carry Secure; SameSite=Lax, got: {}",
        ic_env[0]
    );
    assert!(
        ic_env[1].contains("SameSite=None")
            && ic_env[1].contains("Secure")
            && ic_env[1].contains("Partitioned"),
        "second ic_env cookie should carry SameSite=None; Secure; Partitioned, got: {}",
        ic_env[1]
    );
    // One cookie per host, outliving the browsing session.
    for c in &ic_env {
        assert!(c.contains("; Path=/;"), "expected Path=/, got: {c}");
        assert!(c.contains("; Max-Age="), "expected Max-Age, got: {c}");
    }

    // A non-HTML asset carries no env cookie.
    let r = http_fetch(project, "/style.css");
    assert_eq!(r.status(), StatusCode::OK);
    let cookies = set_cookies(r.headers());
    assert!(
        !cookies.iter().any(|c| c.starts_with("ic_env=")),
        "css must not carry the env cookie, got: {cookies:?}"
    );
}
