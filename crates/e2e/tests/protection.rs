//! End-to-end test for access protection (the "private app" gate), driven
//! through the real `icp` CLI and the local HTTP gateway. Every assertion below
//! goes through the gateway, so a passing status code means the gateway accepted
//! the canister's *certified* response — the multi-response-per-path scheme working
//! against the production verifier, not just the in-process one the unit tests use.
//!
//! The project deployed here is the runnable showcase at
//! `examples/access-protection/`. It is deployed from a throwaway copy of that
//! directory (see `setup_example`) using its committed `icp.yaml` *unchanged* —
//! the same file, referencing the repo's `dist/` wasms, that a human runs. This
//! test both verifies the feature and guarantees the example stays deployable
//! (see its README), while a developer's own manual run of the example is never
//! disturbed.

use e2e::{
    frontend_canister_id, http_fetch, http_fetch_with_headers, http_post_form, icp_cmd,
    setup_example, LocalNetwork,
};
use reqwest::StatusCode;

/// Run a controller `icp canister call frontend <method> <candid-args>`.
fn call(project: &std::path::Path, method: &str, args: &str) {
    icp_cmd(project)
        .args(["canister", "call", "frontend", method, args])
        .assert()
        .success();
}

#[test]
fn protected_app_gates_unauthenticated_requests() {
    let tmp = setup_example("access-protection");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // Public before enabling: index.html serves its content.
    assert_eq!(http_fetch(project, "/index.html").status(), StatusCode::OK);

    // Enable protection and mint one chosen-value token (a "password").
    call(project, "enable_protection", "(\"/login.html\")");
    call(
        project,
        "issue_token",
        "(record { label = \"owner\"; ttl_secs = 3600 : nat32; value = opt \"secret\" })",
    );

    // Unauthenticated HTML → certified 307 to the login page.
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        r.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/login.html"),
    );

    // Unauthenticated non-HTML → certified 401 (not a redirect, which would hand
    // a <script> the wrong content type).
    assert_eq!(
        http_fetch(project, "/app.js").status(),
        StatusCode::UNAUTHORIZED,
    );

    // The login page is gate-exempt: it serves even with no cookie.
    assert_eq!(http_fetch(project, "/login.html").status(), StatusCode::OK);

    // A valid cookie unlocks the asset (no-store on the certified response).
    let r = http_fetch_with_headers(
        project,
        "/index.html",
        &[("Cookie", "certified_assets_access=secret")],
    );
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
    );

    // A wrong cookie is still gated.
    let r = http_fetch_with_headers(
        project,
        "/index.html",
        &[("Cookie", "certified_assets_access=nope")],
    );
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);

    // Redeeming the right token through the login POST returns a certified
    // 302 + Set-Cookie (delivered only because it is certified).
    let r = http_post_form(project, "/login.html", "token=secret", &[]);
    assert_eq!(r.status(), StatusCode::FOUND);
    let set_cookie = r
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("redeem must Set-Cookie");
    assert!(
        set_cookie.contains("certified_assets_access=secret"),
        "got: {set_cookie}"
    );
    assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
    // Embeddable by default: the credential must survive a cross-site iframe
    // (Caffeine-style preview), so it is a partitioned cross-site cookie.
    assert!(set_cookie.contains("SameSite=None"), "got: {set_cookie}");
    assert!(set_cookie.contains("Partitioned"), "got: {set_cookie}");

    // A wrong password re-prompts with a certified 401.
    assert_eq!(
        http_post_form(project, "/login.html", "token=nope", &[]).status(),
        StatusCode::UNAUTHORIZED,
    );

    // Disabling restores the fully public app.
    call(project, "disable_protection", "()");
    let r = http_fetch(project, "/index.html");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers().get("cache-control").is_none(),
        "no-store must be gone once public",
    );

    // Sanity: same canister throughout.
    assert!(!frontend_canister_id(project).is_empty());
}
