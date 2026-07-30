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
    LocalNetwork, frontend_canister_id, http_fetch, http_fetch_with_headers, http_post_form,
    icp_cmd, setup_example,
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

/// The management methods a user reaches for are only ever *documented*, never
/// called by the tests above under the form the docs print. That gap shipped a
/// broken quick start (#116): `issue_token` was written with three positional
/// arguments instead of the single `IssueTokenArgs` record, in a copy-pasteable
/// `sh` block *and* in the reference table, while this file called it correctly
/// by hand. So: run what the docs actually say.
///
/// Every `<method> '<candid>'` pair in the committed markdown is extracted and
/// sent to the deployed canister. A rejected snippet fails this test — the CLI
/// exits non-zero whether the mismatch is caught locally against the canister's
/// candid interface or by the canister trapping on decode.
///
/// Each snippet is judged on its own candid form: `issue_token` is the one call
/// the canister refuses while the gate is off, so the gate is re-enabled before
/// each of those rather than depending on where `disable_protection` happens to
/// sit in the document. Whether the documented *sequence* works is what
/// `protected_app_gates_unauthenticated_requests` above covers.
#[test]
fn documented_calls_are_accepted_by_the_canister() {
    let tmp = setup_example("access-protection");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // crates/e2e -> crates -> repo root. Read the committed docs, not the copy's,
    // so this guards the files a reader lands on.
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/e2e/ must have a repo root two levels up");

    let mut covered = std::collections::BTreeSet::new();
    for source in [
        "docs/access-protection.md",
        "examples/access-protection/README.md",
    ] {
        let markdown =
            std::fs::read_to_string(repo.join(source)).unwrap_or_else(|e| panic!("{source}: {e}"));
        for (method, args) in documented_calls(&markdown) {
            if method == "issue_token" {
                call(project, "enable_protection", "(\"/login.html\")");
            }
            // Printed first so a failure below is attributed to a document.
            eprintln!("{source}: icp canister call frontend {method} '{args}'");
            call(project, &method, &args);
            covered.insert(method);
        }
    }

    // Guards the extraction itself: a reformatted table that stopped matching
    // would otherwise let this test pass while checking nothing.
    assert_eq!(
        covered.into_iter().collect::<Vec<_>>(),
        {
            let mut all = METHODS.to_vec();
            all.sort_unstable();
            all
        },
        "the docs must show a runnable form of every management method",
    );
}

/// The management surface `docs/access-protection.md` and the example's README
/// document. Both files list all of them.
const METHODS: [&str; 6] = [
    "enable_protection",
    "disable_protection",
    "issue_token",
    "revoke_token",
    "list_tokens",
    "check_protection_status",
];

/// Reference forms are written with placeholders; fill in concrete values so the
/// snippet can be sent as-is. A placeholder left unfilled fails the test rather
/// than skipping the snippet — a new spelling belongs here, not in a hole in the
/// coverage.
const PLACEHOLDERS: [(&str, &str); 5] = [
    ("<label>", "doc-label"),
    ("<value>", "doc-secret"),
    ("<secs>", "3600"),
    ("= N :", "= 3600 :"),
    ("...", "doc"),
];

/// Extracts every documented `(method, candid-args)` pair from `markdown`, in
/// document order — the same shape whether it sits in a fenced `icp canister call
/// frontend …` line or in a reference-table cell, so both stay checked.
fn documented_calls(markdown: &str) -> Vec<(String, String)> {
    // A shell line continued with `\` puts the method and its argument on
    // different source lines (the quick start does); glue those back together.
    let text = markdown
        .split("\\\n")
        .fold(String::new(), |mut acc, piece| {
            if acc.is_empty() {
                acc.push_str(piece);
            } else {
                acc.push_str(piece.trim_start());
            }
            acc
        });

    let mut calls: Vec<(usize, String, String)> = Vec::new();
    for method in METHODS {
        let mut from = 0;
        while let Some(offset) = text[from..].find(method) {
            let start = from + offset;
            from = start + method.len();
            // Reject a name embedded in a longer identifier, and require the
            // argument to follow immediately — prose like "the `issue_token`
            // call" documents nothing runnable.
            let preceded_by_ident = text[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let rest = &text[from..];
            if preceded_by_ident || !rest.starts_with(" '") {
                continue;
            }
            let Some(end) = rest[2..].find('\'') else {
                continue;
            };
            let mut args = rest[2..2 + end].to_string();
            for (placeholder, value) in PLACEHOLDERS {
                args = args.replace(placeholder, value);
            }
            assert!(
                !args.contains('<') && !args.contains("..."),
                "unfilled placeholder in `{method} '{args}'` — add it to PLACEHOLDERS",
            );
            calls.push((start, method.to_string(), args));
        }
    }
    calls.sort_by_key(|(offset, _, _)| *offset);
    calls
        .into_iter()
        .map(|(_, method, args)| (method, args))
        .collect()
}
