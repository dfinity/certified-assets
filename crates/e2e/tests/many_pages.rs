//! A site with many HTML pages.
//!
//! Every HTML page synthesises ~5 redirect rules (`html_handling`), so a few
//! thousand pages make ten thousand rules. Certifying them all costs more than
//! one message's instruction limit, which once made such a site undeployable:
//! the canister rebuilt every rule in the single step that replaced the list,
//! and again at the end of every later `execute_operations` call. The
//! protection toggles and `refresh_env`, which re-certify every asset as well,
//! hit the same limit. This deploys such a site, re-syncs a one-page edit,
//! toggles protection both ways and refreshes the env, all of which must spread
//! the certification across messages.

use e2e::{LocalNetwork, http_fetch, http_fetch_with_headers, icp_cmd, setup_project};
use reqwest::StatusCode;
use std::{fs, path::Path};

/// Enough pages that certifying their rules in one message exceeds the 40B
/// instruction limit (2000 pages ≈ 10k rules was the first size observed to fail).
const PAGES: usize = 2000;

fn write_page(dist: &Path, i: usize, body: &str) {
    // Big enough to be worth compressing, so each page carries several
    // encodings — and its `200` rewrite several certified leaves per encoding.
    let filler = "<p>lorem ipsum dolor sit amet</p>\n".repeat(64);
    let dir = dist.join(format!("p{i}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("index.html"),
        format!("<html><body>{body}{filler}</body></html>"),
    )
    .unwrap();
}

/// Run a controller `icp canister call frontend <method> <candid-args>`.
fn call(project: &Path, method: &str, args: &str) {
    icp_cmd(project)
        .args(["canister", "call", "frontend", method, args])
        .assert()
        .success();
}

#[test]
fn many_html_pages_deploy_resync_and_toggle_protection() {
    let tmp = setup_project("many-pages");
    let project = tmp.path();
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(dist.join("index.html"), "<html><body>home</body></html>").unwrap();
    for i in 0..PAGES {
        write_page(&dist, i, &format!("page {i}"));
    }
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let last = format!("/p{}/", PAGES - 1);
    let r = http_fetch(project, &last);
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().unwrap().contains(&format!("page {}", PAGES - 1)));
    // A synthesised redirect: `/pN` → `/pN/`.
    let r = http_fetch(project, &format!("/p{}", PAGES - 1));
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);

    // Edit one page: the re-sync's single `execute_operations` call must not
    // rebuild every rule.
    write_page(&dist, 7, "page 7, edited");
    icp_cmd(project).arg("deploy").assert().success();

    let r = http_fetch(project, "/p7/");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().unwrap().contains("page 7, edited"));
    let r = http_fetch(project, &last);
    assert_eq!(r.status(), StatusCode::OK);

    // Protection on: every page (and every rule) is re-certified as gated.
    call(project, "enable_protection", "(\"/index.html\")");
    call(
        project,
        "issue_token",
        "(record { label = \"owner\"; ttl_secs = 3600 : nat32; value = opt \"secret\" })",
    );
    let r = http_fetch(project, &last);
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    let r = http_fetch(project, &format!("/p{}", PAGES - 1));
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    let r = http_fetch_with_headers(
        project,
        &last,
        &[("Cookie", "certified_assets_access=secret")],
    );
    assert_eq!(r.status(), StatusCode::OK);

    // Re-publishing the env re-certifies every HTML page.
    call(project, "refresh_env", "()");
    let r = http_fetch_with_headers(
        project,
        "/p7/",
        &[("Cookie", "certified_assets_access=secret")],
    );
    assert_eq!(r.status(), StatusCode::OK);

    // Protection off: public again.
    call(project, "disable_protection", "()");
    let r = http_fetch(project, &last);
    assert_eq!(r.status(), StatusCode::OK);
}
