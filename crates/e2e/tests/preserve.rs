//! `upload_asset` + `_preserve`: the discouraged escape hatch for a file that is
//! written outside a deploy and kept across later ones.

use e2e::{LocalNetwork, committed_doc, documented_calls, http_fetch, icp_cmd, setup_example};
use reqwest::StatusCode;
use std::fs;

const ORIGINS: &str = "/.well-known/ii-alternative-origins";

/// Deploys and returns the combined output. `--debug` surfaces the sync plugin's
/// own log lines, which is where it reports what it kept.
fn deploy(project: &std::path::Path) -> String {
    let output = icp_cmd(project)
        .args(["--debug", "deploy"])
        .assert()
        .success()
        .get_output()
        .clone();
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

/// Upload a file with the call `docs/site-files.md` documents, then check that a
/// deploy keeps it while `_preserve` names it and deletes it once it doesn't.
///
/// Running the committed snippet, rather than a hand-written copy, is what keeps
/// the documented call form from drifting from the canister's interface.
#[test]
fn uploaded_file_survives_deploys_only_while_preserved() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);
    deploy(project);

    let calls = documented_calls(&committed_doc("docs/site-files.md"), &["upload_asset"]);
    assert_eq!(calls.len(), 1, "expected one documented upload_asset call");
    let (method, args) = &calls[0];
    icp_cmd(project)
        .args(["canister", "call", "frontend", method, args])
        .assert()
        .success();

    let response = http_fetch(project, ORIGINS);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().unwrap(),
        r#"{"alternativeOrigins":["https://example.com"]}"#
    );

    // Kept: the project doesn't ship the file, but `_preserve` names it.
    fs::write(project.join("dist/_preserve"), format!("{ORIGINS}\n")).unwrap();
    let output = deploy(project);
    assert!(
        output.contains("keeping 1 preserved asset(s)"),
        "expected the deploy to report the kept file; got:\n{output}"
    );
    assert_eq!(http_fetch(project, ORIGINS).status(), StatusCode::OK);

    // Not named any more: an ordinary deploy deletes it.
    fs::remove_file(project.join("dist/_preserve")).unwrap();
    deploy(project);
    assert_eq!(http_fetch(project, ORIGINS).status(), StatusCode::NOT_FOUND);
}
