use e2e::{generate_minimal_png, icp_cmd, list_assets, setup_project, AssetDetails, LocalNetwork};
use std::fs;

/// Deploy to an empty canister with one HTML file and one runtime-generated PNG.
/// Verifies both keys are present and content types are correct.
#[test]
fn initial_sync() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();

    // Write a PNG generated at runtime so no binary file is committed to the repo.
    fs::write(project.join("dist/logo.png"), generate_minimal_png())
        .expect("failed to write logo.png");

    let _network = LocalNetwork::start(project);
    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);

    let html = assets
        .iter()
        .find(|a| a.key == "/index.html")
        .expect("/index.html missing from canister after initial sync");
    assert_eq!(html.content_type, "text/html");

    let png = assets
        .iter()
        .find(|a| a.key == "/logo.png")
        .expect("/logo.png missing from canister after initial sync");
    assert_eq!(png.content_type, "image/png");
}

/// Run sync twice without modifying any files.
/// The second deploy must report "up to date" and must not change canister state.
#[test]
fn no_op_sync() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let keys_before: Vec<String> = list_assets(project).into_iter().map(|a| a.key).collect();

    let output = icp_cmd(project)
        .args(["--debug", "deploy"])
        .assert()
        .success()
        .get_output()
        .clone();
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("up to date"),
        "expected 'up to date' in deploy output on second run; got:\n{combined}",
    );

    let mut keys_after: Vec<String> = list_assets(project).into_iter().map(|a| a.key).collect();
    let mut keys_before = keys_before;
    keys_before.sort();
    keys_after.sort();
    assert_eq!(
        keys_before, keys_after,
        "canister asset list should be unchanged after no-op sync",
    );
}

fn identity_sha(assets: &[AssetDetails], key: &str) -> Option<Vec<u8>> {
    assets
        .iter()
        .find(|a| a.key == key)
        .and_then(|a| {
            a.encodings
                .iter()
                .find(|e| e.content_encoding == "identity")
        })
        .and_then(|e| e.sha256.clone())
}

/// Modify one file's content and re-sync.
/// The updated file's identity SHA256 must change; the untouched file's must not.
#[test]
fn content_update() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets_before = list_assets(project);
    let html_sha_before = identity_sha(&assets_before, "/index.html")
        .expect("/index.html identity sha256 missing before update");
    let css_sha_before = identity_sha(&assets_before, "/style.css")
        .expect("/style.css identity sha256 missing before update");

    // Overwrite index.html with clearly different content.
    fs::write(
        project.join("dist/index.html"),
        b"<html><body><h1>Updated content</h1></body></html>",
    )
    .expect("failed to overwrite index.html");

    icp_cmd(project).arg("deploy").assert().success();

    let assets_after = list_assets(project);
    let html_sha_after = identity_sha(&assets_after, "/index.html")
        .expect("/index.html identity sha256 missing after update");
    let css_sha_after = identity_sha(&assets_after, "/style.css")
        .expect("/style.css identity sha256 missing after update");

    assert_ne!(
        html_sha_before, html_sha_after,
        "/index.html sha256 should change after content update",
    );
    assert_eq!(
        css_sha_before, css_sha_after,
        "/style.css sha256 should not change when file was not modified",
    );
}

/// Remove one file from the local directory and re-sync.
/// The deleted key must disappear from the canister; the remaining key must survive.
#[test]
fn asset_deletion() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets_before = list_assets(project);
    assert!(
        assets_before.iter().any(|a| a.key == "/index.html"),
        "/index.html should be present before deletion",
    );
    assert!(
        assets_before.iter().any(|a| a.key == "/style.css"),
        "/style.css should be present before deletion",
    );

    fs::remove_file(project.join("dist/style.css")).expect("failed to remove style.css");

    icp_cmd(project).arg("deploy").assert().success();

    let assets_after = list_assets(project);
    assert!(
        assets_after.iter().any(|a| a.key == "/index.html"),
        "/index.html should still be present after deleting style.css",
    );
    assert!(
        !assets_after.iter().any(|a| a.key == "/style.css"),
        "/style.css should be removed from the canister after local deletion",
    );
}

/// Configure two source directories with non-overlapping files and sync.
/// All files from both directories must appear in the canister with the
/// correct leading-slash keys.
#[test]
fn multi_directory_sync() {
    let tmp = setup_project("tests/fixture/multi-dir");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);

    assert!(
        assets.iter().any(|a| a.key == "/page.html"),
        "/page.html from dist-a should be present; got: {assets:#?}",
    );
    assert!(
        assets.iter().any(|a| a.key == "/app.js"),
        "/app.js from dist-b should be present; got: {assets:#?}",
    );
}
