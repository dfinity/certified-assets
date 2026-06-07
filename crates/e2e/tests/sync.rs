use candid::Principal;
use e2e::{icp_cmd, list_assets, setup_project, AssetDetails, LocalNetwork};
use std::fs;

/// Deploy the test fixture to a local replica and verify that `/index.html` appears
/// in the canister's asset list.
#[test]
fn basic_deploy() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);

    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html in canister asset list; got: {assets:#?}",
    );
}

/// Deploy a fixture whose `dirs` entry is a *nested* path (`src/frontend/dist`).
/// The host preopens it under a multi-segment WASI guest name; the plugin's scan
/// step must not call `canonicalize`/`realpath` on it (WASI returns ENOENT for
/// any path under a multi-component preopen, even though plain access works).
#[test]
fn nested_dir_deploy() {
    let tmp = setup_project("tests/fixture/nested");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);

    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html in canister asset list; got: {assets:#?}",
    );
    assert!(
        assets.iter().any(|a| a.key == "/assets/style.css"),
        "expected /assets/style.css (nested subdir) in canister asset list; got: {assets:#?}",
    );
}

#[test]
fn basic_deploy_with_proxy() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);
    let network_status = icp_cmd(project)
        .args(["network", "status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status_json: serde_json::Value =
        serde_json::from_slice(&network_status).expect("failed to parse network status JSON");
    let proxy_id: Principal = status_json["proxy_canister_principal"]
        .as_str()
        .and_then(|s| Principal::from_text(s).ok())
        .expect("proxy_canister_principal missing or invalid in network status");

    icp_cmd(project)
        .args(["deploy", "--proxy", proxy_id.to_text().as_str()])
        .assert()
        .success();

    let assets = list_assets(project);

    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html in canister asset list; got: {assets:#?}",
    );
}

/// Run sync twice without modifying any files.
/// The second deploy must report "up to date" and must not change canister state.
#[test]
fn no_op_sync() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let mut assets_before = list_assets(project);
    assets_before.sort_by(|a, b| a.key.cmp(&b.key));
    for a in assets_before.iter_mut() {
        a.encodings
            .sort_by(|x, y| x.content_encoding.cmp(&y.content_encoding));
    }

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

    let mut assets_after = list_assets(project);
    assets_after.sort_by(|a, b| a.key.cmp(&b.key));
    for a in assets_after.iter_mut() {
        a.encodings
            .sort_by(|x, y| x.content_encoding.cmp(&y.content_encoding));
    }
    assert_eq!(
        assets_before, assets_after,
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

/// The assets sync plugin owns the URL space of its canister and only
/// supports a single source directory. A manifest that lists multiple
/// `dirs:` entries must fail the sync step before any canister mutation.
#[test]
fn multi_directory_sync_rejected() {
    let tmp = setup_project("tests/fixture/multi-dir");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    let output = icp_cmd(project)
        .arg("deploy")
        .assert()
        .failure()
        .get_output()
        .clone();
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("expected exactly one input directory"),
        "expected multi-dir rejection message; got:\n{combined}",
    );
}
