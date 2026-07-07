//! Deploying from a nested source directory.

use e2e::{LocalNetwork, icp_cmd, list_assets, setup_project};

/// Deploy a fixture whose `dirs` entry is a *nested* path (`src/frontend/dist`).
/// The host preopens it under a multi-segment WASI guest name; the plugin's scan
/// step must not call `canonicalize`/`realpath` on it (WASI returns ENOENT for
/// any path under a multi-component preopen, even though plain access works).
#[test]
fn nested_dir_deploy() {
    let tmp = setup_project("nested");
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
