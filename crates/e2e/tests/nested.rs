//! Deploying from a nested source directory.

use e2e::{LocalNetwork, http_fetch, icp_cmd, list_assets, setup_project};
use reqwest::StatusCode;

/// Deploy a fixture whose `dirs` entry is a *nested* path (`src/frontend/dist`).
/// The host preopens it under a multi-segment WASI guest name; the plugin's scan
/// step must not call `canonicalize`/`realpath` on it (WASI returns ENOENT for
/// any path under a multi-component preopen, even though plain access works).
///
/// Covers both ways the plugin reaches into that preopen: the recursive scan of
/// the tree, and the `_redirects` read at its root. The latter is the quiet one —
/// an absent config file means "no rules", so a path that failed to resolve would
/// drop every redirect rule without an error, hence the fetch below.
#[test]
fn nested_dir_deploy() {
    let tmp = setup_project("nested");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let r = http_fetch(project, "/old");
    assert_eq!(
        r.status(),
        StatusCode::MOVED_PERMANENTLY,
        "the fixture's `_redirects`, which sits at the root of the nested preopen, was not loaded"
    );
    assert_eq!(
        r.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        Some("/index.html".into()),
    );

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
