//! End-to-end tests for the `static-site` recipe.
//!
//! Each test renders the *local* recipe variant (via `recipe-gen`, pinning the
//! freshly built wasm by path), drops it next to a fixture `icp.yaml` that
//! references it with `type: "file://recipe.hbs"`, and deploys through the real
//! `icp` CLI — exercising recipe resolution + rendering + both wasm pins.
//!
//! Together with the recipe-gen unit tests (which assert every configuration
//! renders to valid icp-cli YAML), this covers each config field: `dir`
//! (`recipe_basic`), `build` (`recipe_build_step`), `presync`
//! (`recipe_presync_env`), and `metadata` (`recipe_metadata`).

use e2e::{
    LocalNetwork, frontend_canister_id, http_fetch, icp_cmd, list_assets, setup_recipe_project,
};

/// `dir` only: deploy through the recipe and confirm the asset is served.
#[test]
fn recipe_basic() {
    let tmp = setup_recipe_project("recipe-basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);
    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html via recipe deploy; got: {assets:#?}",
    );
}

/// `build`: a build command produces an extra asset, which must then sync.
#[test]
fn recipe_build_step() {
    let tmp = setup_recipe_project("recipe-build");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);
    assert!(
        assets.iter().any(|a| a.key == "/generated.txt"),
        "expected /generated.txt produced by the recipe's build step; got: {assets:#?}",
    );
}

/// `metadata`: ic-wasm injection runs as part of the build. ic-wasm is assumed
/// installed (on dev machines and in CI); when missing, the recipe's own
/// `command -v ic-wasm` guard makes the deploy fail loudly, surfacing a clear
/// error here rather than silently skipping. A successful deploy that still
/// serves assets proves the injected wasm installs and runs.
#[test]
fn recipe_metadata() {
    let tmp = setup_recipe_project("recipe-metadata");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);
    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html after metadata injection; got: {assets:#?}",
    );
}

/// `presync`: commands run at sync time — after the canister exists — with the
/// deployed canister IDs in the environment. This proves those vars are really
/// readable (not just that a step runs): pre-sync steps write `$ICP_CLI_CID`
/// and `$ICP_CLI_CID_FRONTEND` into the asset dir, and the served files must
/// each equal the frontend canister's own principal. That the files are served
/// at all also proves the pre-sync step runs *before* the plugin uploads.
#[test]
fn recipe_presync_env() {
    let tmp = setup_recipe_project("recipe-presync");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let cid = frontend_canister_id(project);

    for path in ["/cid.txt", "/cid-frontend.txt"] {
        let resp = http_fetch(project, path);
        assert!(
            resp.status().is_success(),
            "{path} should be served (written by a pre-sync step); got {}",
            resp.status(),
        );
        let body = resp.text().expect("asset body should be utf-8");
        assert_eq!(
            body, cid,
            "{path} must hold the canister id read from the pre-sync environment",
        );
    }
}
