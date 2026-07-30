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
///
/// The fixture mixes an entry carrying `visibility: public` with one that omits
/// it, and the assertions check both halves: that each section reached the
/// installed canister with its value, and that `visibility` decided the section's
/// *name* — ic-wasm writes `icp:public <name>` or `icp:private <name>`, and only
/// the prefix distinguishes a dropped `-v public` from a working one.
///
/// The prefix is read off the built artifact, not the replica, because the
/// replica cannot tell us: it serves a public section to anyone and a private one
/// to controllers, so separating them needs a *non-controller* read — and there
/// is no identity a test can rely on for that. A fresh icp-cli install has only
/// the built-in `anonymous` identity and deploys as it, which makes anonymous the
/// canister's controller and every section readable (that is exactly how CI
/// runs); a developer machine with a real default identity behaves the opposite
/// way. So the visibility half asks ic-wasm instead, which needs no identity at
/// all.
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

    // Both sections reached the *installed* canister, values intact. The deployer
    // is the canister's controller either way, so this read needs no identity
    // choice — and it means the visibility check below can't pass vacuously on a
    // wasm whose sections never made it onto the replica.
    for (section, value) in [("build:commit", "a1b2c3d"), ("app:framework", "react")] {
        let out = icp_cmd(project)
            .args(["canister", "metadata", "frontend", section])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let out = String::from_utf8_lossy(&out);
        assert!(
            out.contains(value),
            "read of `{section}` should yield {value:?}; got: {out}",
        );
    }

    // And `visibility` landed each one in the right section namespace.
    let sections = wasm_metadata_sections(project);
    assert!(
        sections.contains(&"icp:public build:commit".to_string()),
        "`build:commit` declares `visibility: public`, so ic-wasm must have written \
         `icp:public build:commit`; a `-v public` lost from the recipe template would \
         leave it icp:private. Sections: {sections:#?}",
    );
    assert!(
        sections.contains(&"icp:private app:framework".to_string()),
        "`app:framework` omits `visibility`, so it must stay in ic-wasm's default \
         private namespace. Sections: {sections:#?}",
    );
}

/// The metadata section names — each `icp:public <name>` or `icp:private <name>` —
/// of the wasm `icp build` produced for the `frontend` canister.
///
/// Reaches into icp-cli's build cache: `icp build` has no `--output`, and the
/// visibility prefix exists nowhere else observable (see the note on the caller).
/// That path is an icp-cli implementation detail, so this fails with an explicit
/// message if it moves — a version bump that relocates the artifact means
/// updating this helper, not that the recipe broke.
fn wasm_metadata_sections(project: &std::path::Path) -> Vec<String> {
    let artifact = project.join(".icp/cache/artifacts/frontend");
    assert!(
        artifact.is_file(),
        "no built wasm at {} — icp-cli's build-cache layout changed; find the new path \
         (`icp build` still has no --output flag) and update this helper",
        artifact.display(),
    );
    let out = std::process::Command::new("ic-wasm")
        .arg(&artifact)
        .arg("metadata")
        .output()
        .expect("run `ic-wasm <wasm> metadata` (ic-wasm is required by this test)");
    assert!(
        out.status.success(),
        "ic-wasm failed to list metadata: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
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
