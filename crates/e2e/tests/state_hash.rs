//! The reproducible-frontend claim, end to end.
//!
//! [`docs/verifying-contents.md`](../../../docs/verifying-contents.md) tells a
//! verifier to reproduce `dist/` from source, run the `state-hash` tool on it,
//! and compare against the canister's `state_hash()`. Every other test covers
//! one side or the other; this covers the equality itself.
//!
//! It is the only test where the two sides are built for *different targets*.
//! The plugin prepared and uploaded these assets compiled to `wasm32-wasip2` and
//! running under wasmtime; `asset-prep` here is compiled natively for the host.
//! Both hash the same `dist/` through the same code, so a divergence would mean
//! the compressors disagree across targets — which would silently break
//! verification for every deployed canister while leaving every other test green.

use e2e::{LocalNetwork, canister_state_hash, icp_cmd, setup_example};

/// Deploy, then verify exactly the way the docs tell a third party to.
#[test]
fn verifier_hash_matches_canister_after_deploy() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let dist = project.join("dist");
    let dist = dist.to_str().expect("dist path is utf-8");

    // `icp deploy` always uses the canonical (compressed) preparation.
    let verifier_hash = asset_prep::state_hash_for_dir(dist, asset_prep::Compression::Enabled)
        .expect("compute state hash from dist");

    assert_eq!(
        hex::encode(canister_state_hash(project)),
        hex::encode(verifier_hash),
        "the canister's state hash must equal the one a verifier computes from the same dist/"
    );
}

/// The same equality must survive an ordinary edit-and-redeploy — the path where
/// the plugin skips encoding for assets the canister already holds. If a skip
/// ever left a stale encoding behind, the canister's hash would drift from the
/// verifier's while every serving test still passed.
#[test]
fn verifier_hash_still_matches_after_a_partial_redeploy() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let index = project.join("dist").join("index.html");
    let edited = std::fs::read_to_string(&index).expect("read index.html") + "\n<!-- edited -->\n";
    std::fs::write(&index, edited).expect("write index.html");

    icp_cmd(project).arg("deploy").assert().success();

    let dist = project.join("dist");
    let dist = dist.to_str().expect("dist path is utf-8");
    let verifier_hash = asset_prep::state_hash_for_dir(dist, asset_prep::Compression::Enabled)
        .expect("compute state hash from dist");

    assert_eq!(
        hex::encode(canister_state_hash(project)),
        hex::encode(verifier_hash),
        "a re-deploy that re-encoded only the changed asset must still leave a canonical state"
    );
}
