//! Persistence across a canister upgrade.
//!
//! The canister keeps its durable state (asset metadata + content) in stable
//! memory via `ic-stable-structures`, so there is no `pre_upgrade`
//! serialization step. `post_upgrade` only rebuilds the in-heap
//! certified-response tree. This test proves an in-place upgrade preserves the
//! assets and that they still serve with a valid certificate afterward.

use e2e::{http_fetch, icp_cmd, list_assets, setup_example, AssetDetails, LocalNetwork};
use reqwest::StatusCode;

fn sorted_assets(project: &std::path::Path) -> Vec<AssetDetails> {
    let mut assets = list_assets(project);
    assets.sort_by(|a, b| a.key.cmp(&b.key));
    for a in assets.iter_mut() {
        a.encodings.sort_by_key(|x| x.encoding);
    }
    assets
}

/// Deploy, then upgrade the canister in place with the same WASM, and confirm
/// the assets survive and still serve over the gateway (which validates the
/// `IC-Certificate` — an invalid cert is rejected before the response reaches
/// us, so a 200 here means `post_upgrade` rebuilt the certified tree correctly).
#[test]
fn assets_persist_across_canister_upgrade() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // Baseline: the asset list and a served, certificate-validated response.
    let assets_before = sorted_assets(project);
    let before = http_fetch(project, "/index.html");
    assert_eq!(before.status(), StatusCode::OK);
    let body_before = before.text().expect("read index.html before upgrade");
    assert!(
        body_before.contains("Hello, certified-assets!"),
        "unexpected index.html body before upgrade: {body_before}",
    );

    // Upgrade the canister in place. With `pre_upgrade` gone, this exercises
    // `post_upgrade` rebuilding the certified-response tree from the metadata
    // already present in stable memory.
    icp_cmd(project)
        .args(["canister", "install", "frontend", "--mode", "upgrade", "-y"])
        .assert()
        .success();

    // The asset list is byte-for-byte unchanged across the upgrade.
    let assets_after = sorted_assets(project);
    assert_eq!(
        assets_before, assets_after,
        "asset list should be identical after an in-place upgrade",
    );

    // And the asset still serves with a valid certificate and identical content.
    let after = http_fetch(project, "/index.html");
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "index.html should still serve 200 after upgrade",
    );
    let body_after = after.text().expect("read index.html after upgrade");
    assert_eq!(
        body_before, body_after,
        "served content should be unchanged after upgrade",
    );
}
