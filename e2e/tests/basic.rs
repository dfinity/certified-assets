use candid::Principal;
use e2e::{icp_cmd, list_assets, setup_project, AssetDetails, LocalNetwork};

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
