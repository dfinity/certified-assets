use candid::Principal;
use e2e::{icp_cmd, AssetDetails, LocalNetwork};
use std::{fs, path::Path};
use tempfile::TempDir;

fn copy_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir_contents(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

/// Set up an isolated copy of a fixture in a temporary directory, with
/// pre-built WASM modules placed at `wasms/canister.wasm` and
/// `wasms/plugin.wasm` (paths supplied by the build script).
///
/// `fixture_path` is relative to the e2e crate root (e.g. `"tests/fixture"`).
/// The returned `TempDir` must be kept alive for the duration of the test.
fn setup_project(fixture_path: &str) -> TempDir {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = tempfile::TempDir::new().expect("failed to create tempdir");

    copy_dir_contents(&crate_root.join(fixture_path), tmp.path())
        .expect("failed to copy fixture into tempdir");

    let wasms_dir = tmp.path().join("wasms");
    fs::create_dir_all(&wasms_dir).expect("failed to create wasms/ dir");

    fs::copy(env!("CANISTER_WASM"), wasms_dir.join("canister.wasm"))
        .expect("failed to copy canister.wasm");
    fs::copy(env!("PLUGIN_WASM"), wasms_dir.join("plugin.wasm"))
        .expect("failed to copy plugin.wasm");

    tmp
}

/// Deploy the test fixture to a local replica and verify that `/index.html` appears
/// in the canister's asset list.
#[test]
fn basic_deploy() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let stdout = icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "list",
            "(record {})",
            "-o",
            "hex",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let hex_str = String::from_utf8_lossy(&stdout);
    let bytes = hex::decode(hex_str.trim()).expect("failed to decode hex response");
    let (assets,) = candid::decode_args::<(Vec<AssetDetails>,)>(&bytes)
        .expect("failed to decode candid response");

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

    let stdout = icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "list",
            "(record {})",
            "-o",
            "hex",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let hex_str = String::from_utf8_lossy(&stdout);
    let bytes = hex::decode(hex_str.trim()).expect("failed to decode hex response");
    let (assets,) = candid::decode_args::<(Vec<AssetDetails>,)>(&bytes)
        .expect("failed to decode candid response");

    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html in canister asset list; got: {assets:#?}",
    );
}
