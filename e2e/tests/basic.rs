use e2e::{icp_cmd, AssetDetails, LocalNetwork};
use std::path::PathBuf;

/// Absolute path to the committed `example/` project at the workspace root.
///
/// The `icp.yaml` inside that directory knows how to build the canister WASM
/// and plugin WASM with paths relative to the workspace `target/`, so the
/// test can run `icp deploy` directly from that directory without any fixture
/// copying.
fn example_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e/ must have a parent (the workspace root)")
        .join("example")
}

/// Deploy `example/` to a local replica and verify that `/index.html` appears
/// in the canister's asset list.
///
/// # Prerequisites
///
/// - `icp` binary on `$PATH` (install from the icp-cli GitHub releases).
/// - `ic-wasm` binary on `$PATH` (used by the `icp deploy` build step).
/// - `wasm32-unknown-unknown` and `wasm32-wasip2` Rust targets installed
///   (handled automatically via `rust-toolchain.toml`).
#[test]
fn example_deploys_successfully() {
    let project = example_dir();
    let _network = LocalNetwork::start(&project);

    icp_cmd(&project).arg("deploy").assert().success();

    let stdout = icp_cmd(&project)
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
