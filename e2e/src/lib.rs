use assert_cmd::Command as AssertCmd;
use candid::CandidType;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}

/// Build an `icp` subprocess command rooted at `project_dir`.
///
/// `current_dir` is set so that build tools spawned by `icp` (e.g. `cargo`)
/// inherit the right working directory.  `--project-root-override` is passed
/// explicitly so `icp` locates `icp.yaml` without relying on `$PWD` or
/// `getcwd(2)`.
pub fn icp_cmd(project_dir: &Path) -> AssertCmd {
    let mut cmd = AssertCmd::new("icp");
    cmd.current_dir(project_dir)
        .arg(format!("--project-root-override={}", project_dir.display()));
    cmd
}

/// RAII guard for a local ICP replica.
///
/// Starts the replica with `icp network start -d` on construction and stops it
/// with `icp network stop` on drop — even when the test panics.
pub struct LocalNetwork {
    dir: PathBuf,
}

impl LocalNetwork {
    /// Start the local replica from `project_dir` and return a guard that stops
    /// it when dropped.  `project_dir` must contain a valid `icp.yaml`; the
    /// replica state is kept in `project_dir/.icp/`.
    pub fn start(project_dir: impl Into<PathBuf>) -> Self {
        let dir = project_dir.into();
        icp_cmd(&dir)
            .args(["network", "start", "-d"])
            .assert()
            .success();
        LocalNetwork { dir }
    }
}

impl Drop for LocalNetwork {
    fn drop(&mut self) {
        // Ignore errors: the replica may have already exited or been cleaned up.
        let _ = Command::new("icp")
            .current_dir(&self.dir)
            .arg(format!("--project-root-override={}", self.dir.display()))
            .args(["network", "stop"])
            .output();
    }
}

pub fn copy_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
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
/// `fixture_path` is relative to the e2e crate root (e.g. `"tests/fixture/basic"`).
/// The returned `TempDir` must be kept alive for the duration of the test.
pub fn setup_project(fixture_path: &str) -> tempfile::TempDir {
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

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AssetProperties {
    pub max_age: Option<u64>,
    pub headers: Option<BTreeMap<String, String>>,
    pub allow_raw_access: Option<bool>,
    pub is_aliased: Option<bool>,
}

/// Call `get_asset_properties` on the `frontend` canister for `key`.
pub fn get_asset_properties(project: &Path, key: &str) -> AssetProperties {
    let stdout = icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "get_asset_properties",
            &format!("(\"{key}\")"),
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
    let (properties,) = candid::decode_args::<(AssetProperties,)>(&bytes)
        .expect("failed to decode candid response");
    properties
}

/// Call `list` on the `frontend` canister and return all asset details.
pub fn list_assets(project: &Path) -> Vec<AssetDetails> {
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
    assets
}
