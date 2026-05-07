use assert_cmd::Command as AssertCmd;
use candid::CandidType;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
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
