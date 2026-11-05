//! The `stable_memory_bucket_mib` install argument, end to end.
//!
//! The unit tests in `canister-core` cover the bucket arithmetic over an
//! in-process memory. What only a real install shows is the wiring in `init`:
//! the argument has to reach the `MemoryManager` before anything else touches
//! stable memory, because the bucket size is fixed once the header is written.
//! If that ordering broke, the argument would be silently ignored and the
//! canister would keep the default buckets.

use e2e::{LocalNetwork, http_fetch, icp_cmd, setup_example};
use reqwest::StatusCode;
use std::path::Path;

const MIB: u64 = 1024 * 1024;

/// The canister's total memory (heap + stable), as `icp canister status` reports
/// it. The CLI doesn't break out stable memory, but the bucket sizes compared
/// here differ by far more than any heap noise.
fn memory_size(project: &Path) -> u64 {
    let stdout = icp_cmd(project)
        .args(["canister", "status", "frontend", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: serde_json::Value = serde_json::from_slice(&stdout).expect("status is JSON");
    status["memory_size"]
        .as_str()
        .expect("memory_size is a string")
        .replace('_', "")
        .parse()
        .expect("memory_size is a number")
}

fn reinstall(project: &Path, args: &str) -> assert_cmd::assert::Assert {
    icp_cmd(project)
        .args([
            "canister",
            "install",
            "frontend",
            "--mode",
            "reinstall",
            "--yes",
            "--args",
            args,
        ])
        .assert()
}

#[test]
fn install_argument_sets_the_stable_memory_bucket_size() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    // The default: 1 MiB buckets, so the deployed site (a few KiB) sits in
    // roughly 14 MiB of stable memory.
    icp_cmd(project).arg("deploy").assert().success();
    let default_size = memory_size(project);
    assert!(
        default_size < 32 * MIB,
        "a small site with default buckets uses {default_size} bytes"
    );

    // 4 MiB buckets: the same memories now take 4 MiB each, so the canister
    // grows by about 14 × 3 MiB = 42 MiB.
    reinstall(project, "(opt record { stable_memory_bucket_mib = opt 4 })").success();
    icp_cmd(project).arg("deploy").assert().success();
    assert_eq!(http_fetch(project, "/index.html").status(), StatusCode::OK);
    let larger = memory_size(project);
    assert!(
        larger >= default_size + 32 * MIB,
        "4 MiB buckets should cost tens of MiB more: {default_size} -> {larger} bytes"
    );

    // An out-of-range size is refused at install, not clamped.
    let refused = reinstall(project, "(opt record { stable_memory_bucket_mib = opt 0 })")
        .failure()
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("stable_memory_bucket_mib must be between 1 and 16"),
        "{stderr}"
    );
}
