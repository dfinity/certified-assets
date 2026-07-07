//! Rejecting a manifest that syncs more than one source directory.

use e2e::{LocalNetwork, icp_cmd, setup_project};

/// The assets sync plugin owns the URL space of its canister and only
/// supports a single source directory. A manifest that lists multiple
/// `dirs:` entries must fail the sync step before any canister mutation.
#[test]
fn multi_directory_sync_rejected() {
    let tmp = setup_project("multi-dir");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    let output = icp_cmd(project)
        .arg("deploy")
        .assert()
        .failure()
        .get_output()
        .clone();
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("expected exactly one input directory"),
        "expected multi-dir rejection message; got:\n{combined}",
    );
}
