use e2e::{generate_minimal_png, icp_cmd, list_assets, setup_project, LocalNetwork};
use std::fs;

/// Deploy to an empty canister with one HTML file and one runtime-generated PNG.
/// Verifies both keys are present and content types are correct.
#[test]
fn initial_sync() {
    let tmp = setup_project("tests/fixture/basic");
    let project = tmp.path();

    // Write a PNG generated at runtime so no binary file is committed to the repo.
    fs::write(project.join("dist/logo.png"), generate_minimal_png())
        .expect("failed to write logo.png");

    let _network = LocalNetwork::start(project);
    icp_cmd(project).arg("deploy").assert().success();

    let assets = list_assets(project);

    let html = assets
        .iter()
        .find(|a| a.key == "/index.html")
        .expect("/index.html missing from canister after initial sync");
    assert_eq!(html.content_type, "text/html");

    let png = assets
        .iter()
        .find(|a| a.key == "/logo.png")
        .expect("/logo.png missing from canister after initial sync");
    assert_eq!(png.content_type, "image/png");
}
