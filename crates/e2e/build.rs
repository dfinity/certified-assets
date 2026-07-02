use std::{env, path::Path, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../canister/src");
    println!("cargo:rerun-if-changed=../canister-core/src");
    println!("cargo:rerun-if-changed=../sync-plugin/src");
    println!("cargo:rerun-if-changed=../sync-core/src");
    // The build recipe (profiles, targets) lives in the workspace Makefile.
    println!("cargo:rerun-if-changed=../../Makefile");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // crates/e2e -> crates -> workspace root
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/e2e/ must have a workspace root two levels up");

    // Delegate to the workspace Makefile so the tests exercise the exact same
    // wasm artifacts — same profiles and targets — that the release workflow
    // ships. It builds both modules and copies them to dist/, which every test
    // project's `icp.yaml` references by relative path (`../../dist/*.wasm`).
    let status = Command::new("make")
        .arg("wasm")
        // Prevent the nested cargo (spawned by make) from inheriting the
        // jobserver file descriptors the outer Cargo passes via CARGO_MAKEFLAGS.
        .env_remove("CARGO_MAKEFLAGS")
        .current_dir(workspace_root)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn `make wasm`: {e}"));
    assert!(status.success(), "`make wasm` failed");
}
