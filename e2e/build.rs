use std::{env, path::Path, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../canister/src");
    println!("cargo:rerun-if-changed=../ic-certified-assets/src");
    println!("cargo:rerun-if-changed=../plugin/src");
    println!("cargo:rerun-if-changed=../assets-sync/src");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().expect("e2e/ must have a parent");

    build_wasm(workspace_root, "canister", "wasm32-unknown-unknown");
    build_wasm(workspace_root, "plugin", "wasm32-wasip2");

    println!(
        "cargo:rustc-env=CANISTER_WASM={}",
        workspace_root
            .join("target/wasm32-unknown-unknown/release/canister.wasm")
            .display()
    );
    println!(
        "cargo:rustc-env=PLUGIN_WASM={}",
        workspace_root
            .join("target/wasm32-wasip2/release/plugin.wasm")
            .display()
    );
}

fn build_wasm(workspace_root: &Path, package: &str, target: &str) {
    let status = Command::new("cargo")
        .args(["build", "-p", package, "--target", target, "--release"])
        // Prevent the nested cargo from inheriting the jobserver file
        // descriptors that the outer Cargo passes via CARGO_MAKEFLAGS.
        .env_remove("CARGO_MAKEFLAGS")
        .current_dir(workspace_root)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn cargo build for {package}: {e}"));
    assert!(
        status.success(),
        "cargo build -p {package} --target {target} --release failed"
    );
}
