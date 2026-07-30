use std::{env, path::Path, path::PathBuf, process::Command};

fn main() {
    // Every workspace crate that ends up inside either wasm, watched whole (so a
    // crate's `Cargo.toml` counts too), because Cargo has no idea this build
    // script produces the wasm and will not re-run it otherwise. Miss one and the
    // suite silently keeps testing a stale `dist/*.wasm` — a change to the
    // omitted crate looks green because it was never in the artifact. Watching
    // more than needed costs only a no-op `make wasm`, so when in doubt add it.
    //
    //   canister.wasm: canister -> canister-core -> wire-types, state-hash
    //   plugin.wasm:   sync-plugin -> sync-core -> asset-prep -> wire-types, state-hash
    for crate_dir in [
        "canister",
        "canister-core",
        "sync-plugin",
        "sync-core",
        "asset-prep",
        "wire-types",
        "state-hash",
    ] {
        println!("cargo:rerun-if-changed=../{crate_dir}");
    }
    // The build recipe (profiles, targets) lives in the workspace Makefile and
    // root manifest; the lockfile pins the compressors whose exact output bytes
    // a sync stores.
    println!("cargo:rerun-if-changed=../../Makefile");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    println!("cargo:rerun-if-changed=../../Cargo.lock");

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
