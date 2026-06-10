use std::{env, path::Path, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../canister/src");
    println!("cargo:rerun-if-changed=../ic-certified-assets/src");
    println!("cargo:rerun-if-changed=../plugin/src");
    println!("cargo:rerun-if-changed=../assets-sync/src");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().expect("e2e/ must have a parent");

    let canister_wasm = build_wasm(workspace_root, "canister", "wasm32-unknown-unknown");
    let plugin_wasm = build_wasm(workspace_root, "plugin", "wasm32-wasip2");

    println!("cargo:rustc-env=CANISTER_WASM={}", canister_wasm.display());
    println!("cargo:rustc-env=PLUGIN_WASM={}", plugin_wasm.display());
}

/// Build `package` for `target` and return the path to the wasm it produced.
///
/// The path is read from Cargo's `--message-format=json` artifact output rather
/// than assembled by hand, so it is correct wherever the target directory is
/// configured (`CARGO_TARGET_DIR`, `build.target-dir` in `.cargo/config.toml`,
/// etc.) instead of assuming `<workspace>/target`.
fn build_wasm(workspace_root: &Path, package: &str, target: &str) -> PathBuf {
    let output = Command::new("cargo")
        .args([
            "build",
            "-p",
            package,
            "--target",
            target,
            "--release",
            "--message-format=json",
        ])
        // Prevent the nested cargo from inheriting the jobserver file
        // descriptors that the outer Cargo passes via CARGO_MAKEFLAGS.
        .env_remove("CARGO_MAKEFLAGS")
        .current_dir(workspace_root)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn cargo build for {package}: {e}"));

    assert!(
        output.status.success(),
        "cargo build -p {package} --target {target} --release failed:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    wasm_artifact(&output.stdout, package)
        .unwrap_or_else(|| panic!("no wasm artifact for `{package}` in `cargo build` JSON output"))
}

/// Extracts the wasm path for `package` from a stream of `cargo --message-format=json`
/// lines: the `compiler-artifact` message for the package's own target carries
/// the built file in `executable` (or, for a library crate-type, `filenames`).
fn wasm_artifact(stdout: &[u8], package: &str) -> Option<PathBuf> {
    for line in stdout.split(|&b| b == b'\n') {
        let msg: serde_json::Value = match serde_json::from_slice(line) {
            Ok(msg) => msg,
            Err(_) => continue, // non-JSON / blank lines
        };
        if msg["reason"] != "compiler-artifact" || msg["target"]["name"] != package {
            continue;
        }
        if let Some(exe) = msg["executable"].as_str() {
            return Some(PathBuf::from(exe));
        }
        if let Some(wasm) = msg["filenames"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f.as_str())
            .find(|f| f.ends_with(".wasm"))
        {
            return Some(PathBuf::from(wasm));
        }
    }
    None
}
