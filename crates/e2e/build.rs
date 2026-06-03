use sha2::{Digest, Sha256};
use std::{env, path::Path, path::PathBuf, process::Command};

/// The legacy `assetstorage` canister shipped with dfx 0.32.0. The migration
/// plugin targets this canister, so the e2e suite deploys it (gzipped — icp-cli
/// installs `.wasm.gz` directly) rather than this repo's canister.
const LEGACY_WASM_URL: &str =
    "https://github.com/dfinity/sdk/releases/download/0.32.0/assetstorage.wasm.gz";
/// sha256 published on the GH release page for `assetstorage.wasm.gz`.
const LEGACY_WASM_SHA256: &str = "04e565b3425fe7510ee16b02adcfe3f01abc9a2725c82a21cb08969241debd62";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../sync-plugin/src");
    println!("cargo:rerun-if-changed=../sync-core/src");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // crates/e2e -> crates -> workspace root
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/e2e/ must have a workspace root two levels up");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let canister_wasm = fetch_legacy_canister(&out_dir);
    build_wasm(workspace_root, "sync-plugin", "wasm32-wasip2");

    println!("cargo:rustc-env=CANISTER_WASM={}", canister_wasm.display());
    println!(
        "cargo:rustc-env=PLUGIN_WASM={}",
        workspace_root
            .join("target/wasm32-wasip2/release/sync_plugin.wasm")
            .display()
    );
}

/// Downloads (and caches in `OUT_DIR`) the legacy `assetstorage.wasm.gz`,
/// verifying it against the pinned sha256. Returns the path to the `.gz`.
fn fetch_legacy_canister(out_dir: &Path) -> PathBuf {
    let dest = out_dir.join("assetstorage.wasm.gz");
    if dest.exists() && sha256_hex(&dest) == LEGACY_WASM_SHA256 {
        return dest;
    }
    let status = Command::new("curl")
        .args(["-sSL", "-o"])
        .arg(&dest)
        .arg(LEGACY_WASM_URL)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn curl for {LEGACY_WASM_URL}: {e}"));
    assert!(status.success(), "curl {LEGACY_WASM_URL} failed");

    let got = sha256_hex(&dest);
    assert_eq!(
        got, LEGACY_WASM_SHA256,
        "sha256 mismatch for assetstorage.wasm.gz (got {got}, expected {LEGACY_WASM_SHA256})"
    );
    dest
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let digest = Sha256::digest(&bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
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
