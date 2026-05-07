use assert_cmd::Command as AssertCmd;
use candid::CandidType;
use serde::Deserialize;
use std::{
    fs,
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

/// Generate a minimal 1×1 grayscale PNG at runtime without any external crate.
///
/// Uses a stored (non-compressed) deflate block inside zlib so no compression
/// library is needed.  The CRC32 and Adler-32 checksums are computed inline.
pub fn generate_minimal_png() -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            let mut v = (crc ^ b as u32) & 0xFF;
            for _ in 0..8 {
                v = if v & 1 != 0 { 0xEDB88320 ^ (v >> 1) } else { v >> 1 };
            }
            crc = (crc >> 8) ^ v;
        }
        !crc
    }

    fn adler32(data: &[u8]) -> u32 {
        let (mut s1, mut s2) = (1u32, 0u32);
        for &b in data {
            s1 = (s1 + b as u32) % 65521;
            s2 = (s2 + s1) % 65521;
        }
        (s2 << 16) | s1
    }

    fn chunk(tag: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let crc = crc32(&[tag.as_slice(), data].concat());
        let mut v = Vec::new();
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(tag);
        v.extend_from_slice(data);
        v.extend_from_slice(&crc.to_be_bytes());
        v
    }

    // 1×1 grayscale scanline: filter byte 0, pixel value 128
    let scanline: &[u8] = &[0x00, 0x80];

    // Wrap the scanline in a zlib stored (non-compressed) deflate block.
    let len = scanline.len() as u16;
    let mut zlib = Vec::new();
    zlib.extend_from_slice(&[0x78, 0x01]); // zlib header (deflate, default compression check)
    zlib.push(0x01); // BFINAL=1, BTYPE=00 (stored block)
    zlib.extend_from_slice(&len.to_le_bytes()); // LEN
    zlib.extend_from_slice(&(!len).to_le_bytes()); // NLEN (one's complement)
    zlib.extend_from_slice(scanline);
    zlib.extend_from_slice(&adler32(scanline).to_be_bytes()); // zlib checksum

    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // PNG signature

    // IHDR: 1×1, 8-bit grayscale (color_type=0)
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
    ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // bit_depth=8, color_type=0, compress=0, filter=0, interlace=0
    png.extend_from_slice(&chunk(b"IHDR", &ihdr));

    png.extend_from_slice(&chunk(b"IDAT", &zlib));
    png.extend_from_slice(&chunk(b"IEND", &[]));
    png
}
