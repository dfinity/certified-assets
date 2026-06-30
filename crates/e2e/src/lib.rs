use assert_cmd::Command as AssertCmd;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

// Wire types shared with the canister and sync plugin.
pub use wire_types::{AssetDetails, AssetEncodingDetails, Encoding};

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

/// Generate a local `recipe.hbs` in `project` that pins the canister/plugin wasm
/// by the relative paths `setup_project` placed under `wasms/`. The recipe is the
/// real product produced by `recipe-gen`; writing the *local* variant here lets
/// the e2e tests exercise icp-cli's recipe resolution end to end against the
/// freshly built wasm. A fixture's `icp.yaml` references it via
/// `recipe: { type: "file://recipe.hbs", ... }`.
pub fn write_local_recipe(project: &Path) {
    let recipe = recipe_gen::render_recipe(&recipe_gen::WasmSource::Local {
        canister: "wasms/canister.wasm".to_string(),
        plugin: "wasms/plugin.wasm".to_string(),
    });
    fs::write(project.join("recipe.hbs"), recipe).expect("failed to write recipe.hbs");
}

/// Return the canister ID of `frontend` as printed by `icp canister status --id-only`.
pub fn frontend_canister_id(project: &Path) -> String {
    let stdout = icp_cmd(project)
        .args(["canister", "status", "frontend", "--id-only"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(stdout)
        .expect("--id-only output should be utf-8")
        .trim()
        .to_string()
}

/// Return the local network's HTTP gateway URL (e.g. `http://localhost:1234`),
/// as reported by `icp network status --json`.
pub fn gateway_url(project: &Path) -> String {
    let stdout = icp_cmd(project)
        .args(["network", "status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value =
        serde_json::from_slice(&stdout).expect("network status JSON should parse");
    json["gateway_url"]
        .as_str()
        .expect("gateway_url missing from network status JSON")
        .trim_end_matches('/')
        .to_string()
}

/// Fetch `<path>` (must start with `/`) from the `frontend` canister via the
/// local HTTP gateway. The reqwest client is configured to NOT follow
/// redirects so callers can assert on 3xx status codes and the `Location`
/// header. Going through the gateway implicitly validates the
/// `IC-Certificate` — if certification fails, the gateway short-circuits
/// before the response reaches the caller.
pub fn http_fetch(project: &Path, path: &str) -> reqwest::blocking::Response {
    http_fetch_with_headers(project, path, &[])
}

/// Like [`http_fetch`], but attaches arbitrary request headers — e.g. an
/// `If-None-Match` to exercise conditional-request / 304 handling end to end
/// through the gateway.
pub fn http_fetch_with_headers(
    project: &Path,
    path: &str,
    headers: &[(&str, &str)],
) -> reqwest::blocking::Response {
    let cid = frontend_canister_id(project);
    let base = gateway_url(project);
    let url = format!("{base}{path}?canisterId={cid}");
    let mut req = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client")
        .get(&url);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    req.send()
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"))
}

/// Like `http_fetch`, but routes the canister via the subdomain syntax that
/// browsers use (`http://<cid>.localhost:PORT/path`) instead of the
/// `?canisterId=…` query parameter. The query-string form and the subdomain
/// form sometimes exercise slightly different code paths in the gateway
/// (notably around path normalisation), so tests that mirror real browser
/// behaviour should prefer this helper.
pub fn http_fetch_subdomain(project: &Path, path: &str) -> reqwest::blocking::Response {
    let cid = frontend_canister_id(project);
    let base = gateway_url(project);
    // base looks like `http://127.0.0.1:PORT` or `http://localhost:PORT`. We
    // need to splice the canister id in front of the host.
    let url = base.replacen("://", &format!("://{cid}."), 1);
    let url = format!("{url}{path}");

    // macOS doesn't resolve `*.localhost` to loopback by default (Linux/glibc
    // does via RFC 6761). Pin DNS for the subdomain host to 127.0.0.1 so the
    // gateway still routes on the canister-subdomain Host header without
    // depending on the system resolver.
    let parsed = reqwest::Url::parse(&url).expect("parse subdomain URL");
    let host = parsed
        .host_str()
        .expect("subdomain URL has host")
        .to_string();
    let port = parsed
        .port_or_known_default()
        .expect("subdomain URL has port");
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();

    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, addr)
        .build()
        .expect("build reqwest client")
        .get(&url)
        .send()
        .unwrap_or_else(|e| panic!("GET {url} failed: {e}"))
}

/// POST `body` (as `application/x-www-form-urlencoded`) to `<path>` on the
/// `frontend` canister via the local gateway, attaching `headers`. Redirects are
/// not followed, so callers can assert on the `302` + `Set-Cookie` a login redeem
/// returns. Like the GET helpers, going through the gateway implicitly validates
/// the `IC-Certificate` — the redeem response must be certified to be delivered.
pub fn http_post_form(
    project: &Path,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> reqwest::blocking::Response {
    let cid = frontend_canister_id(project);
    let base = gateway_url(project);
    let url = format!("{base}{path}?canisterId={cid}");
    let mut req = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client")
        .post(&url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_string());
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    req.send()
        .unwrap_or_else(|e| panic!("POST {url} failed: {e}"))
}

/// Call `get_asset_details` on the `frontend` canister and return all asset details.
pub fn list_assets(project: &Path) -> Vec<AssetDetails> {
    let stdout = icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "get_asset_details",
            "(null)",
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
