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

/// Recursively copy the contents of `src` into `dst`, skipping any `.icp/`
/// directory. `.icp/` holds a project's local replica + deploy state; a developer
/// who ran the project by hand leaves one behind, and copying it would drag a
/// stale replica (and its canister ids) into the test's throwaway project.
fn copy_project_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_name() == ".icp" {
            continue;
        }
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_project_contents(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

/// Copy a project directory into a fresh throwaway dir and return the guarding
/// [`tempfile::TempDir`]. Every e2e test runs against such a copy — never a
/// committed directory in place — so a developer's manual `icp deploy` and the
/// test suite never fight over one `.icp/`, and tests are free to mutate files
/// and run in parallel.
///
/// The copy is created **two directory levels below the repo root** (under the
/// workspace `target/`), which is the whole trick that lets one committed
/// `icp.yaml` serve both humans and tests: a project pins its wasms as
/// `../../dist/{canister,plugin}.wasm`, and from a two-deep location that
/// resolves to the repo's real `dist/` (populated by `make wasm`) — the exact
/// bytes, via the exact path, a human runs. No wasm injection, no path rewriting.
///
/// The returned `TempDir` deletes the copy on drop; keep it alive for the whole
/// test, and declare the [`LocalNetwork`] *after* it so the replica is stopped
/// before the directory is removed.
fn copy_project(src: &Path) -> tempfile::TempDir {
    // CARGO_MANIFEST_DIR = <repo>/crates/e2e, so the repo root is two levels up.
    // The copy must land exactly two levels below it for `../../dist` to resolve
    // to the repo's dist/ — hence a tempdir directly under the workspace target/.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/e2e must sit two levels below the repo root");
    let target = repo_root.join("target");
    fs::create_dir_all(&target).expect("failed to create workspace target/ dir");

    let tmp = tempfile::Builder::new()
        .prefix("e2e-")
        .tempdir_in(&target)
        .expect("failed to create tempdir under target/");
    copy_project_contents(src, tmp.path())
        .unwrap_or_else(|e| panic!("failed to copy project {}: {e}", src.display()));
    tmp
}

/// Set up an isolated copy of a test-only fixture from `tests/fixture/<name>`
/// (e.g. `setup_project("nested")`) — the sibling of [`setup_example`] for the
/// throwaway fixtures that aren't showcase-worthy. See [`copy_project`] for why
/// the copy resolves the fixture's `../../dist/*.wasm` pins to the repo's `dist/`.
pub fn setup_project(name: &str) -> tempfile::TempDir {
    copy_project(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixture")
            .join(name),
    )
}

/// Set up an isolated copy of a runnable example from the repo's `examples/`.
///
/// The example's committed `icp.yaml` is used **unchanged** — the same file, with
/// the same `../../dist/*.wasm` pins, that a human runs by hand (see the example's
/// README). Running from a throwaway copy rather than in place means the test
/// never disturbs a developer's own `examples/<name>/.icp/`. See [`copy_project`].
pub fn setup_example(name: &str) -> tempfile::TempDir {
    copy_project(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name),
    )
}

/// Generate a local `recipe.hbs` in `project` pinning the canister/plugin wasm by
/// the `../../dist/*.wasm` paths that resolve from the copied project (see
/// [`copy_project`]). The recipe is the real product produced by `recipe-gen`;
/// writing the *local* variant here lets the e2e tests exercise icp-cli's recipe
/// resolution end to end against the freshly built wasm. A fixture's `icp.yaml`
/// references it via `recipe: { type: "file://recipe.hbs", ... }`.
pub fn write_local_recipe(project: &Path) {
    let recipe = recipe_gen::render_recipe(&recipe_gen::WasmSource::Local {
        canister: "../../dist/canister.wasm".to_string(),
        plugin: "../../dist/plugin.wasm".to_string(),
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
