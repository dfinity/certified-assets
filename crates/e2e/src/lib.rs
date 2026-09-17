use assert_cmd::Command as AssertCmd;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

// Wire types shared with the canister and sync plugin.
pub use wire_types::{AssetDetails, AssetEncodingDetails, Encoding, ProposedState};

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

/// Set up an isolated copy of a recipe fixture (`tests/fixture/<name>`) and drop
/// the local `recipe.hbs` it references next to its `icp.yaml`. The recipe must
/// exist before the replica starts and before `icp deploy` resolves the manifest.
/// Lets the e2e tests exercise icp-cli's recipe resolution end to end.
pub fn setup_recipe_project(name: &str) -> tempfile::TempDir {
    let tmp = setup_project(name);
    write_local_recipe(tmp.path());
    tmp
}

/// Generate a local `recipe.hbs` in `project` pinning the canister/plugin wasm by
/// the `../../dist/*.wasm` paths that resolve from the copied project (see
/// [`copy_project`]). The recipe is the real product produced by `recipe-gen`;
/// writing the *local* variant lets the e2e tests exercise icp-cli's recipe
/// resolution against the freshly built wasm. A recipe fixture's `icp.yaml`
/// references it via `recipe: { type: "file://recipe.hbs", ... }`.
fn write_local_recipe(project: &Path) {
    let recipe = recipe_gen::render_recipe(&recipe_gen::WasmSource::Local {
        canister: "../../dist/canister.wasm".to_string(),
        plugin: "../../dist/plugin.wasm".to_string(),
    });
    fs::write(project.join("recipe.hbs"), recipe).expect("failed to write recipe.hbs");
}

/// Return the canister ID of `name` as printed by `icp canister status --id-only`.
pub fn canister_id(project: &Path, name: &str) -> String {
    let stdout = icp_cmd(project)
        .args(["canister", "status", name, "--id-only"])
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

/// Return the canister ID of `frontend` — the canister name every e2e project uses.
pub fn frontend_canister_id(project: &Path) -> String {
    canister_id(project, "frontend")
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
    http_fetch_subdomain_with_headers(project, path, &[])
}

/// Like [`http_fetch_subdomain`], but attaches arbitrary request headers — e.g.
/// an `If-None-Match` to exercise a 304 through the browser-style URL, which is
/// the form that forces the gateway's full v2 verification.
pub fn http_fetch_subdomain_with_headers(
    project: &Path,
    path: &str,
    headers: &[(&str, &str)],
) -> reqwest::blocking::Response {
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

    let mut req = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, addr)
        .build()
        .expect("build reqwest client")
        .get(&url);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    req.send()
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

/// Call `state_hash` on the `frontend` canister and return the 32-byte digest it
/// reports over its stored state.
pub fn canister_state_hash(project: &Path) -> [u8; 32] {
    let stdout = icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "state_hash",
            "()",
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
    let (hash,) = candid::decode_args::<(serde_bytes::ByteBuf,)>(&bytes)
        .expect("failed to decode candid response");
    <[u8; 32]>::try_from(hash.as_ref()).expect("state_hash must be 32 bytes")
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

/// Reference forms in the docs are written with placeholders; fill in concrete
/// values so a snippet can be sent as-is. A placeholder left unfilled fails the
/// caller rather than skipping the snippet — a new spelling belongs here, not in
/// a hole in the coverage.
const PLACEHOLDERS: [(&str, &str); 5] = [
    ("<label>", "doc-label"),
    ("<value>", "doc-secret"),
    ("<secs>", "3600"),
    ("= N :", "= 3600 :"),
    ("...", "doc"),
];

/// Extracts every documented `(method, candid-args)` pair for `methods` from
/// `markdown`, in document order — the same shape whether it sits in a fenced
/// `icp canister call frontend …` line or in a reference-table cell, so both stay
/// checked.
///
/// Shared by the doc-coverage tests (`protection.rs`, `governance.rs`): the point
/// of those tests is that the *committed* docs stay runnable, so there is exactly
/// one notion of "a call a document shows".
pub fn documented_calls(markdown: &str, methods: &[&str]) -> Vec<(String, String)> {
    // A shell line continued with `\` puts the method and its argument on
    // different source lines (the quick start does); glue those back together.
    let text = markdown
        .split("\\\n")
        .fold(String::new(), |mut acc, piece| {
            if acc.is_empty() {
                acc.push_str(piece);
            } else {
                acc.push_str(piece.trim_start());
            }
            acc
        });

    let mut calls: Vec<(usize, String, String)> = Vec::new();
    for method in methods {
        let mut from = 0;
        while let Some(offset) = text[from..].find(method) {
            let start = from + offset;
            from = start + method.len();
            // Reject a name embedded in a longer identifier, and require the
            // argument to follow immediately — prose like "the `issue_token`
            // call" documents nothing runnable.
            let preceded_by_ident = text[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let rest = &text[from..];
            if preceded_by_ident || !rest.starts_with(" '") {
                continue;
            }
            let Some(end) = rest[2..].find('\'') else {
                continue;
            };
            let mut args = rest[2..2 + end].to_string();
            for (placeholder, value) in PLACEHOLDERS {
                args = args.replace(placeholder, value);
            }
            assert!(
                !args.contains('<') && !args.contains("..."),
                "unfilled placeholder in `{method} '{args}'` — add it to PLACEHOLDERS",
            );
            calls.push((start, method.to_string(), args));
        }
    }
    calls.sort_by_key(|(offset, _, _)| *offset);
    calls
        .into_iter()
        .map(|(_, method, args)| (method, args))
        .collect()
}

/// The principal `icp canister call` signs with in this project — what a test
/// names when it needs the calling identity to *be* some configured principal.
pub fn identity_principal(project: &Path) -> String {
    let stdout = icp_cmd(project)
        .args(["identity", "principal"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8_lossy(&stdout).trim().to_string()
}

/// Read the committed `docs/<name>` (not the project copy's), so a doc-coverage
/// test guards the file a reader actually lands on.
pub fn committed_doc(relative: &str) -> String {
    // crates/e2e -> crates -> repo root.
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/e2e/ must have a repo root two levels up");
    std::fs::read_to_string(repo.join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// Call `proposed_state` on the `frontend` canister and decode the reply.
///
/// Decoded from `-o hex` rather than read out of the CLI's textual rendering:
/// the test wasm carries no `candid:service` metadata (only the release build
/// does), so `icp canister call` prints field *hashes*, not names.
pub fn proposed_state(project: &Path) -> ProposedState {
    let stdout = icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "proposed_state",
            "()",
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
    let (state,) =
        candid::decode_args::<(ProposedState,)>(&bytes).expect("failed to decode candid response");
    state
}
