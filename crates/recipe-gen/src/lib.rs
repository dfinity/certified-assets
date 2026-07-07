//! Generator for the `certified-assets` icp-cli recipe.
//!
//! A recipe is a Handlebars template (`recipe.hbs`) hosted in the
//! `dfinity/icp-cli-recipes` registry. icp-cli downloads it, renders it against
//! the user's `configuration`, and the rendered YAML pins the canister wasm (a
//! `build` `pre-built` step) and the sync-plugin wasm (a `sync` `plugin` step).
//!
//! The recipe ships in two shapes that differ only in how those two wasm
//! modules are pinned:
//!
//! - **local** — by file `path:`, for in-repo e2e testing (`make recipe-local`).
//! - **release** — by versioned GitHub release `url:` + `sha256:`, for
//!   publishing (`make recipe-release`, `scripts/publish-recipe.sh`).
//!
//! Both are produced from one source ([`TEMPLATE`]). Because the output *is
//! itself* a Handlebars template — its `{{ ... }}` directives are meant for the
//! end user and must survive verbatim — we never run it through Handlebars here.
//! We only substitute two non-Handlebars sentinels with plain string
//! replacement.

use std::path::Path;

/// The base recipe template (`recipe.hbs.in`). Everything except the two wasm
/// sources is shared between the local and release variants.
const TEMPLATE: &str = include_str!("recipe.hbs.in");

/// Placeholders the generator replaces with the canister/plugin wasm source.
/// They sit on their own line under their `- type:` entry; the replacement
/// carries the 6-space indentation that aligns with the sibling `type:` key.
const CANISTER_SENTINEL: &str = "@@CANISTER_SOURCE@@";
const PLUGIN_SENTINEL: &str = "@@PLUGIN_SOURCE@@";

/// Base URL for this repo's GitHub release assets.
const RELEASE_BASE: &str = "https://github.com/dfinity/certified-assets/releases/download";
/// Release asset names produced by `make release` (see the workspace Makefile).
const CANISTER_ASSET: &str = "canister-release.wasm.gz";
const PLUGIN_ASSET: &str = "plugin-release.wasm";

/// How the recipe pins the canister and sync-plugin wasm modules.
pub enum WasmSource {
    /// Pin both modules by local file path (no checksum). Used by the e2e tests
    /// and `make recipe-local`.
    Local {
        /// Path to the canister wasm, as written into the recipe (e.g.
        /// `wasms/canister.wasm`, resolved relative to the project root).
        canister: String,
        /// Path to the sync-plugin wasm, as written into the recipe.
        plugin: String,
    },
    /// Pin both modules by versioned GitHub release URL + sha256. Used by
    /// `make recipe-release` and the publish script.
    Release {
        /// Release tag, e.g. `v1.0.0`.
        version: String,
        /// Hex sha256 of `canister-release.wasm.gz`.
        canister_sha: String,
        /// Hex sha256 of `plugin-release.wasm`.
        plugin_sha: String,
    },
}

impl WasmSource {
    /// The YAML lines that pin the canister wasm, indented to sit under
    /// `- type: pre-built`.
    fn canister_block(&self) -> String {
        match self {
            WasmSource::Local { canister, .. } => format!("      path: {canister}"),
            WasmSource::Release {
                version,
                canister_sha,
                ..
            } => format!(
                "      url: {RELEASE_BASE}/{version}/{CANISTER_ASSET}\n      sha256: {canister_sha}"
            ),
        }
    }

    /// The YAML lines that pin the sync-plugin wasm, indented to sit under
    /// `- type: plugin` (and above the templated `dirs:`).
    fn plugin_block(&self) -> String {
        match self {
            WasmSource::Local { plugin, .. } => format!("      path: {plugin}"),
            WasmSource::Release {
                version,
                plugin_sha,
                ..
            } => format!(
                "      url: {RELEASE_BASE}/{version}/{PLUGIN_ASSET}\n      sha256: {plugin_sha}"
            ),
        }
    }
}

/// Render the recipe template with the wasm sources filled in. The result is a
/// complete `recipe.hbs` whose user-facing `{{ ... }}` directives are untouched.
pub fn render_recipe(src: &WasmSource) -> String {
    TEMPLATE
        .replace(CANISTER_SENTINEL, &src.canister_block())
        .replace(PLUGIN_SENTINEL, &src.plugin_block())
}

/// Read a `shasum -a 256` style checksum file (`<hex>  <filename>`) and return
/// the bare hex digest. Used by the release path to pin the exact published
/// artifacts.
pub fn read_sha256_file(path: &Path) -> std::io::Result<String> {
    let contents = std::fs::read_to_string(path)?;
    let hash = contents
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let is_hex64 = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_hex64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: expected a 64-char hex sha256 as the first field, found {hash:?}",
                path.display()
            ),
        ));
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_yaml::Value;

    // A subset of icp-cli's rendered manifest shape, enough to assert the recipe
    // produces the build/sync structure the CLI expects (mirrors the
    // BuildSyncHelper in icp-cli's recipe/handlebars.rs).
    #[derive(Deserialize)]
    struct Rendered {
        build: Steps,
        #[serde(default)]
        sync: Option<Steps>,
    }
    #[derive(Deserialize)]
    struct Steps {
        steps: Vec<Value>,
    }

    fn step_type(step: &Value) -> &str {
        step.get("type").and_then(Value::as_str).unwrap_or("")
    }

    /// Render `recipe.hbs` (built from `src`) through Handlebars with `config`,
    /// the same way icp-cli does: strict mode on, HTML escaping off.
    fn render_with_config(src: &WasmSource, config: Value) -> Result<String, String> {
        let recipe = render_recipe(src);
        let mut reg = handlebars::Handlebars::new();
        reg.register_escape_fn(handlebars::no_escape);
        reg.set_strict_mode(true);
        reg.render_template(&recipe, &config)
            .map_err(|e| e.to_string())
    }

    fn parse(yaml: &str) -> Rendered {
        let rendered: Rendered = serde_yaml::from_str(yaml)
            .unwrap_or_else(|e| panic!("rendered recipe is not valid: {e}\n---\n{yaml}\n---"));
        // icp-cli deserializes script `commands` as `Vec<String>`; a value with a
        // stray `: ` would parse as a map here and be rejected there. Assert each
        // command is a YAML string so we catch that before it reaches the CLI.
        let all_steps = rendered
            .build
            .steps
            .iter()
            .chain(rendered.sync.iter().flat_map(|s| s.steps.iter()));
        for step in all_steps {
            if let Some(cmds) = step.get("commands") {
                let seq = cmds
                    .as_sequence()
                    .expect("a script step's `commands` must be a sequence");
                for c in seq {
                    assert!(
                        c.as_str().is_some(),
                        "every command must be a YAML string, got: {c:?}\n---\n{yaml}\n---",
                    );
                }
            }
        }
        rendered
    }

    fn local() -> WasmSource {
        WasmSource::Local {
            canister: "wasms/canister.wasm".into(),
            plugin: "wasms/plugin.wasm".into(),
        }
    }

    #[test]
    fn local_only_dir() {
        let out = render_with_config(&local(), serde_yaml::from_str("dir: dist").unwrap()).unwrap();
        let r = parse(&out);
        // Exactly one build step (the pre-built canister), no build/metadata scripts.
        assert_eq!(r.build.steps.len(), 1);
        assert_eq!(step_type(&r.build.steps[0]), "pre-built");
        assert_eq!(
            r.build.steps[0].get("path").and_then(Value::as_str),
            Some("wasms/canister.wasm")
        );
        // Single plugin sync step pinned to the local path, with exactly one dir.
        let sync = r.sync.expect("sync section present");
        assert_eq!(sync.steps.len(), 1);
        assert_eq!(step_type(&sync.steps[0]), "plugin");
        assert_eq!(
            sync.steps[0].get("path").and_then(Value::as_str),
            Some("wasms/plugin.wasm")
        );
        let dirs = sync.steps[0]
            .get("dirs")
            .and_then(Value::as_sequence)
            .unwrap();
        assert_eq!(dirs.len(), 1, "exactly one dir is rendered");
        assert_eq!(dirs[0].as_str(), Some("dist"));
    }

    #[test]
    fn local_with_build() {
        let cfg = serde_yaml::from_str("dir: dist\nbuild:\n  - npm ci\n  - npm run build").unwrap();
        let out = render_with_config(&local(), cfg).unwrap();
        let r = parse(&out);
        // build script step is prepended before the pre-built canister step.
        assert_eq!(r.build.steps.len(), 2);
        assert_eq!(step_type(&r.build.steps[0]), "script");
        assert_eq!(step_type(&r.build.steps[1]), "pre-built");
        let cmds = r.build.steps[0]
            .get("commands")
            .and_then(Value::as_sequence)
            .unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].as_str(), Some("npm ci"));
    }

    #[test]
    fn local_with_metadata() {
        let cfg =
            serde_yaml::from_str("dir: dist\nmetadata:\n  - name: app:framework\n    value: react")
                .unwrap();
        let out = render_with_config(&local(), cfg).unwrap();
        let r = parse(&out);
        // ic-wasm availability check, pre-built canister, then the injection script.
        let types: Vec<&str> = r.build.steps.iter().map(step_type).collect();
        assert_eq!(types, vec!["script", "pre-built", "script"]);
        // The injection command carries the name/value pair.
        let inject = r.build.steps[2]
            .get("commands")
            .and_then(Value::as_sequence)
            .unwrap()[0]
            .as_str()
            .unwrap();
        assert!(inject.contains("app:framework"), "got: {inject}");
        assert!(inject.contains("react"), "got: {inject}");
    }

    #[test]
    fn release_pins_urls_and_shas() {
        let src = WasmSource::Release {
            version: "v1.2.3".into(),
            canister_sha: "a".repeat(64),
            plugin_sha: "b".repeat(64),
        };
        let out = render_with_config(&src, serde_yaml::from_str("dir: dist").unwrap()).unwrap();
        let r = parse(&out);
        assert_eq!(
            r.build.steps[0].get("url").and_then(Value::as_str),
            Some(
                "https://github.com/dfinity/certified-assets/releases/download/v1.2.3/canister-release.wasm.gz"
            )
        );
        assert_eq!(
            r.build.steps[0].get("sha256").and_then(Value::as_str),
            Some(&*"a".repeat(64))
        );
        let sync = r.sync.unwrap();
        assert_eq!(
            sync.steps[0].get("url").and_then(Value::as_str),
            Some(
                "https://github.com/dfinity/certified-assets/releases/download/v1.2.3/plugin-release.wasm"
            )
        );
        assert_eq!(
            sync.steps[0].get("sha256").and_then(Value::as_str),
            Some(&*"b".repeat(64))
        );
    }

    #[test]
    fn missing_required_dir_fails() {
        // `dir` is required; strict-mode rendering must reject its absence.
        let err = render_with_config(&local(), serde_yaml::from_str("{}").unwrap()).unwrap_err();
        assert!(!err.is_empty());
    }
}
