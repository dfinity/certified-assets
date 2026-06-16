//! `recipe-gen` — emit the `certified-assets` recipe (`recipe.hbs`) pinning the
//! canister and sync-plugin wasm either by local path or by release URL + sha256.
//!
//! ```text
//! recipe-gen local   --canister <path> --plugin <path> [-o <out>]
//! recipe-gen release --version <vX.Y.Z>
//!                    (--shas-from <dir> | --canister-sha <hex> --plugin-sha <hex>)
//!                    [-o <out>]
//! ```
//!
//! With no `-o`, the recipe is written to stdout.

use std::collections::HashMap;
use std::path::Path;
use std::process::exit;

use recipe_gen::{read_sha256_file, render_recipe, WasmSource};

const USAGE: &str = "\
usage:
  recipe-gen local   --canister <path> --plugin <path> [-o <out>]
  recipe-gen release --version <vX.Y.Z> (--shas-from <dir> | --canister-sha <hex> --plugin-sha <hex>) [-o <out>]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("recipe-gen: {e}\n\n{USAGE}");
        exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = args.split_first().ok_or("missing command")?;
    let flags = parse_flags(rest)?;

    let source = match cmd.as_str() {
        "local" => WasmSource::Local {
            canister: required(&flags, "canister")?,
            plugin: required(&flags, "plugin")?,
        },
        "release" => {
            let version = required(&flags, "version")?;
            let (canister_sha, plugin_sha) = match flags.get("shas-from") {
                Some(dir) => {
                    let dir = Path::new(dir);
                    let read =
                        |name: &str| read_sha256_file(&dir.join(name)).map_err(|e| e.to_string());
                    (
                        read("canister-release.wasm.gz.sha256")?,
                        read("plugin-release.wasm.sha256")?,
                    )
                }
                None => (
                    required(&flags, "canister-sha")?,
                    required(&flags, "plugin-sha")?,
                ),
            };
            WasmSource::Release {
                version,
                canister_sha,
                plugin_sha,
            }
        }
        other => return Err(format!("unknown command '{other}'")),
    };

    let recipe = render_recipe(&source);
    match flags.get("o").or_else(|| flags.get("output")) {
        Some(path) => std::fs::write(path, recipe).map_err(|e| format!("write {path}: {e}"))?,
        None => print!("{recipe}"),
    }
    Ok(())
}

fn required(flags: &HashMap<String, String>, key: &str) -> Result<String, String> {
    flags
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing required flag --{key}"))
}

/// Minimal `--flag value` / `-o value` parser. Every flag takes a value.
fn parse_flags(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let key = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .ok_or_else(|| format!("unexpected argument '{arg}'"))?;
        let value = it
            .next()
            .ok_or_else(|| format!("missing value for '{arg}'"))?;
        map.insert(key.to_string(), value.clone());
    }
    Ok(map)
}
