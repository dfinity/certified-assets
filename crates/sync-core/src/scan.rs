//! Scan a project's input directory for asset files, applying the per-directory
//! `.ic-assets.json5` configuration.
//!
//! Ported from `ic-asset`'s `gather_asset_descriptors` / `include_entry`:
//! - dotfiles and dotdirs are skipped unless a config rule re-includes them
//!   (`"ignore": false`), with the exception of `KNOWN_DIRECTORIES` (`.well-known`),
//! - a rule's `"ignore": true` drops a path (and prunes a directory subtree),
//! - the `.ic-assets.json` / `.ic-assets.json5` files themselves are never uploaded,
//! - each surviving file carries its resolved [`AssetConfig`].
//!
//! Symlinks are not followed (walkdir default), matching `ic-asset`.

use crate::config::{
    AssetConfig, AssetSourceDirectoryConfiguration, ASSETS_CONFIG_FILENAME_JSON,
    ASSETS_CONFIG_FILENAME_JSON5,
};
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const KNOWN_DIRECTORIES: &[&str] = &[".well-known"];

#[derive(Debug)]
pub struct AssetSource {
    pub path: PathBuf,
    pub key: String,
    pub config: AssetConfig,
}

/// Builds an absolute root for `dir` (a manifest-relative directory the host
/// preopened) by prepending `/` and dropping `.` / redundant components.
///
/// We deliberately avoid [`Path::canonicalize`] here. Under WASI it calls
/// `realpath`, which returns `ENOENT` ("No such file or directory") for *any*
/// path beneath a preopen whose guest name has more than one component (e.g.
/// `src/frontend/dist`) — even though ordinary access (`read_dir`, `metadata`,
/// `read`) through that preopen works fine. Single-component dirs like `dist`
/// happen to canonicalize to `/dist`; this helper produces the same shape
/// (`/src/frontend/dist`) for nested dirs without touching `realpath`, and gives
/// [`AssetSourceDirectoryConfiguration::load`] the absolute root it requires.
///
/// The host guarantees `dir` is relative and free of `..` components, so keeping
/// only `Normal` components cannot escape the preopen.
fn absolute_root(dir: &str) -> PathBuf {
    let mut root = PathBuf::from("/");
    for component in Path::new(dir).components() {
        if let std::path::Component::Normal(c) = component {
            root.push(c);
        }
    }
    root
}

/// Scans `dirs` for asset files, resolving each file's `.ic-assets.json5` config.
pub fn scan(dirs: &[String]) -> Result<Vec<AssetSource>, String> {
    let mut out: Vec<AssetSource> = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    for dir in dirs {
        let root = absolute_root(dir);
        let mut configuration = AssetSourceDirectoryConfiguration::load(&root)?;

        let entries: Vec<DirEntry> = WalkDir::new(&root)
            .into_iter()
            .filter_entry(|entry| {
                // The root itself is always traversed; pruning it (e.g. when the
                // root dir name starts with `.`) would drop the whole tree.
                if entry.depth() == 0 {
                    return true;
                }
                // `entry.path()` is already rooted at `root`, so it matches the
                // config-map keys directly — no canonicalization needed.
                let config = configuration
                    .get_asset_config(entry.path())
                    .unwrap_or_default();
                include_entry(entry, &config)
            })
            .filter_map(|r| r.ok())
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry.file_name() != ASSETS_CONFIG_FILENAME_JSON
                    && entry.file_name() != ASSETS_CONFIG_FILENAME_JSON5
            })
            .collect();

        for entry in entries {
            let source = entry.path().to_path_buf();
            let relative = source
                .strip_prefix(&root)
                .map_err(|e| format!("strip_prefix {}: {e}", source.display()))?;
            let key = format!("/{}", relative.to_string_lossy());
            let config = configuration.get_asset_config(&source)?;

            if !seen_keys.insert(key.clone()) {
                return Err(format!("duplicate asset key {key}"));
            }
            out.push(AssetSource {
                path: source,
                key,
                config,
            });
        }
    }

    Ok(out)
}

/// Decides whether a walkdir entry is included, mirroring `ic-asset::include_entry`.
/// An explicit `ignore` rule wins; otherwise dotfiles/dotdirs are excluded unless
/// they are a known directory (e.g. `.well-known`).
fn include_entry(entry: &DirEntry, config: &AssetConfig) -> bool {
    if let Some(ignored) = config.ignore {
        !ignored
    } else if let Some(entry_name) = entry.file_name().to_str() {
        let is_known = entry.file_type().is_dir() && KNOWN_DIRECTORIES.contains(&entry_name);
        is_known || !entry_name.starts_with('.')
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    fn sorted_keys(sources: Vec<AssetSource>) -> Vec<String> {
        let mut keys: Vec<String> = sources.into_iter().map(|s| s.key).collect();
        keys.sort();
        keys
    }

    fn dir_str(d: &TempDir) -> String {
        d.path().to_str().unwrap().to_string()
    }

    #[test]
    fn single_file() {
        let dir = tmp();
        fs::write(dir.path().join("index.html"), b"hello").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn nested_directory() {
        let dir = tmp();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/app.js"), b"js").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/sub/app.js"]);
    }

    #[test]
    fn dotfile_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(".hidden"), b"secret").unwrap();
        fs::write(dir.path().join("visible.txt"), b"ok").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/visible.txt"]);
    }

    #[test]
    fn config_file_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(".ic-assets.json5"), b"[]").unwrap();
        fs::write(dir.path().join("index.html"), b"hi").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn ignore_rule_excludes_file() {
        let dir = tmp();
        fs::write(
            dir.path().join(".ic-assets.json5"),
            br#"[{ "match": "secret.txt", "ignore": true }]"#,
        )
        .unwrap();
        fs::write(dir.path().join("secret.txt"), b"x").unwrap();
        fs::write(dir.path().join("index.html"), b"y").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn reinclude_dotfile_via_config() {
        let dir = tmp();
        fs::write(
            dir.path().join(".ic-assets.json5"),
            br#"[{ "match": ".env", "ignore": false }]"#,
        )
        .unwrap();
        fs::write(dir.path().join(".env"), b"x").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/.env"]);
    }

    #[test]
    fn config_attaches_to_source() {
        let dir = tmp();
        fs::write(
            dir.path().join(".ic-assets.json5"),
            br#"[{ "match": "*.html", "headers": { "X-Foo": "bar" } }]"#,
        )
        .unwrap();
        fs::write(dir.path().join("index.html"), b"x").unwrap();
        let sources = scan(&[dir_str(&dir)]).unwrap();
        let src = sources.iter().find(|s| s.key == "/index.html").unwrap();
        assert_eq!(
            src.config
                .headers
                .as_ref()
                .unwrap()
                .get("X-Foo")
                .map(String::as_str),
            Some("bar")
        );
    }

    #[test]
    fn well_known_directory_included() {
        let dir = tmp();
        fs::create_dir(dir.path().join(".well-known")).unwrap();
        fs::write(dir.path().join(".well-known/ic-domains"), b"foo.bar.com").unwrap();
        fs::write(dir.path().join("index.html"), b"hello").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/.well-known/ic-domains", "/index.html"]);
    }

    #[test]
    fn empty_directory() {
        let dir = tmp();
        assert!(scan(&[dir_str(&dir)]).unwrap().is_empty());
    }

    #[test]
    fn duplicate_key_across_two_source_dirs() {
        let dir1 = tmp();
        let dir2 = tmp();
        fs::write(dir1.path().join("index.html"), b"v1").unwrap();
        fs::write(dir2.path().join("index.html"), b"v2").unwrap();
        let err = scan(&[dir_str(&dir1), dir_str(&dir2)]).unwrap_err();
        assert!(
            err.contains("/index.html"),
            "error should name the key: {err}"
        );
    }
}
