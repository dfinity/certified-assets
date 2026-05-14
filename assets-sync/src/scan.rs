//! Scan preopened dirs for asset files.
//!
//! Matches `ic-asset`'s traversal behaviour: only plain files are included;
//! dotfiles and all symlinks (to files or directories) are skipped.
//! Exception: `.well-known/` is traversed even though it starts with `.`,
//! mirroring `ic-asset`'s `KNOWN_DIRECTORIES` list.
//!
//! Each returned `AssetSource` carries the `AssetConfig` resolved from any
//! `.ic-assets.json` / `.ic-assets.json5` files found in the directory tree.
//! Files whose config has `ignore: true` are excluded from the output.

use crate::config::{AssetConfig, AssetSourceDirectoryConfiguration};
use std::path::{Path, PathBuf};

const KNOWN_DIRECTORIES: &[&str] = &[".well-known"];

#[derive(Debug)]
pub struct AssetSource {
    pub path: PathBuf,
    pub key: String,
    pub config: AssetConfig,
}

pub fn scan(dirs: &[String]) -> Result<Vec<AssetSource>, String> {
    let mut out = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for dir in dirs {
        let root = Path::new(dir);
        // Config loading requires an absolute path.  Canonicalize so that the
        // paths used in the walk match those stored in the config map.
        let root_abs = root
            .canonicalize()
            .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;
        let root_config = AssetSourceDirectoryConfiguration::load(&root_abs)?;
        walk(&root_abs, &root_abs, &mut out, &mut seen_keys, &root_config)?;
    }
    Ok(out)
}

fn walk(
    root: &Path,
    current: &Path,
    out: &mut Vec<AssetSource>,
    seen_keys: &mut std::collections::HashSet<String>,
    dir_config: &AssetSourceDirectoryConfiguration,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(current).map_err(|e| format!("read_dir {}: {e}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry in {}: {e}", current.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| format!("file_type {}: {e}", path.display()))?;

        // Skip dotfiles / dotdirs (except known dirs like .well-known).
        if name_str.starts_with('.') && !(ft.is_dir() && KNOWN_DIRECTORIES.contains(&&*name_str)) {
            continue;
        }

        if ft.is_dir() {
            let sub_config = dir_config.for_subdir(&path)?;
            walk(root, &path, out, seen_keys, &sub_config)?;
        } else if ft.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| format!("strip_prefix {}: {e}", path.display()))?;
            let key = format!("/{}", relative.to_string_lossy());

            let config = dir_config.get_asset_config(&path);

            // Respect the `ignore` flag from .ic-assets.json[5].
            if config.ignore == Some(true) {
                continue;
            }

            if !seen_keys.insert(key.clone()) {
                return Err(format!("duplicate asset key {key}"));
            }
            out.push(AssetSource { path, key, config });
        }
        // Symlinks (to files or directories) are skipped, matching ic-asset::sync.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ASSETS_CONFIG_FILENAME_JSON, ASSETS_CONFIG_FILENAME_JSON5};
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
        fs::write(dir.path().join(".gitignore"), b"*.tmp").unwrap();
        fs::write(dir.path().join("visible.txt"), b"ok").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/visible.txt"]);
    }

    #[test]
    fn ic_assets_config_file_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(ASSETS_CONFIG_FILENAME_JSON), b"[]").unwrap();
        fs::write(dir.path().join("index.html"), b"hi").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn ic_assets_json5_config_file_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(ASSETS_CONFIG_FILENAME_JSON5), b"[]").unwrap();
        fs::write(dir.path().join("index.html"), b"hi").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
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

    #[test]
    fn multiple_source_dirs() {
        let dir1 = tmp();
        let dir2 = tmp();
        fs::write(dir1.path().join("a.txt"), b"a").unwrap();
        fs::write(dir2.path().join("b.txt"), b"b").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir1), dir_str(&dir2)]).unwrap());
        assert_eq!(keys, vec!["/a.txt", "/b.txt"]);
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
    fn ignored_file_excluded() {
        let dir = tmp();
        fs::write(
            dir.path().join(ASSETS_CONFIG_FILENAME_JSON),
            br#"[{"match": "*.secret", "ignore": true}]"#,
        )
        .unwrap();
        fs::write(dir.path().join("data.secret"), b"secret").unwrap();
        fs::write(dir.path().join("index.html"), b"public").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn config_fields_attached_to_source() {
        let dir = tmp();
        fs::write(
            dir.path().join(ASSETS_CONFIG_FILENAME_JSON),
            br#"[{"match": "*.html", "cache": {"max_age": 3600}, "allow_raw_access": false}]"#,
        )
        .unwrap();
        fs::write(dir.path().join("index.html"), b"hi").unwrap();

        let sources = scan(&[dir_str(&dir)]).unwrap();
        assert_eq!(sources.len(), 1);
        let config = &sources[0].config;
        assert_eq!(
            config.cache,
            Some(crate::config::CacheConfig {
                max_age: Some(3600)
            })
        );
        assert_eq!(config.allow_raw_access, Some(false));
    }

    #[test]
    fn default_allow_raw_access_is_true() {
        let dir = tmp();
        fs::write(dir.path().join("index.html"), b"hi").unwrap();
        let sources = scan(&[dir_str(&dir)]).unwrap();
        assert_eq!(sources[0].config.allow_raw_access, Some(true));
    }

    // Symlinks are skipped regardless of target type, matching ic-asset::sync.
    #[cfg(unix)]
    #[test]
    fn symlink_skipped() {
        let dir = tmp();
        let target = dir.path().join("real.txt");
        fs::write(&target, b"content").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/real.txt"]);
    }
}
