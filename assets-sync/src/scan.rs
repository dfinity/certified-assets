//! Scan a project's input directory for asset files.
//!
//! Matches `ic-asset`'s traversal behaviour: only plain files are included;
//! dotfiles and all symlinks (to files or directories) are skipped.
//! Exception: `.well-known/` is traversed even though it starts with `.`,
//! mirroring `ic-asset`'s `KNOWN_DIRECTORIES` list.
//!
//! Files whose names appear in `CONFIG_FILENAMES` (`_redirects`, etc.) are
//! consumed by the sync layer and excluded from the upload set.

use crate::redirects::REDIRECTS_FILENAME;
use std::path::{Path, PathBuf};

const KNOWN_DIRECTORIES: &[&str] = &[".well-known"];

/// Filenames whose presence is configuration, not asset content. Loaded for
/// their side effects (redirect rules, etc.) and excluded from the upload set.
const CONFIG_FILENAMES: &[&str] = &[REDIRECTS_FILENAME];

#[derive(Debug)]
pub struct AssetSource {
    pub path: PathBuf,
    pub key: String,
}

/// Scans `dirs` for asset files.
pub fn scan(dirs: &[String]) -> Result<Vec<AssetSource>, String> {
    let mut out = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for dir in dirs {
        let root = Path::new(dir);
        let root_abs = root
            .canonicalize()
            .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;
        walk(&root_abs, &root_abs, &mut out, &mut seen_keys)?;
    }
    Ok(out)
}

fn walk(
    root: &Path,
    current: &Path,
    out: &mut Vec<AssetSource>,
    seen_keys: &mut std::collections::HashSet<String>,
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

        // Skip config files (`_redirects` etc.) regardless of where they sit
        // in the tree — they're consumed by the sync layer, not uploaded.
        if ft.is_file() && CONFIG_FILENAMES.contains(&&*name_str) {
            continue;
        }

        if ft.is_dir() {
            walk(root, &path, out, seen_keys)?;
        } else if ft.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| format!("strip_prefix {}: {e}", path.display()))?;
            let key = format!("/{}", relative.to_string_lossy());

            if !seen_keys.insert(key.clone()) {
                return Err(format!("duplicate asset key {key}"));
            }
            out.push(AssetSource { path, key });
        }
        // Symlinks (to files or directories) are skipped, matching ic-asset::sync.
    }

    Ok(())
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
        fs::write(dir.path().join(".gitignore"), b"*.tmp").unwrap();
        fs::write(dir.path().join("visible.txt"), b"ok").unwrap();
        let keys = sorted_keys(scan(&[dir_str(&dir)]).unwrap());
        assert_eq!(keys, vec!["/visible.txt"]);
    }

    #[test]
    fn redirects_file_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(REDIRECTS_FILENAME), b"").unwrap();
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
