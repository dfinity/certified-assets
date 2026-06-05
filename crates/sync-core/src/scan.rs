//! Scan a project's input directory for asset files.
//!
//! Matches `ic-asset`'s traversal behaviour: only plain files are included;
//! dotfiles and all symlinks (to files or directories) are skipped.
//! Exception: `.well-known/` is traversed even though it starts with `.`,
//! mirroring `ic-asset`'s `KNOWN_DIRECTORIES` list.
//!
//! Files whose names appear in `CONFIG_FILENAMES` (`_redirects`, etc.) are
//! consumed by the sync layer and excluded from the upload set.

use crate::headers::HEADERS_FILENAME;
use crate::redirects::REDIRECTS_FILENAME;
use std::path::{Path, PathBuf};

const KNOWN_DIRECTORIES: &[&str] = &[".well-known"];

/// Filenames whose presence is configuration, not asset content. Loaded for
/// their side effects (redirect rules, header rules, etc.) and excluded from
/// the upload set.
const CONFIG_FILENAMES: &[&str] = &[REDIRECTS_FILENAME, HEADERS_FILENAME];

#[derive(Debug)]
pub struct AssetSource {
    pub path: PathBuf,
    pub key: String,
}

/// Scans `dir` for asset files.
pub fn scan(dir: &str) -> Result<Vec<AssetSource>, String> {
    let mut out = Vec::new();
    let root = Path::new(dir);
    let root_abs = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;
    walk(&root_abs, &root_abs, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, current: &Path, out: &mut Vec<AssetSource>) -> Result<(), String> {
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
            walk(root, &path, out)?;
        } else if ft.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| format!("strip_prefix {}: {e}", path.display()))?;
            let key = format!("/{}", relative.to_string_lossy());
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
        let keys = sorted_keys(scan(&dir_str(&dir)).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn nested_directory() {
        let dir = tmp();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/app.js"), b"js").unwrap();
        let keys = sorted_keys(scan(&dir_str(&dir)).unwrap());
        assert_eq!(keys, vec!["/sub/app.js"]);
    }

    #[test]
    fn dotfile_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(".hidden"), b"secret").unwrap();
        fs::write(dir.path().join(".gitignore"), b"*.tmp").unwrap();
        fs::write(dir.path().join("visible.txt"), b"ok").unwrap();
        let keys = sorted_keys(scan(&dir_str(&dir)).unwrap());
        assert_eq!(keys, vec!["/visible.txt"]);
    }

    #[test]
    fn redirects_file_skipped() {
        let dir = tmp();
        fs::write(dir.path().join(REDIRECTS_FILENAME), b"").unwrap();
        fs::write(dir.path().join("index.html"), b"hi").unwrap();
        let keys = sorted_keys(scan(&dir_str(&dir)).unwrap());
        assert_eq!(keys, vec!["/index.html"]);
    }

    #[test]
    fn empty_directory() {
        let dir = tmp();
        assert!(scan(&dir_str(&dir)).unwrap().is_empty());
    }

    #[test]
    fn well_known_directory_included() {
        let dir = tmp();
        fs::create_dir(dir.path().join(".well-known")).unwrap();
        fs::write(dir.path().join(".well-known/ic-domains"), b"foo.bar.com").unwrap();
        fs::write(dir.path().join("index.html"), b"hello").unwrap();
        let keys = sorted_keys(scan(&dir_str(&dir)).unwrap());
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
        let keys = sorted_keys(scan(&dir_str(&dir)).unwrap());
        assert_eq!(keys, vec!["/real.txt"]);
    }
}
