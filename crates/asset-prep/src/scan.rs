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
///
/// `dir` is used exactly as given — neither canonicalized nor rewritten — so a
/// relative path stays relative. Both callers depend on that: the `state-hash`
/// verifier is run from a shell (`state-hash ./dist`, as
/// `docs/verifying-contents.md` documents) where a relative path resolves
/// against the process's working directory, and under WASI the sync plugin's
/// `dir` is the guest name of a read-only preopen, which resolves relative just
/// as well. It also matches how `prepare` reads `_headers` / `_redirects` from
/// the same `dir`.
///
/// In particular, do not reintroduce [`Path::canonicalize`]. Under WASI it calls
/// `realpath`, which returns `ENOENT` ("No such file or directory") for *any*
/// path beneath a preopen whose guest name has more than one component (e.g.
/// `src/frontend/dist`) — even though ordinary access (`read_dir`, `metadata`,
/// `read`) through that preopen works fine. Nothing here needs an absolute root:
/// [`walk`] only joins onto the root it was handed and strips that same prefix
/// back off to build keys. Sandbox safety is the preopen's, not this path's: a
/// WASI guest reaches nothing outside its preopens however it spells a path, and
/// the host rejects `dirs` entries that are absolute or contain `..` before
/// preopening them.
pub fn scan(dir: &str) -> Result<Vec<AssetSource>, String> {
    let mut out = Vec::new();
    let root = Path::new(dir);
    walk(root, root, &mut out)?;
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

    // A relative dir must be scanned relative to the working directory, not
    // reinterpreted as absolute: `state-hash ./dist` is the invocation
    // `docs/verifying-contents.md` documents, and it used to fail with
    // "read_dir /dist: No such file or directory".
    //
    // Scans this crate's own `src/` — cargo runs a test with the crate root as
    // the working directory. A tempdir can't stand in: it would have to be
    // created under that same working directory to be nameable relatively, and
    // creating/removing one there changes the directory's mtime, which is how
    // `crates/e2e/build.rs` decides whether to rebuild the wasm.
    #[test]
    fn relative_directory() {
        let keys = sorted_keys(scan("./src").expect("scan a relative dir"));
        assert!(
            keys.contains(&"/scan.rs".to_string()),
            "expected this file among the keys scanned from ./src; got: {keys:?}"
        );
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
