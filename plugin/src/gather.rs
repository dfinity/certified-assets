//! Walk preopened dirs to produce asset descriptors.
//!
//! Skips dotfiles (matching `ic-asset`'s `include_entry` heuristic, minus
//! the `.well-known` exception which we don't need for the basic case).

use std::path::{Path, PathBuf};

pub struct AssetDescriptor {
    pub source: PathBuf,
    pub key: String,
}

pub fn gather(dirs: &[String]) -> Result<Vec<AssetDescriptor>, String> {
    let mut out = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for dir in dirs {
        let root = Path::new(dir);
        walk(root, root, &mut out, &mut seen_keys)?;
    }
    Ok(out)
}

fn walk(
    root: &Path,
    current: &Path,
    out: &mut Vec<AssetDescriptor>,
    seen_keys: &mut std::collections::HashSet<String>,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(current).map_err(|e| format!("read_dir {}: {e}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry in {}: {e}", current.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| format!("file_type {}: {e}", path.display()))?;
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
            out.push(AssetDescriptor { source: path, key });
        }
    }
    Ok(())
}
