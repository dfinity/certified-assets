//! Per-directory `.ic-assets.json` / `.ic-assets.json5` configuration.
//!
//! Ported from `ic-asset/src/asset/config.rs`.  Parses the config for one
//! directory on demand, then lets callers look up the resolved `AssetConfig`
//! for any file inside that directory.  Use `for_subdir` to descend the tree
//! lazily (one directory at a time), which avoids a separate pre-walk.

use crate::content::Encoder;
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub const ASSETS_CONFIG_FILENAME_JSON: &str = ".ic-assets.json";
pub const ASSETS_CONFIG_FILENAME_JSON5: &str = ".ic-assets.json5";

pub type HeadersConfig = BTreeMap<String, String>;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_age: Option<u64>,
}

/// Resolved metadata for a single asset file.
#[derive(Debug, Clone, PartialEq)]
pub struct AssetConfig {
    pub cache: Option<CacheConfig>,
    pub headers: Option<HeadersConfig>,
    pub ignore: Option<bool>,
    pub enable_aliasing: Option<bool>,
    pub allow_raw_access: Option<bool>,
    pub encodings: Option<Vec<Encoder>>,
    /// Parsed but not acted upon until the security-policy TODO is implemented.
    pub security_policy: Option<SecurityPolicy>,
    pub disable_security_policy_warning: Option<bool>,
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self {
            cache: None,
            headers: None,
            ignore: None,
            enable_aliasing: None,
            allow_raw_access: Some(true),
            encodings: None,
            security_policy: None,
            disable_security_policy_warning: None,
        }
    }
}

impl AssetConfig {
    /// Returns the effective HTTP headers for this asset.
    /// Security-policy header injection is deferred to the security-policy TODO.
    pub fn combined_headers(&self) -> Option<HeadersConfig> {
        self.headers.clone()
    }
}

/// Parsed but not yet acted upon — see the security-policy TODO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityPolicy {
    Disabled,
    Standard,
    Hardened,
}

// ── Internal types ───────────────────────────────────────────────────────────

/// Represents an absent / null / present optional value.
/// Used for `headers` so that `null` explicitly clears inherited headers.
#[derive(Debug, Clone, PartialEq, Default)]
enum Maybe<T> {
    Null,
    #[default]
    Absent,
    Value(T),
}

struct AssetConfigRule {
    r#match: GlobMatcher,
    pattern: String,
    cache: Option<CacheConfig>,
    headers: Maybe<HeadersConfig>,
    ignore: Option<bool>,
    enable_aliasing: Option<bool>,
    allow_raw_access: Option<bool>,
    encodings: Option<Vec<Encoder>>,
    security_policy: Option<SecurityPolicy>,
    disable_security_policy_warning: Option<bool>,
    used: bool,
}

impl AssetConfigRule {
    fn applies(&self, path: &Path) -> bool {
        self.r#match.is_match(path)
    }
}

// ── Config tree ──────────────────────────────────────────────────────────────

type ConfigNode = Rc<RefCell<AssetConfigTreeNode>>;

/// Holds the parsed `.ic-assets.json[5]` rules for a **single** directory,
/// with a link to the parent directory's node for inheritance.
///
/// Obtain one via `AssetSourceDirectoryConfiguration::load` for the root, then
/// use `for_subdir` to descend lazily — one directory at a time — without a
/// separate pre-walk of the full directory tree.
pub struct AssetSourceDirectoryConfiguration {
    node: ConfigNode,
}

struct AssetConfigTreeNode {
    parent: Option<ConfigNode>,
    rules: Vec<AssetConfigRule>,
    origin: PathBuf,
}

impl AssetSourceDirectoryConfiguration {
    /// Builds the config node for `root_dir` with no parent.
    /// `root_dir` must be an absolute path.
    pub fn load(root_dir: &Path) -> Result<Self, String> {
        if !root_dir.is_absolute() {
            return Err(format!(
                "root_dir '{}' must be an absolute path",
                root_dir.display()
            ));
        }
        let node = AssetConfigTreeNode::load_single(None, root_dir)?;
        Ok(Self { node })
    }

    /// Returns the config node for an immediate subdirectory, inheriting from
    /// this directory's rules.  Call this as `walk` descends into each subdir
    /// so that configs are loaded on demand rather than in a separate pre-pass.
    pub fn for_subdir(&self, dir: &Path) -> Result<Self, String> {
        let node = AssetConfigTreeNode::load_single(Some(self.node.clone()), dir)?;
        Ok(Self { node })
    }

    /// Returns the resolved `AssetConfig` for `path`, which must be a file
    /// directly inside the directory this config was loaded for.
    pub fn get_asset_config(&self, path: &Path) -> AssetConfig {
        self.node.borrow_mut().get_config(path)
    }

    /// Returns warning strings for every rule in this config node that never
    /// matched any asset.  Only the rules belonging to *this* node are checked;
    /// parent-node rules are reported when the parent directory is visited.
    pub fn get_unused_configs(&self) -> Vec<String> {
        let node = self.node.borrow();
        node.rules
            .iter()
            .filter(|r| !r.used)
            .map(|r| {
                format!(
                    "config in '{}': pattern '{}' did not match any assets",
                    node.origin.display(),
                    r.pattern,
                )
            })
            .collect()
    }

    /// Returns `true` when this config was loaded specifically for `dir` (i.e.
    /// it was not inherited from a parent directory that had no config file).
    pub fn is_own_for_dir(&self, dir: &Path) -> bool {
        self.node.borrow().origin == dir
    }
}

impl AssetConfigTreeNode {
    /// Loads the config file (if any) for a single directory and returns a
    /// node linked to `parent`.  Does **not** recurse into subdirectories.
    fn load_single(parent: Option<ConfigNode>, dir: &Path) -> Result<ConfigNode, String> {
        let json_path = dir.join(ASSETS_CONFIG_FILENAME_JSON);
        let json5_path = dir.join(ASSETS_CONFIG_FILENAME_JSON5);
        let config_path = match (json_path.exists(), json5_path.exists()) {
            (true, true) => {
                return Err(format!(
                    "both {} and {} exist in '{}'",
                    ASSETS_CONFIG_FILENAME_JSON,
                    ASSETS_CONFIG_FILENAME_JSON5,
                    dir.display()
                ));
            }
            (true, false) => Some(json_path),
            (false, true) => Some(json5_path),
            (false, false) => None,
        };

        let mut rules = vec![];
        if let Some(ref cfg_path) = config_path {
            let content = std::fs::read_to_string(cfg_path)
                .map_err(|e| format!("failed to read {} as string: {e}", cfg_path.display()))?;
            let interim: Vec<InterimAssetConfigRule> = json5::from_str(&content).map_err(|_| {
                format!("Malformed JSON asset config file '{}'", cfg_path.display())
            })?;
            for rule_interim in interim {
                let rule = AssetConfigRule::from_interim(rule_interim, dir).map_err(|_| {
                    format!("Malformed JSON asset config file '{}'", cfg_path.display())
                })?;
                rules.push(rule);
            }
        }

        // Optimisation: if this dir has no config file, reuse the parent node
        // rather than creating a new one with an empty rule list.
        let node = match parent {
            Some(p) if rules.is_empty() => p,
            p => Rc::new(RefCell::new(Self {
                parent: p,
                rules,
                origin: dir.to_path_buf(),
            })),
        };

        Ok(node)
    }

    fn get_config(&mut self, path: &Path) -> AssetConfig {
        let base = match &self.parent {
            Some(parent) => parent.clone().borrow_mut().get_config(path),
            None => AssetConfig::default(),
        };
        self.rules
            .iter_mut()
            .filter(|r| r.applies(path))
            .fold(base, |acc, rule| {
                rule.used = true;
                acc.merge(rule)
            })
    }
}

// ── AssetConfig merge ────────────────────────────────────────────────────────

impl AssetConfig {
    fn merge(mut self, other: &AssetConfigRule) -> Self {
        if let Some(c) = &other.cache {
            self.cache = Some(c.clone());
        }
        match (self.headers.as_mut(), &other.headers) {
            (Some(sh), Maybe::Value(oh)) => sh.extend(oh.clone()),
            (None, Maybe::Value(oh)) => self.headers = Some(oh.clone()),
            (_, Maybe::Null) => self.headers = None,
            (_, Maybe::Absent) => (),
        }
        if other.ignore.is_some() {
            self.ignore = other.ignore;
        }
        if other.enable_aliasing.is_some() {
            self.enable_aliasing = other.enable_aliasing;
        }
        if other.allow_raw_access.is_some() {
            self.allow_raw_access = other.allow_raw_access;
        }
        if other.encodings.is_some() {
            self.encodings.clone_from(&other.encodings);
        }
        if other.security_policy.is_some() {
            self.security_policy = other.security_policy;
        }
        if other.disable_security_policy_warning.is_some() {
            self.disable_security_policy_warning = other.disable_security_policy_warning;
        }
        self
    }
}

// ── Deserialization helpers ──────────────────────────────────────────────────

/// Intermediate representation used during JSON5 parsing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterimAssetConfigRule {
    r#match: String,
    cache: Option<CacheConfig>,
    #[serde(default, deserialize_with = "deser_headers")]
    headers: Maybe<HeadersConfig>,
    ignore: Option<bool>,
    enable_aliasing: Option<bool>,
    allow_raw_access: Option<bool>,
    encodings: Option<Vec<Encoder>>,
    security_policy: Option<SecurityPolicy>,
    disable_security_policy_warning: Option<bool>,
}

fn deser_headers<'de, D>(deserializer: D) -> Result<Maybe<HeadersConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Object(map) => {
            let headers = map
                .into_iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => s,
                        serde_json::Value::Null => String::new(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "headers must be strings, numbers, or bools (got {other:?})"
                            )))
                        }
                    };
                    Ok((k, val))
                })
                .collect::<Result<BTreeMap<String, String>, D::Error>>()?;
            Ok(Maybe::Value(headers))
        }
        serde_json::Value::Null => Ok(Maybe::Null),
        _ => Err(D::Error::custom(
            "wrong data format for field `headers` (only map or null are allowed)",
        )),
    }
}

impl AssetConfigRule {
    fn from_interim(interim: InterimAssetConfigRule, config_dir: &Path) -> Result<Self, String> {
        let glob_path = config_dir.join(&interim.r#match);
        let glob_str = glob_path.to_str().ok_or_else(|| {
            format!(
                "failed to combine '{}' and '{}' into a glob string",
                config_dir.display(),
                interim.r#match
            )
        })?;
        let matcher = Glob::new(glob_str)
            .map_err(|e| format!("'{}' is not a valid glob pattern: {e}", interim.r#match))?
            .compile_matcher();
        Ok(Self {
            r#match: matcher,
            pattern: interim.r#match,
            cache: interim.cache,
            headers: interim.headers,
            ignore: interim.ignore,
            enable_aliasing: interim.enable_aliasing,
            allow_raw_access: interim.allow_raw_access,
            encodings: interim.encodings,
            security_policy: interim.security_policy,
            disable_security_policy_warning: interim.disable_security_policy_warning,
            used: false,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;
    use std::{fs, fs::File};
    use tempfile::TempDir;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn tmpdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Creates a minimal assets directory with config files and some asset files.
    fn make_assets_dir(config_files: HashMap<&str, &str>, asset_paths: &[&str]) -> TempDir {
        let dir = tmpdir();
        for p in asset_paths {
            let full = dir.path().join(p);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            File::create(full).unwrap();
        }
        for (sub, content) in &config_files {
            let full = dir.path().join(sub).join(ASSETS_CONFIG_FILENAME_JSON);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            write!(File::create(full).unwrap(), "{content}").unwrap();
        }
        dir
    }

    fn load(dir: &TempDir) -> AssetSourceDirectoryConfiguration {
        AssetSourceDirectoryConfiguration::load(&dir.path().canonicalize().unwrap()).unwrap()
    }

    fn cfg(ac: &AssetSourceDirectoryConfiguration, dir: &TempDir, path: &str) -> AssetConfig {
        ac.get_asset_config(&dir.path().canonicalize().unwrap().join(path))
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn max_age_from_nested_config() {
        let mut files = HashMap::new();
        files.insert("nested", r#"[{"match": "*", "cache": {"max_age": 333}}]"#);
        let d = make_assets_dir(files, &["index.html", "nested/thing.txt"]);
        let root_ac = load(&d);
        let nested_path = d.path().canonicalize().unwrap().join("nested");
        let nested_ac = root_ac.for_subdir(&nested_path).unwrap();

        assert_eq!(
            nested_ac
                .get_asset_config(&d.path().canonicalize().unwrap().join("nested/thing.txt"))
                .cache,
            Some(CacheConfig { max_age: Some(333) })
        );
        assert_eq!(cfg(&root_ac, &d, "index.html").cache, None);
    }

    #[test]
    fn child_config_overrides_parent() {
        let mut files = HashMap::new();
        files.insert("", r#"[{"match": "*", "cache": {"max_age": 999}}]"#);
        files.insert("nested", r#"[{"match": "*", "cache": {"max_age": 111}}]"#);
        let d = make_assets_dir(files, &["index.html", "nested/thing.txt"]);
        let root_ac = load(&d);
        let nested_path = d.path().canonicalize().unwrap().join("nested");
        let nested_ac = root_ac.for_subdir(&nested_path).unwrap();

        assert_eq!(
            nested_ac
                .get_asset_config(&d.path().canonicalize().unwrap().join("nested/thing.txt"))
                .cache,
            Some(CacheConfig { max_age: Some(111) })
        );
        assert_eq!(
            cfg(&root_ac, &d, "index.html").cache,
            Some(CacheConfig { max_age: Some(999) })
        );
    }

    #[test]
    fn headers_merged_across_rules() {
        let content = r#"[
          {"match": "index.html", "headers": {"X-A": "a", "X-B": "old"}},
          {"match": "*",          "headers": {"X-B": "new", "X-C": "c"}}
        ]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &["index.html"]);
        let ac = load(&d);

        let headers = cfg(&ac, &d, "index.html").headers.unwrap();
        assert_eq!(headers["X-A"], "a");
        assert_eq!(headers["X-B"], "new"); // overridden by later rule
        assert_eq!(headers["X-C"], "c");
    }

    #[test]
    fn null_headers_clears_inherited() {
        let content = r#"[
          {"match": "*",       "headers": {"X-A": "a"}},
          {"match": "*.html",  "headers": null}
        ]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &["index.html", "app.js"]);
        let ac = load(&d);

        assert!(cfg(&ac, &d, "index.html").headers.is_none());
        assert!(cfg(&ac, &d, "app.js").headers.is_some());
    }

    #[test]
    fn ignore_flag_set() {
        let content = r#"[{"match": "*.secret", "ignore": true}]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &["data.secret", "index.html"]);
        let ac = load(&d);

        assert_eq!(cfg(&ac, &d, "data.secret").ignore, Some(true));
        assert_eq!(cfg(&ac, &d, "index.html").ignore, None);
    }

    #[test]
    fn allow_raw_access_default_is_true() {
        let mut files = HashMap::new();
        files.insert("", "[]");
        let d = make_assets_dir(files, &[]);
        let ac = load(&d);

        assert_eq!(cfg(&ac, &d, "index.html").allow_raw_access, Some(true));
    }

    #[test]
    fn allow_raw_access_can_be_overridden() {
        let content = r#"[{"match": "*", "allow_raw_access": false}]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &[]);
        let ac = load(&d);

        assert_eq!(cfg(&ac, &d, "index.html").allow_raw_access, Some(false));
    }

    #[test]
    fn encoding_override() {
        let content = r#"[{"match": "**/*.txt", "encodings": []}, {"match": "*.unknown", "encodings": ["gzip"]}]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &[]);
        let ac = load(&d);

        assert_eq!(cfg(&ac, &d, "data.txt").encodings, Some(vec![]));
        assert_eq!(
            cfg(&ac, &d, "file.unknown").encodings,
            Some(vec![Encoder::Gzip])
        );
    }

    #[test]
    fn json5_filename_is_loaded() {
        let d = tmpdir();
        write!(
            File::create(d.path().join(ASSETS_CONFIG_FILENAME_JSON5)).unwrap(),
            r#"[{{ "match": "*", cache: {{ max_age: 77 }} }}]"#,
        )
        .unwrap();
        let ac =
            AssetSourceDirectoryConfiguration::load(&d.path().canonicalize().unwrap()).unwrap();
        assert_eq!(
            ac.get_asset_config(&d.path().canonicalize().unwrap().join("any.html"))
                .cache,
            Some(CacheConfig { max_age: Some(77) })
        );
    }

    #[test]
    fn json5_with_comments_and_unquoted_keys() {
        let content = r#"[
            // a comment
            { "match": "*", cache: { max_age: 42 } }
        ]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &[]);
        let ac = load(&d);

        assert_eq!(
            cfg(&ac, &d, "any.html").cache,
            Some(CacheConfig { max_age: Some(42) })
        );
    }

    #[test]
    fn both_config_files_is_an_error() {
        let d = tmpdir();
        File::create(d.path().join(ASSETS_CONFIG_FILENAME_JSON)).unwrap();
        File::create(d.path().join(ASSETS_CONFIG_FILENAME_JSON5)).unwrap();
        let result = AssetSourceDirectoryConfiguration::load(&d.path().canonicalize().unwrap());
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("both"));
    }

    #[test]
    fn malformed_config_returns_error() {
        let mut files = HashMap::new();
        files.insert("", "[[[");
        let d = make_assets_dir(files, &[]);
        let result = AssetSourceDirectoryConfiguration::load(&d.path().canonicalize().unwrap());
        assert!(result.is_err());
        assert!(
            result.err().unwrap().contains("Malformed"),
            "expected 'Malformed' in error"
        );
    }

    #[test]
    fn relative_root_returns_error() {
        let result = AssetSourceDirectoryConfiguration::load(Path::new("relative/path"));
        assert!(result.is_err());
    }

    #[test]
    fn path_outside_tree_returns_default() {
        let d = make_assets_dir(HashMap::new(), &[]);
        let ac = load(&d);
        // Path whose parent dir was never loaded — falls back to the root node's
        // get_config, which returns AssetConfig::default() (no matching rules).
        let outside = d.path().join("../outside/file.txt");
        let result = ac.get_asset_config(&outside);
        assert_eq!(result, AssetConfig::default());
    }
}
