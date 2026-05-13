//! Per-directory `.ic-assets.json` / `.ic-assets.json5` configuration.
//!
//! Ported from `ic-asset/src/asset/config.rs`.  Parses the config tree once
//! for a root directory, then lets callers look up the resolved `AssetConfig`
//! for any file inside that tree.

use crate::content::Encoder;
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
#[derive(Debug, Clone, PartialEq)]
#[derive(Default)]
enum Maybe<T> {
    Null,
    #[default]
    Absent,
    Value(T),
}


struct AssetConfigRule {
    r#match: GlobMatcher,
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

type ConfigNode = Arc<Mutex<AssetConfigTreeNode>>;
type ConfigMap = HashMap<PathBuf, ConfigNode>;

/// Aggregates `.ic-assets.json[5]` files nested under a root directory.
pub struct AssetSourceDirectoryConfiguration {
    config_map: ConfigMap,
}

struct AssetConfigTreeNode {
    parent: Option<ConfigNode>,
    rules: Vec<AssetConfigRule>,
    // Only used for diagnostics / unused-rule reporting.
    #[allow(dead_code)]
    origin: PathBuf,
}

impl AssetSourceDirectoryConfiguration {
    /// Builds the config tree for `root_dir`, which must be an absolute path.
    pub fn load(root_dir: &Path) -> Result<Self, String> {
        if !root_dir.is_absolute() {
            return Err(format!(
                "root_dir '{}' must be an absolute path",
                root_dir.display()
            ));
        }
        let mut config_map = HashMap::new();
        AssetConfigTreeNode::load(None, root_dir, &mut config_map)?;
        Ok(Self { config_map })
    }

    /// Returns the resolved `AssetConfig` for the given file path.
    /// Falls back to `AssetConfig::default()` if the path is outside the tree.
    pub fn get_asset_config(&mut self, path: &Path) -> AssetConfig {
        let parent_dir = match path.parent() {
            Some(p) => p.to_path_buf(),
            None => return AssetConfig::default(),
        };
        match self.config_map.get(&parent_dir) {
            Some(node) => node.clone().lock().unwrap().get_config(path),
            None => AssetConfig::default(),
        }
    }
}

impl AssetConfigTreeNode {
    fn load(parent: Option<ConfigNode>, dir: &Path, configs: &mut ConfigMap) -> Result<(), String> {
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
            p => Arc::new(Mutex::new(Self {
                parent: p,
                rules,
                origin: dir.to_path_buf(),
            })),
        };

        configs.insert(dir.to_path_buf(), node.clone());

        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                Self::load(Some(node.clone()), &entry.path(), configs)?;
            }
        }
        Ok(())
    }

    fn get_config(&mut self, path: &Path) -> AssetConfig {
        let base = match &self.parent {
            Some(parent) => parent.clone().lock().unwrap().get_config(path),
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

    fn cfg(ac: &mut AssetSourceDirectoryConfiguration, dir: &TempDir, path: &str) -> AssetConfig {
        ac.get_asset_config(&dir.path().canonicalize().unwrap().join(path))
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn max_age_from_nested_config() {
        let mut files = HashMap::new();
        files.insert("nested", r#"[{"match": "*", "cache": {"max_age": 333}}]"#);
        let d = make_assets_dir(files, &["index.html", "nested/thing.txt"]);
        let mut ac = load(&d);

        assert_eq!(
            cfg(&mut ac, &d, "nested/thing.txt").cache,
            Some(CacheConfig { max_age: Some(333) })
        );
        assert_eq!(cfg(&mut ac, &d, "index.html").cache, None);
    }

    #[test]
    fn child_config_overrides_parent() {
        let mut files = HashMap::new();
        files.insert("", r#"[{"match": "*", "cache": {"max_age": 999}}]"#);
        files.insert("nested", r#"[{"match": "*", "cache": {"max_age": 111}}]"#);
        let d = make_assets_dir(files, &["index.html", "nested/thing.txt"]);
        let mut ac = load(&d);

        assert_eq!(
            cfg(&mut ac, &d, "nested/thing.txt").cache,
            Some(CacheConfig { max_age: Some(111) })
        );
        assert_eq!(
            cfg(&mut ac, &d, "index.html").cache,
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
        let mut ac = load(&d);

        let headers = cfg(&mut ac, &d, "index.html").headers.unwrap();
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
        let mut ac = load(&d);

        assert!(cfg(&mut ac, &d, "index.html").headers.is_none());
        assert!(cfg(&mut ac, &d, "app.js").headers.is_some());
    }

    #[test]
    fn ignore_flag_set() {
        let content = r#"[{"match": "*.secret", "ignore": true}]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &["data.secret", "index.html"]);
        let mut ac = load(&d);

        assert_eq!(cfg(&mut ac, &d, "data.secret").ignore, Some(true));
        assert_eq!(cfg(&mut ac, &d, "index.html").ignore, None);
    }

    #[test]
    fn allow_raw_access_default_is_true() {
        let mut files = HashMap::new();
        files.insert("", "[]");
        let d = make_assets_dir(files, &[]);
        let mut ac = load(&d);

        assert_eq!(cfg(&mut ac, &d, "index.html").allow_raw_access, Some(true));
    }

    #[test]
    fn allow_raw_access_can_be_overridden() {
        let content = r#"[{"match": "*", "allow_raw_access": false}]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &[]);
        let mut ac = load(&d);

        assert_eq!(cfg(&mut ac, &d, "index.html").allow_raw_access, Some(false));
    }

    #[test]
    fn encoding_override() {
        let content = r#"[{"match": "**/*.txt", "encodings": []}, {"match": "*.unknown", "encodings": ["gzip"]}]"#;
        let mut files = HashMap::new();
        files.insert("", content);
        let d = make_assets_dir(files, &[]);
        let mut ac = load(&d);

        assert_eq!(cfg(&mut ac, &d, "data.txt").encodings, Some(vec![]));
        assert_eq!(
            cfg(&mut ac, &d, "file.unknown").encodings,
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
        let mut ac =
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
        let mut ac = load(&d);

        assert_eq!(
            cfg(&mut ac, &d, "any.html").cache,
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
        let mut ac = load(&d);
        // Path whose parent was never loaded into the config map.
        let outside = d.path().join("../outside/file.txt");
        // canonicalize may fail for non-existent paths; just check fallback works:
        let result = ac.get_asset_config(&outside);
        assert_eq!(result, AssetConfig::default());
    }
}
