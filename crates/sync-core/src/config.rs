//! `.ic-assets.json5` (and `.ic-assets.json`) parsing, ported from `ic-asset`'s
//! `asset/config.rs`.
//!
//! Config files nest: a directory's `.ic-assets.json5` applies to that directory
//! and all descendants, and child configs merge on top of parent ones. Each rule
//! has a glob `match` (resolved relative to the config file's directory) plus
//! optional `cache`, `headers`, `ignore`, `enable_aliasing`, `allow_raw_access`,
//! `encodings`, and `security_policy` fields.
//!
//! Differences from the upstream `ic-asset` port:
//! - errors are plain `String`s (this crate's convention),
//! - the `derivative` proc-macro is replaced with hand-written impls,
//! - the json5 pretty-printer / serialize plumbing is dropped; unused-rule
//!   warnings print the glob pattern only.

use crate::content::Encoder;
use crate::security_policy::SecurityPolicy;
use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const ASSETS_CONFIG_FILENAME_JSON: &str = ".ic-assets.json";
pub const ASSETS_CONFIG_FILENAME_JSON5: &str = ".ic-assets.json5";

pub type HeadersConfig = BTreeMap<String, String>;

/// The resolved configuration assigned to a single asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetConfig {
    pub cache: Option<CacheConfig>,
    pub headers: Option<HeadersConfig>,
    pub ignore: Option<bool>,
    pub enable_aliasing: Option<bool>,
    pub allow_raw_access: Option<bool>,
    pub encodings: Option<Vec<Encoder>>,
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
            // Matches ic-asset: raw access is allowed unless a rule turns it off.
            allow_raw_access: Some(true),
            encodings: None,
            security_policy: None,
            disable_security_policy_warning: None,
        }
    }
}

impl AssetConfig {
    /// Merges the custom `headers` with the headers implied by `security_policy`.
    /// Custom headers win on case-insensitive name collisions.
    pub fn combined_headers(&self) -> Option<HeadersConfig> {
        match (self.headers.as_ref(), self.security_policy) {
            (None, None) => None,
            (None, Some(policy)) => Some(policy.to_headers()),
            (Some(custom_headers), None) => Some(custom_headers.clone()),
            (Some(custom_headers), Some(policy)) => {
                let mut headers = custom_headers.clone();
                let custom_header_names: HashSet<String> =
                    HashSet::from_iter(custom_headers.keys().map(|a| a.to_lowercase()));
                for (policy_header_name, policy_header_value) in policy.to_headers() {
                    if !custom_header_names.contains(&policy_header_name.to_lowercase()) {
                        headers.insert(policy_header_name, policy_header_value);
                    }
                }
                Some(headers)
            }
        }
    }

    pub fn warn_about_standard_security_policy(&self) -> bool {
        let warning_disabled = self.disable_security_policy_warning == Some(true);
        let standard_policy = self.security_policy == Some(SecurityPolicy::Standard);
        standard_policy && !warning_disabled
    }

    pub fn warn_about_no_security_policy(&self) -> bool {
        let warning_disabled = self.disable_security_policy_warning == Some(true);
        let no_policy = self.security_policy.is_none();
        no_policy && !warning_disabled
    }

    /// `"hardened"` expects custom headers to be present; this cannot be silenced.
    pub fn warn_about_missing_hardening_headers(&self) -> bool {
        let is_hardened = self.security_policy == Some(SecurityPolicy::Hardened);
        let has_headers = self
            .headers
            .as_ref()
            .map(|headers| !headers.is_empty())
            .unwrap_or_default();
        is_hardened && !has_headers
    }

    fn merge(mut self, other: &AssetConfigRule) -> Self {
        if let Some(c) = &other.cache {
            self.cache = Some(c.to_owned());
        }
        match (self.headers.as_mut(), &other.headers) {
            (Some(sh), Maybe::Value(oh)) => sh.extend(oh.to_owned()),
            (None, Maybe::Value(oh)) => self.headers = Some(oh.to_owned()),
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

#[derive(Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheConfig {
    pub max_age: Option<u64>,
}

/// Tri-state for the `headers` field: absent (don't touch), `null` (clear), or a
/// map of header values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum Maybe<T> {
    Null,
    #[default]
    Absent,
    Value(T),
}

/// A single rule from a `.ic-assets.json5` file, with its glob resolved against
/// the config file's directory.
#[derive(Clone)]
struct AssetConfigRule {
    r#match: GlobMatcher,
    cache: Option<CacheConfig>,
    headers: Maybe<HeadersConfig>,
    ignore: Option<bool>,
    enable_aliasing: Option<bool>,
    used: bool,
    allow_raw_access: Option<bool>,
    encodings: Option<Vec<Encoder>>,
    security_policy: Option<SecurityPolicy>,
    disable_security_policy_warning: Option<bool>,
}

impl AssetConfigRule {
    fn applies(&self, canonical_path: &Path) -> bool {
        self.r#match.is_match(canonical_path)
    }

    fn from_interim(interim: InterimAssetConfigRule, dir: &Path) -> Result<Self, String> {
        let InterimAssetConfigRule {
            r#match,
            cache,
            headers,
            ignore,
            enable_aliasing,
            allow_raw_access,
            encodings,
            security_policy,
            disable_security_policy_warning,
        } = interim;
        let pattern = r#match;
        let glob = dir.join(&pattern);
        let glob = glob
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 glob pattern '{pattern}' in {}", dir.display()))?;
        let matcher = Glob::new(glob)
            .map_err(|e| format!("invalid glob pattern '{pattern}': {e}"))?
            .compile_matcher();
        Ok(Self {
            r#match: matcher,
            cache,
            headers,
            ignore,
            enable_aliasing,
            used: false,
            allow_raw_access,
            encodings,
            security_policy,
            disable_security_policy_warning,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterimAssetConfigRule {
    r#match: String,
    cache: Option<CacheConfig>,
    #[serde(default, deserialize_with = "headers_deserialize")]
    headers: Maybe<HeadersConfig>,
    ignore: Option<bool>,
    enable_aliasing: Option<bool>,
    allow_raw_access: Option<bool>,
    encodings: Option<Vec<Encoder>>,
    security_policy: Option<SecurityPolicy>,
    disable_security_policy_warning: Option<bool>,
}

fn headers_deserialize<'de, D>(deserializer: D) -> Result<Maybe<HeadersConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    match Value::deserialize(deserializer)? {
        Value::Object(v) => Ok(Maybe::Value(
            v.into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        match v {
                            Value::Bool(b) => b.to_string(),
                            Value::Number(n) => n.to_string(),
                            Value::String(s) => s,
                            Value::Null => String::new(),
                            v => {
                                return Err(D::Error::custom(format!(
                                    "headers must be strings, numbers, or bools (was {v:?})"
                                )))
                            }
                        },
                    ))
                })
                .collect::<Result<BTreeMap<String, String>, D::Error>>()?,
        )),
        Value::Null => Ok(Maybe::Null),
        _ => Err(D::Error::custom(
            "wrong data format for field `headers` (only map or null are allowed)",
        )),
    }
}

type ConfigNode = Arc<Mutex<AssetConfigTreeNode>>;
type ConfigMap = HashMap<PathBuf, ConfigNode>;

/// Aggregates `.ic-assets.json5` files nested in a directory tree.
#[derive(Debug)]
pub struct AssetSourceDirectoryConfiguration {
    config_map: ConfigMap,
}

#[derive(Default)]
struct AssetConfigTreeNode {
    parent: Option<ConfigNode>,
    rules: Vec<AssetConfigRule>,
    origin: PathBuf,
}

impl std::fmt::Debug for AssetConfigTreeNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssetConfigTreeNode")
            .field("origin", &self.origin)
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl AssetSourceDirectoryConfiguration {
    /// Builds the config tree for an (absolute) assets directory.
    pub fn load(root_dir: &Path) -> Result<Self, String> {
        if !root_dir.has_root() {
            return Err(format!(
                "asset config root dir must be absolute: {}",
                root_dir.display()
            ));
        }
        let mut config_map = HashMap::new();
        AssetConfigTreeNode::load(None, root_dir, &mut config_map)?;
        Ok(Self { config_map })
    }

    /// Resolves the configuration for an asset at `canonical_path`.
    pub fn get_asset_config(&mut self, canonical_path: &Path) -> Result<AssetConfig, String> {
        let parent_dir = canonical_path
            .parent()
            .ok_or_else(|| format!("no parent dir for {}", canonical_path.display()))?;
        Ok(self
            .config_map
            .get(parent_dir)
            .ok_or_else(|| format!("no asset config found for {}", parent_dir.display()))?
            .lock()
            .unwrap()
            .get_config(canonical_path))
    }

    /// Returns the rules that never matched any asset, grouped by config-file
    /// directory. Used to warn about typo'd globs.
    pub fn get_unused_configs(&self) -> HashMap<PathBuf, Vec<String>> {
        let mut hm: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for node in self.config_map.values() {
            let node = node.lock().unwrap();
            for rule in &node.rules {
                if !rule.used {
                    hm.entry(node.origin.clone())
                        .or_default()
                        .push(rule.r#match.glob().to_string());
                }
            }
        }
        for (_, globs) in hm.iter_mut() {
            globs.sort();
            globs.dedup();
        }
        hm
    }
}

impl AssetConfigTreeNode {
    fn load(parent: Option<ConfigNode>, dir: &Path, configs: &mut ConfigMap) -> Result<(), String> {
        let json = dir.join(ASSETS_CONFIG_FILENAME_JSON);
        let json5 = dir.join(ASSETS_CONFIG_FILENAME_JSON5);
        let config_path = match (json.exists(), json5.exists()) {
            (true, true) => {
                return Err(format!(
                    "both {ASSETS_CONFIG_FILENAME_JSON} and {ASSETS_CONFIG_FILENAME_JSON5} present in {}",
                    dir.display()
                ))
            }
            (true, false) => Some(json),
            (false, true) => Some(json5),
            (false, false) => None,
        };

        let mut rules = vec![];
        if let Some(config_path) = &config_path {
            let content = std::fs::read_to_string(config_path)
                .map_err(|e| format!("read {}: {e}", config_path.display()))?;
            let interim_rules: Vec<InterimAssetConfigRule> = json5::from_str(&content)
                .map_err(|e| format!("malformed {}: {e}", config_path.display()))?;
            for interim_rule in interim_rules {
                rules.push(AssetConfigRule::from_interim(interim_rule, dir)?);
            }
        }

        // An empty node just forwards to its parent (matches ic-asset).
        let node_ref = match parent {
            Some(p) if rules.is_empty() => p,
            _ => Arc::new(Mutex::new(Self {
                parent,
                rules,
                origin: dir.to_path_buf(),
            })),
        };

        configs.insert(dir.to_path_buf(), node_ref.clone());
        for entry in std::fs::read_dir(dir)
            .map_err(|e| format!("read_dir {}: {e}", dir.display()))?
            .filter_map(|x| x.ok())
            .filter(|x| x.file_type().is_ok_and(|ft| ft.is_dir()))
        {
            Self::load(Some(node_ref.clone()), &entry.path(), configs)?;
        }
        Ok(())
    }

    /// Resolves config for `canonical_path`, marking matched rules as used.
    fn get_config(&mut self, canonical_path: &Path) -> AssetConfig {
        let base_config = match &self.parent {
            Some(parent) => parent.clone().lock().unwrap().get_config(canonical_path),
            None => AssetConfig::default(),
        };
        self.rules
            .iter_mut()
            .filter(|rule| rule.applies(canonical_path))
            .fold(base_config, |acc, x| {
                x.used = true;
                acc.merge(x)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn config_for(root: &TempDir, rel_file: &str) -> AssetConfig {
        let root_abs = root.path().canonicalize().unwrap();
        let mut cfg = AssetSourceDirectoryConfiguration::load(&root_abs).unwrap();
        cfg.get_asset_config(&root_abs.join(rel_file)).unwrap()
    }

    #[test]
    fn default_allows_raw_access() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "index.html", "x");
        let cfg = config_for(&dir, "index.html");
        assert_eq!(cfg.allow_raw_access, Some(true));
        assert!(cfg.headers.is_none());
    }

    #[test]
    fn headers_and_cache_apply_by_glob() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".ic-assets.json5",
            r#"[{ "match": "*.html", "cache": { "max_age": 42 }, "headers": { "X-Foo": "bar" } }]"#,
        );
        write(dir.path(), "index.html", "x");
        write(dir.path(), "app.js", "x");
        let html = config_for(&dir, "index.html");
        assert_eq!(html.cache, Some(CacheConfig { max_age: Some(42) }));
        assert_eq!(
            html.headers.unwrap().get("X-Foo").map(String::as_str),
            Some("bar")
        );
        let js = config_for(&dir, "app.js");
        assert!(js.cache.is_none());
        assert!(js.headers.is_none());
    }

    #[test]
    fn nested_config_merges_over_parent() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".ic-assets.json5",
            r#"[{ "match": "**/*", "headers": { "A": "1" } }]"#,
        );
        write(
            dir.path(),
            "sub/.ic-assets.json5",
            r#"[{ "match": "*", "headers": { "B": "2" } }]"#,
        );
        write(dir.path(), "sub/page.html", "x");
        let cfg = config_for(&dir, "sub/page.html");
        let headers = cfg.headers.unwrap();
        assert_eq!(headers.get("A").map(String::as_str), Some("1"));
        assert_eq!(headers.get("B").map(String::as_str), Some("2"));
    }

    #[test]
    fn null_headers_clears() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".ic-assets.json5",
            r#"[
                { "match": "*", "headers": { "A": "1" } },
                { "match": "page.html", "headers": null }
            ]"#,
        );
        write(dir.path(), "page.html", "x");
        let cfg = config_for(&dir, "page.html");
        assert!(cfg.headers.is_none());
    }

    #[test]
    fn security_policy_parsed_and_combined() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".ic-assets.json5",
            r#"[{ "match": "**/*", "security_policy": "standard" }]"#,
        );
        write(dir.path(), "index.html", "x");
        let cfg = config_for(&dir, "index.html");
        assert_eq!(cfg.security_policy, Some(SecurityPolicy::Standard));
        let combined = cfg.combined_headers().unwrap();
        assert!(combined.contains_key("Content-Security-Policy"));
    }

    #[test]
    fn encodings_override_parsed() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".ic-assets.json5",
            r#"[{ "match": "*.wasm", "encodings": ["identity", "gzip"] }]"#,
        );
        write(dir.path(), "mod.wasm", "x");
        let cfg = config_for(&dir, "mod.wasm");
        assert_eq!(cfg.encodings, Some(vec![Encoder::Identity, Encoder::Gzip]));
    }

    #[test]
    fn unused_rule_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".ic-assets.json5",
            r#"[{ "match": "nonexistent.css", "headers": { "A": "1" } }]"#,
        );
        write(dir.path(), "index.html", "x");
        let root_abs = dir.path().canonicalize().unwrap();
        let mut cfg = AssetSourceDirectoryConfiguration::load(&root_abs).unwrap();
        let _ = cfg.get_asset_config(&root_abs.join("index.html")).unwrap();
        let unused = cfg.get_unused_configs();
        assert!(!unused.is_empty());
    }

    #[test]
    fn both_config_files_present_is_error() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".ic-assets.json", "[]");
        write(dir.path(), ".ic-assets.json5", "[]");
        let root_abs = dir.path().canonicalize().unwrap();
        assert!(AssetSourceDirectoryConfiguration::load(&root_abs).is_err());
    }
}
