//! Parser for `assets.toml`. v1 only recognises per-glob `content_type`
//! overrides — see [ASSETS-TOML.md](../../ASSETS-TOML.md) for the full design.
//!
//! Input arrives as `(name, content)` pairs through the plugin runtime's
//! `files:` channel ([plugin/wit/sync-plugin.wit](../../plugin/wit/sync-plugin.wit)).
//! We expect 0 or 1 entries; 2+ is rejected because the plugin has no merge
//! semantics for multiple config files.
//!
//! The standard filename is `assets.toml`, but the parser doesn't assert
//! that — the manifest's `files:` field is the authoritative declaration of
//! which file is the asset config.
//!
//! Errors include the source filename so users see which file is the
//! problem when the plugin runs under `icp-cli`.

use crate::glob::{self, KeyPattern};
use mime::Mime;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetConfig {
    blocks: Vec<AssetBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetBlock {
    pub pattern: KeyPattern,
    pub content_type: Option<Mime>,
}

impl AssetConfig {
    pub fn empty() -> Self {
        Self { blocks: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the first matching block's `content_type`, walking blocks in
    /// declaration order. Blocks without a `content_type` are skipped — they
    /// exist for future fields (`ignore`, `encodings`) that haven't shipped.
    pub fn content_type_for(&self, key: &str) -> Option<Mime> {
        for block in &self.blocks {
            if block.pattern.matches(key) {
                if let Some(mime) = &block.content_type {
                    return Some(mime.clone());
                }
            }
        }
        None
    }

    /// Build from the plugin runtime's `files:` slice. The slice carries
    /// `(name, content)` pairs read by the host.
    ///
    /// * 0 entries → empty config (no overrides).
    /// * 1 entry → parsed as the asset config.
    /// * 2+ entries → error (the plugin has no merge semantics).
    pub fn from_files(files: &[(String, String)]) -> Result<Self, String> {
        match files {
            [] => Ok(Self::empty()),
            [(name, content)] => parse(name, content),
            _ => Err(format!(
                "expected at most one file in `files:`, got {} — consolidate the asset config into a single file",
                files.len()
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    asset: Vec<RawBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBlock {
    #[serde(rename = "match")]
    match_: String,
    #[serde(default)]
    content_type: Option<String>,
}

fn parse(name: &str, content: &str) -> Result<AssetConfig, String> {
    let raw: RawConfig =
        toml::from_str(content).map_err(|e| format!("{name}: TOML parse error: {e}"))?;

    let mut blocks = Vec::with_capacity(raw.asset.len());
    for (idx, raw_block) in raw.asset.into_iter().enumerate() {
        let block_no = idx + 1;
        let pattern = glob::parse(&raw_block.match_)
            .map_err(|e| format!("{name}: [[asset]] #{block_no}: invalid `match`: {e}"))?;
        let content_type = raw_block
            .content_type
            .map(|s| {
                Mime::from_str(&s).map_err(|e| {
                    format!("{name}: [[asset]] #{block_no}: invalid `content_type` {s:?}: {e}")
                })
            })
            .transpose()?;
        blocks.push(AssetBlock {
            pattern,
            content_type,
        });
    }
    Ok(AssetConfig { blocks })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(content: &str) -> AssetConfig {
        parse("assets.toml", content).unwrap()
    }

    fn err(content: &str) -> String {
        parse("assets.toml", content).unwrap_err()
    }

    // ── happy paths ───────────────────────────────────────────────────────────

    #[test]
    fn empty_content_yields_empty_config() {
        let c = cfg("");
        assert!(c.is_empty());
    }

    #[test]
    fn parses_single_content_type_block() {
        let c = cfg(r#"
[[asset]]
match = "/*.md"
content_type = "text/markdown; charset=utf-8"
"#);
        assert_eq!(
            c.content_type_for("/foo.md").unwrap().to_string(),
            "text/markdown; charset=utf-8"
        );
        assert!(c.content_type_for("/foo.html").is_none());
    }

    #[test]
    fn parses_multiple_blocks_in_order() {
        let c = cfg(r#"
[[asset]]
match = "/legacy/oldstyle.md"
content_type = "text/plain"

[[asset]]
match = "/*.md"
content_type = "text/markdown; charset=utf-8"
"#);
        // Specific rule declared first wins.
        assert_eq!(
            c.content_type_for("/legacy/oldstyle.md")
                .unwrap()
                .to_string(),
            "text/plain"
        );
        assert_eq!(
            c.content_type_for("/other.md").unwrap().to_string(),
            "text/markdown; charset=utf-8"
        );
    }

    #[test]
    fn block_without_content_type_is_no_op_for_v1() {
        // A bare `[[asset]] match = "..."` block (no v1 fields) parses
        // and contributes nothing to content-type resolution. Future fields
        // (ignore, encodings) will hang off the same shape.
        let c = cfg(r#"
[[asset]]
match = "/*"
"#);
        assert!(c.content_type_for("/anything").is_none());
    }

    #[test]
    fn from_files_handles_zero_one_and_many() {
        // Zero entries — empty.
        let c = AssetConfig::from_files(&[]).unwrap();
        assert!(c.is_empty());

        // One entry — parsed.
        let files = vec![(
            "assets.toml".into(),
            r#"
[[asset]]
match = "/*.md"
content_type = "text/markdown"
"#
            .into(),
        )];
        let c = AssetConfig::from_files(&files).unwrap();
        assert_eq!(
            c.content_type_for("/x.md").unwrap().to_string(),
            "text/markdown"
        );

        // Two entries — error.
        let files = vec![("a.toml".into(), "".into()), ("b.toml".into(), "".into())];
        let e = AssetConfig::from_files(&files).unwrap_err();
        assert!(e.contains("at most one"), "{e}");
    }

    #[test]
    fn filename_is_not_asserted() {
        // Manifest may declare any filename; the plugin trusts the host.
        let files = vec![(
            "config/custom.toml".into(),
            r#"
[[asset]]
match = "/x"
content_type = "text/plain"
"#
            .into(),
        )];
        let c = AssetConfig::from_files(&files).unwrap();
        assert_eq!(c.content_type_for("/x").unwrap().to_string(), "text/plain");
    }

    // ── reject cases ──────────────────────────────────────────────────────────

    #[test]
    fn rejects_unknown_top_level_field() {
        let e = err(r#"
unknown_key = "x"

[[asset]]
match = "/*"
"#);
        assert!(e.contains("TOML parse error"), "{e}");
        assert!(e.contains("unknown_key") || e.contains("unknown"), "{e}");
    }

    #[test]
    fn rejects_unknown_per_block_field() {
        let e = err(r#"
[[asset]]
match = "/*"
contetn_type = "text/plain"
"#);
        assert!(e.contains("TOML parse error"), "{e}");
        assert!(e.contains("contetn_type") || e.contains("unknown"), "{e}");
    }

    #[test]
    fn rejects_missing_match_field() {
        let e = err(r#"
[[asset]]
content_type = "text/plain"
"#);
        assert!(e.contains("TOML parse error"), "{e}");
    }

    #[test]
    fn rejects_invalid_pattern() {
        let e = err(r#"
[[asset]]
match = "no-leading-slash"
content_type = "text/plain"
"#);
        assert!(e.contains("invalid `match`"), "{e}");
        assert!(e.contains("absolute path"), "{e}");
    }

    #[test]
    fn rejects_double_star_pattern() {
        let e = err(r#"
[[asset]]
match = "/foo/**/bar"
content_type = "text/plain"
"#);
        assert!(e.contains("invalid `match`"), "{e}");
        assert!(e.contains("'**'"), "{e}");
    }

    #[test]
    fn rejects_malformed_mime() {
        let e = err(r#"
[[asset]]
match = "/*.md"
content_type = "not a mime type"
"#);
        assert!(e.contains("invalid `content_type`"), "{e}");
    }

    #[test]
    fn rejects_empty_mime() {
        let e = err(r#"
[[asset]]
match = "/*.md"
content_type = ""
"#);
        assert!(e.contains("invalid `content_type`"), "{e}");
    }

    #[test]
    fn error_names_the_block_number() {
        // Both blocks are syntactically fine; the second has a bad pattern.
        let e = err(r#"
[[asset]]
match = "/*.md"
content_type = "text/markdown"

[[asset]]
match = "/foo/**/bar"
content_type = "text/plain"
"#);
        assert!(e.contains("#2"), "{e}");
    }
}
