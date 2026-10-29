//! Parser for the `_preserve` file: asset keys a sync must not delete from the
//! canister when they are absent from `dist/`.
//!
//! One [`KeyPattern`](crate::glob::KeyPattern) per line, in the same glob syntax
//! as `_headers` paths. Blank lines and `#` comments are ignored. A preserved key
//! that *is* present locally syncs like any other asset; the patterns only decide
//! what happens to canister assets the project no longer ships — see
//! `docs/site-files.md`.

use crate::glob::{self, KeyPattern};
use crate::strip_comment;

pub const PRESERVE_FILENAME: &str = "_preserve";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub source: String,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "_preserve: line {}: {} (source: `{}`)",
            self.line, self.message, self.source
        )
    }
}

impl std::error::Error for ParseError {}

pub fn parse(content: &str) -> Result<Vec<KeyPattern>, ParseError> {
    let mut patterns = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let err = |message: String| ParseError {
            line: idx + 1,
            source: raw.to_string(),
            message,
        };
        if line.split_whitespace().count() > 1 {
            return Err(err("expected exactly one path pattern per line".into()));
        }
        patterns.push(glob::parse(line).map_err(err)?);
    }
    Ok(patterns)
}

/// Whether `key` matches any of `patterns`.
pub fn is_preserved(key: &str, patterns: &[KeyPattern]) -> bool {
    patterns.iter().any(|p| p.matches(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_pattern_per_line() {
        let patterns = parse("/.well-known/ii-alternative-origins\n/uploads/*\n").unwrap();
        assert_eq!(patterns.len(), 2);
        assert!(is_preserved(
            "/.well-known/ii-alternative-origins",
            &patterns
        ));
        assert!(is_preserved("/uploads/a/b.png", &patterns));
        assert!(!is_preserved("/index.html", &patterns));
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        let patterns = parse("# config owned by ops\n\n  /a.json  # trailing\n").unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].source(), "/a.json");
    }

    #[test]
    fn empty_file_preserves_nothing() {
        assert!(parse("").unwrap().is_empty());
        assert!(!is_preserved("/a", &[]));
    }

    #[test]
    fn rejects_relative_pattern_with_line_number() {
        let err = parse("/ok\nrelative.json\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.message.contains("absolute"), "got: {err}");
    }

    #[test]
    fn rejects_more_than_one_token() {
        let err = parse("/a /b\n").unwrap_err();
        assert_eq!(err.line, 1);
        assert!(err.message.contains("one path pattern"), "got: {err}");
    }

    #[test]
    fn rejects_double_star() {
        assert!(parse("/uploads/**\n").is_err());
    }
}
