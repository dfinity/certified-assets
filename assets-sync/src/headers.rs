//! Strict block parser for Netlify-style `_headers` files.
//!
//! Each block is one non-indented `<pattern>` line followed by one or more
//! indented `Header-Name: value` lines. Blank lines and `#` comments close
//! blocks. Errors carry a 1-based line number so the plugin can point users
//! at the offending entry without a canister round-trip.
//!
//! See the "File format" section of HEADERS.md for the full reject list.

use crate::canister::RulePattern;
use http::{HeaderName, HeaderValue};

pub const HEADERS_FILENAME: &str = "_headers";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRule {
    pub pattern: RulePattern,
    /// Headers in declaration order. Multiple entries for the same name are
    /// allowed (e.g. `Set-Cookie`); resolver semantics in `sync.rs`.
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "_headers: line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses an entire `_headers` file into a list of [`HeaderRule`]s. Rules are
/// returned in declaration order — the resolver walks them in order, so order
/// is semantic. The first malformed line aborts parsing; we want the user to
/// fix issues one at a time rather than wade through cascading errors.
pub fn parse(content: &str) -> Result<Vec<HeaderRule>, ParseError> {
    let mut rules = Vec::new();
    // Open block: (line_no of the path line, pattern, headers accumulated so far).
    let mut current: Option<(usize, RulePattern, Vec<(String, String)>)> = None;

    for (i, raw) in content.lines().enumerate() {
        let line_no = i + 1;

        // Truly blank lines (only whitespace, no characters) close blocks.
        // Comment-only lines are skipped without closing.
        if raw.trim().is_empty() {
            if let Some(block) = current.take() {
                rules.push(finalize_block(block)?);
            }
            continue;
        }
        let stripped = strip_comment(raw);
        if stripped.trim().is_empty() {
            // Pure comment line — skip without closing the current block.
            continue;
        }

        let is_indented = stripped
            .chars()
            .next()
            .is_some_and(|c| c == ' ' || c == '\t');

        if !is_indented {
            // Path line. If a block is open, close it (must have headers).
            if let Some(block) = current.take() {
                rules.push(finalize_block(block)?);
            }
            let token = stripped.trim();
            let pattern = parse_pattern(token).map_err(|message| ParseError {
                line: line_no,
                message,
            })?;
            current = Some((line_no, pattern, Vec::new()));
            continue;
        }

        // Indented line: must be a `Header-Name: value` inside an open block.
        let Some((_, _, headers)) = current.as_mut() else {
            return Err(ParseError {
                line: line_no,
                message: "indented header line outside a path block".to_string(),
            });
        };
        let (name, value) = parse_header(stripped).map_err(|message| ParseError {
            line: line_no,
            message,
        })?;
        headers.push((name, value));
    }

    if let Some(block) = current.take() {
        rules.push(finalize_block(block)?);
    }
    Ok(rules)
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

fn finalize_block(
    (line_no, pattern, headers): (usize, RulePattern, Vec<(String, String)>),
) -> Result<HeaderRule, ParseError> {
    if headers.is_empty() {
        return Err(ParseError {
            line: line_no,
            message: "path block has no header lines under it".to_string(),
        });
    }
    Ok(HeaderRule { pattern, headers })
}

fn parse_pattern(token: &str) -> Result<RulePattern, String> {
    if !token.starts_with('/') {
        return Err(format!(
            "'{token}' must be an absolute path (start with '/')"
        ));
    }
    if token.contains(':') {
        return Err(format!(
            "':' placeholders in pattern ('{token}') are not supported"
        ));
    }
    if let Some(prefix) = token.strip_suffix("/*") {
        // Subtree. `/*` alone matches the entire site (subtree at `/`).
        if prefix.contains('*') {
            return Err(format!(
                "wildcards in pattern ('{token}') are only supported as a trailing '/*'"
            ));
        }
        let subtree = if prefix.is_empty() {
            "/".to_string()
        } else {
            format!("{prefix}/")
        };
        return Ok(RulePattern::Subtree(subtree));
    }
    if token.contains('*') {
        return Err(format!(
            "wildcards in pattern ('{token}') are only supported as a trailing '/*'"
        ));
    }
    Ok(RulePattern::Exact(token.to_string()))
}

fn parse_header(stripped: &str) -> Result<(String, String), String> {
    let trimmed = stripped.trim();
    let Some(colon_idx) = trimmed.find(':') else {
        return Err(format!(
            "header line '{trimmed}' is missing a ':' separator"
        ));
    };
    let name = trimmed[..colon_idx].trim();
    let value = trimmed[colon_idx + 1..].trim();
    if name.is_empty() {
        return Err("header name is empty".to_string());
    }
    if name.eq_ignore_ascii_case("content-type") {
        return Err(
            "'Content-Type' is derived from the asset's media type and cannot be overridden"
                .to_string(),
        );
    }
    if value.contains(":splat") || value.contains(":placeholder") {
        return Err(format!(
            "':splat' / ':placeholder' substitution in header value ('{value}') \
             is a known-deferred feature"
        ));
    }
    // `http` rejects CR/LF and other invalid chars — guarantees no header injection.
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|e| format!("invalid header name '{name}': {e}"))?;
    HeaderValue::from_str(value).map_err(|e| format!("invalid header value '{value}': {e}"))?;
    Ok((name.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(content: &str) -> ParseError {
        parse(content).unwrap_err()
    }

    // ── happy paths ───────────────────────────────────────────────────────────

    #[test]
    fn empty_input_yields_no_rules() {
        assert!(parse("").unwrap().is_empty());
        assert!(parse("\n\n   \n").unwrap().is_empty());
    }

    #[test]
    fn single_rule_with_single_header() {
        let rules = parse("/about\n  X-Frame-Options: DENY\n").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, RulePattern::Exact("/about".into()));
        assert_eq!(
            rules[0].headers,
            vec![("X-Frame-Options".into(), "DENY".into())]
        );
    }

    #[test]
    fn tab_indented_headers_are_accepted() {
        let rules = parse("/about\n\tX-Frame-Options: DENY\n").unwrap();
        assert_eq!(
            rules[0].headers,
            vec![("X-Frame-Options".into(), "DENY".into())]
        );
    }

    #[test]
    fn multiple_headers_in_one_block_preserve_order() {
        let input = "\
/api
  Cache-Control: no-store
  X-Frame-Options: DENY
  Set-Cookie: a=1
  Set-Cookie: b=2
";
        let rules = parse(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, RulePattern::Exact("/api".into()));
        assert_eq!(
            rules[0].headers,
            vec![
                ("Cache-Control".into(), "no-store".into()),
                ("X-Frame-Options".into(), "DENY".into()),
                ("Set-Cookie".into(), "a=1".into()),
                ("Set-Cookie".into(), "b=2".into()),
            ]
        );
    }

    #[test]
    fn multiple_blocks_preserve_order() {
        let input = "\
/_astro/*
  Cache-Control: immutable

/*
  X-Frame-Options: DENY

/api
  Cache-Control: no-store
";
        let rules = parse(input).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].pattern, RulePattern::Subtree("/_astro/".into()));
        assert_eq!(rules[1].pattern, RulePattern::Subtree("/".into()));
        assert_eq!(rules[2].pattern, RulePattern::Exact("/api".into()));
    }

    #[test]
    fn blocks_without_blank_separator_still_parse() {
        // A new non-indented path line closes the previous block.
        let input = "\
/a
  X-A: 1
/b
  X-B: 2
";
        let rules = parse(input).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pattern, RulePattern::Exact("/a".into()));
        assert_eq!(rules[0].headers, vec![("X-A".into(), "1".into())]);
        assert_eq!(rules[1].pattern, RulePattern::Exact("/b".into()));
        assert_eq!(rules[1].headers, vec![("X-B".into(), "2".into())]);
    }

    #[test]
    fn comments_and_blanks_are_ignored() {
        let input = "\
# top-level comment
/about
  # comment inside block
  X-Frame-Options: DENY
# trailing comment
";
        let rules = parse(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].headers,
            vec![("X-Frame-Options".into(), "DENY".into())]
        );
    }

    #[test]
    fn inline_comment_after_header_is_stripped() {
        let rules = parse("/about\n  X-Frame-Options: DENY # inline\n").unwrap();
        assert_eq!(
            rules[0].headers,
            vec![("X-Frame-Options".into(), "DENY".into())]
        );
    }

    #[test]
    fn trailing_star_lowers_to_subtree() {
        let rules = parse("/blog/*\n  Cache-Control: public\n").unwrap();
        assert_eq!(rules[0].pattern, RulePattern::Subtree("/blog/".into()));
    }

    #[test]
    fn root_star_lowers_to_root_subtree() {
        let rules = parse("/*\n  X-Frame-Options: DENY\n").unwrap();
        assert_eq!(rules[0].pattern, RulePattern::Subtree("/".into()));
    }

    #[test]
    fn header_value_with_internal_colon_is_preserved() {
        // Only the first colon separates name from value.
        let rules =
            parse("/api\n  Content-Security-Policy: default-src 'self'; img-src https:\n").unwrap();
        assert_eq!(
            rules[0].headers,
            vec![(
                "Content-Security-Policy".into(),
                "default-src 'self'; img-src https:".into()
            )]
        );
    }

    // ── reject cases ──────────────────────────────────────────────────────────

    #[test]
    fn rejects_indented_line_at_top_of_file() {
        let e = err("  X-Frame-Options: DENY\n");
        assert_eq!(e.line, 1);
        assert!(e.message.contains("outside a path block"), "{}", e.message);
    }

    #[test]
    fn rejects_indented_line_after_blank_boundary() {
        let input = "\
/about
  X-A: 1

  X-B: 2
";
        let e = err(input);
        assert_eq!(e.line, 4);
        assert!(e.message.contains("outside a path block"), "{}", e.message);
    }

    #[test]
    fn rejects_path_block_with_no_headers() {
        let input = "\
/lonely

/api
  Cache-Control: no-store
";
        let e = err(input);
        assert_eq!(e.line, 1);
        assert!(e.message.contains("no header lines"), "{}", e.message);
    }

    #[test]
    fn rejects_relative_pattern() {
        let e = err("about\n  X-Frame-Options: DENY\n");
        assert!(e.message.contains("absolute path"), "{}", e.message);
    }

    #[test]
    fn rejects_mid_path_wildcard() {
        let e = err("/foo/*/bar\n  X-Frame-Options: DENY\n");
        assert!(e.message.contains("trailing '/*'"), "{}", e.message);
    }

    #[test]
    fn rejects_placeholder_in_pattern() {
        let e = err("/blog/:slug\n  X-Frame-Options: DENY\n");
        assert!(e.message.contains("placeholders"), "{}", e.message);
    }

    #[test]
    fn rejects_content_type_header() {
        let e = err("/about\n  Content-Type: text/plain\n");
        assert!(e.message.contains("Content-Type"), "{}", e.message);
    }

    #[test]
    fn rejects_content_type_case_insensitive() {
        let e = err("/about\n  content-type: text/plain\n");
        assert!(e.message.contains("Content-Type"), "{}", e.message);
    }

    #[test]
    fn rejects_missing_colon() {
        let e = err("/about\n  X-Frame-Options DENY\n");
        assert!(e.message.contains("missing a ':'"), "{}", e.message);
    }

    #[test]
    fn rejects_blank_header_name() {
        let e = err("/about\n  : DENY\n");
        assert!(e.message.contains("empty"), "{}", e.message);
    }

    #[test]
    fn rejects_invalid_header_name_chars() {
        // Spaces in header name are invalid per RFC 7230.
        let e = err("/about\n  X Frame Options: DENY\n");
        assert!(e.message.contains("invalid header name"), "{}", e.message);
    }

    #[test]
    fn rejects_splat_in_value() {
        let e = err("/about\n  X-Custom: :splat\n");
        assert!(e.message.contains(":splat"), "{}", e.message);
    }

    #[test]
    fn rejects_placeholder_in_value() {
        let e = err("/about\n  X-Custom: :placeholder\n");
        assert!(e.message.contains(":placeholder"), "{}", e.message);
    }

    #[test]
    fn error_reports_line_number() {
        let input = "\
# comment
/good
  X-Good: 1

/bad
  : empty name
";
        let e = err(input);
        assert_eq!(e.line, 6);
    }

    #[test]
    fn unterminated_block_at_eof_is_finalized() {
        // The last block needs no trailing blank line.
        let rules = parse("/about\n  X-Frame-Options: DENY").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].headers,
            vec![("X-Frame-Options".into(), "DENY".into())]
        );
    }

    #[test]
    fn rejects_unterminated_path_block_with_no_headers() {
        let e = err("/about\n");
        assert!(e.message.contains("no header lines"), "{}", e.message);
    }
}
