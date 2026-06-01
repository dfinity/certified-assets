//! Strict line parser for Netlify-style `_redirects` files.
//!
//! Each non-empty, non-comment line is `<from>  <to>  <status>`. Whitespace is
//! permissive; semantics are strict — see the "File format" section of the
//! design plan for the full reject list. Errors carry a line number so the
//! plugin can point users at the offending entry without a canister round-trip.

use crate::canister::{RedirectRule, RulePattern};
use crate::strip_comment;
use http::StatusCode;
use url::Url;

pub const REDIRECTS_FILENAME: &str = "_redirects";

const SUPPORTED_STATUSES: &[u16] = &[200, 301, 302, 307, 308, 404, 410];

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
            "_redirects: line {}: {} (source: `{}`)",
            self.line, self.message, self.source
        )
    }
}

impl std::error::Error for ParseError {}

/// Parses an entire `_redirects` file into the candid `RedirectRule` shape.
/// The first malformed line aborts parsing — we want the user to fix issues
/// one at a time rather than wade through cascading errors.
pub fn parse(content: &str) -> Result<Vec<RedirectRule>, ParseError> {
    let mut rules = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line_no = i + 1;
        let body = strip_comment(raw).trim();
        if body.is_empty() {
            continue;
        }
        let rule = parse_line(body).map_err(|message| ParseError {
            line: line_no,
            source: raw.trim_end().to_string(),
            message,
        })?;
        rules.push(rule);
    }
    Ok(rules)
}

fn parse_line(body: &str) -> Result<RedirectRule, String> {
    let tokens: Vec<&str> = body.split_whitespace().collect();
    match tokens.len() {
        3 => {}
        n if n < 3 => {
            return Err(format!(
                "expected '<from> <to> <status>' (3 fields), got {n}"
            ))
        }
        n => {
            return Err(format!(
                "expected '<from> <to> <status>' (3 fields), got {n}; \
                 extra fields are not supported (no headers, conditions, or query-string match)"
            ))
        }
    }
    let from_tok = tokens[0];
    let to_tok = tokens[1];
    let status_tok = tokens[2];

    let status = parse_status(status_tok)?;
    let from = parse_from(from_tok)?;
    parse_to(to_tok, status)?;

    Ok(RedirectRule {
        from,
        to: to_tok.to_string(),
        status: status.as_u16(),
        headers: None,
    })
}

fn parse_status(token: &str) -> Result<StatusCode, String> {
    if token.ends_with('!') {
        return Err(format!(
            "Netlify '!' force suffix on status ('{token}') is not supported; \
             files win over rules at the same path — remove the conflicting asset instead"
        ));
    }
    let code: u16 = token
        .parse()
        .map_err(|_| format!("status '{token}' is not an integer"))?;
    if !SUPPORTED_STATUSES.contains(&code) {
        return Err(format!(
            "status {code} is not one of {{200, 301, 302, 307, 308, 404, 410}}"
        ));
    }
    StatusCode::from_u16(code).map_err(|e| format!("invalid status {code}: {e}"))
}

fn parse_from(token: &str) -> Result<RulePattern, String> {
    if !token.starts_with('/') {
        return Err(format!(
            "'from' ('{token}') must be an absolute path (start with '/')"
        ));
    }
    if token.contains(':') {
        return Err(format!(
            "':' placeholders in 'from' ('{token}') are not supported"
        ));
    }
    if let Some(prefix) = token.strip_suffix("/*") {
        // Subtree. `/*` alone matches the entire site (subtree at `/`).
        if prefix.contains('*') {
            return Err(format!(
                "wildcards in 'from' ('{token}') are only supported as a trailing '/*'"
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
            "wildcards in 'from' ('{token}') are only supported as a trailing '/*'"
        ));
    }
    Ok(RulePattern::Exact(token.to_string()))
}

fn parse_to(token: &str, status: StatusCode) -> Result<(), String> {
    if token.contains(":splat") || token.contains(":placeholder") {
        return Err(format!(
            "':splat' / ':placeholder' substitution in 'to' ('{token}') \
             is a known-deferred feature; see the plan's tier-3 follow-up"
        ));
    }
    if status.is_redirection() {
        // 3xx: absolute path or fully-qualified URL.
        if token.starts_with('/') {
            return Ok(());
        }
        Url::parse(token).map(|_| ()).map_err(|_| {
            format!(
                "'to' ('{token}') for a {} rule must be an absolute path or fully-qualified URL",
                status.as_u16()
            )
        })
    } else {
        // 200 / 4xx: absolute asset path.
        if !token.starts_with('/') {
            return Err(format!(
                "'to' ('{token}') for a status-{} rule must be an absolute asset path",
                status.as_u16()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(line: &str) -> Result<RedirectRule, ParseError> {
        let mut rules = parse(line)?;
        assert_eq!(rules.len(), 1, "expected exactly one rule from '{line}'");
        Ok(rules.pop().unwrap())
    }

    fn err(line: &str) -> ParseError {
        parse(line).unwrap_err()
    }

    // ── happy paths ───────────────────────────────────────────────────────────

    #[test]
    fn empty_input_yields_no_rules() {
        assert!(parse("").unwrap().is_empty());
        assert!(parse("\n\n   \n").unwrap().is_empty());
    }

    #[test]
    fn comments_and_blanks_are_ignored() {
        let input = "\n# leading comment\n\n   # indented comment\n/from /to 301\n\n# trailing\n";
        let rules = parse(input).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].status, 301);
    }

    #[test]
    fn comment_after_rule_is_stripped() {
        let r = parse_one("/old /new 301 # inline comment").unwrap();
        assert_eq!(r.from, RulePattern::Exact("/old".into()));
        assert_eq!(r.to, "/new");
        assert_eq!(r.status, 301);
    }

    #[test]
    fn hash_inside_token_is_preserved_as_fragment() {
        // `#` only begins a comment after whitespace — a fragment in the `to`
        // token stays attached to the URL.
        let r = parse_one("/from-topic /to/#topic 301").unwrap();
        assert_eq!(r.from, RulePattern::Exact("/from-topic".into()));
        assert_eq!(r.to, "/to/#topic");
        assert_eq!(r.status, 301);
    }

    #[test]
    fn hash_after_tab_starts_a_comment() {
        // Tab counts as whitespace for the purposes of comment detection, so
        // `\t#trailing` is a comment regardless of which whitespace char
        // preceded it.
        let r = parse_one("/old /new 301\t#trailing").unwrap();
        assert_eq!(r.to, "/new");
        let r = parse_one("/old\t/new\t301\t#trailing").unwrap();
        assert_eq!(r.to, "/new");
    }

    #[test]
    fn whitespace_is_permissive() {
        // Mixed tabs/spaces between tokens.
        let r = parse_one("/old\t \t/new   \t  302").unwrap();
        assert_eq!(r.from, RulePattern::Exact("/old".into()));
        assert_eq!(r.to, "/new");
        assert_eq!(r.status, 302);
    }

    #[test]
    fn each_supported_status_parses() {
        for status in SUPPORTED_STATUSES {
            let line = format!("/from /to {status}");
            let r = parse_one(&line).unwrap_or_else(|e| panic!("status {status}: {e}"));
            assert_eq!(r.status, *status);
        }
    }

    #[test]
    fn exact_pattern_is_default() {
        let r = parse_one("/about /about.html 200").unwrap();
        assert_eq!(r.from, RulePattern::Exact("/about".into()));
    }

    #[test]
    fn trailing_star_lowers_to_subtree() {
        let r = parse_one("/blog/* /blog/index.html 200").unwrap();
        assert_eq!(r.from, RulePattern::Subtree("/blog/".into()));
    }

    #[test]
    fn root_star_lowers_to_root_subtree() {
        // `/*` matches the entire site; the lowered prefix is `/` so every
        // request matches via `starts_with("/")`.
        let r = parse_one("/* /index.html 200").unwrap();
        assert_eq!(r.from, RulePattern::Subtree("/".into()));
    }

    #[test]
    fn three_xx_accepts_fully_qualified_url() {
        let r = parse_one("/legacy https://example.com/new 301").unwrap();
        assert_eq!(r.to, "https://example.com/new");
        assert_eq!(r.status, 301);
    }

    #[test]
    fn three_xx_accepts_absolute_path() {
        let r = parse_one("/legacy /new 308").unwrap();
        assert_eq!(r.to, "/new");
    }

    #[test]
    fn multiple_rules_preserve_order() {
        let input = "\
/a /a.html 200
/old /new 301
/gone /tombstone.html 410
";
        let rules = parse(input).unwrap();
        let statuses: Vec<u16> = rules.iter().map(|r| r.status).collect();
        assert_eq!(statuses, vec![200, 301, 410]);
    }

    // ── reject cases ──────────────────────────────────────────────────────────

    #[test]
    fn rejects_too_few_fields() {
        let e = err("/only-from");
        assert!(e.message.contains("3 fields"), "{}", e.message);
        assert_eq!(e.line, 1);
    }

    #[test]
    fn rejects_too_many_fields() {
        // 4 fields = extra token after status (would be inline headers in Netlify).
        let e = err("/from /to 301 extra");
        assert!(e.message.contains("3 fields"), "{}", e.message);
        assert!(e.message.contains("not supported"), "{}", e.message);
    }

    #[test]
    fn rejects_unsupported_status() {
        let e = err("/from /to 418");
        assert!(e.message.contains("418"), "{}", e.message);
        assert!(e.message.contains("200"), "{}", e.message);
    }

    #[test]
    fn rejects_non_integer_status() {
        let e = err("/from /to redirect");
        assert!(e.message.contains("integer"), "{}", e.message);
    }

    #[test]
    fn rejects_netlify_force_suffix() {
        let e = err("/from /to 301!");
        assert!(e.message.contains("'!'"), "{}", e.message);
    }

    #[test]
    fn rejects_splat_in_to() {
        let e = err("/blog/* /archive/:splat 301");
        assert!(e.message.contains(":splat"), "{}", e.message);
    }

    #[test]
    fn rejects_placeholder_in_to() {
        let e = err("/users/:id /people/:id 301");
        // The `:id` in `from` trips the ':' placeholder check first.
        assert!(e.message.contains("placeholders"), "{}", e.message);
    }

    #[test]
    fn rejects_placeholder_in_to_with_safe_from() {
        let e = err("/blog/* /archive/:placeholder 301");
        assert!(e.message.contains(":placeholder"), "{}", e.message);
    }

    #[test]
    fn rejects_relative_from() {
        let e = err("relative /target 301");
        assert!(e.message.contains("absolute path"), "{}", e.message);
    }

    #[test]
    fn rejects_wildcard_in_from_not_at_end() {
        let e = err("/blog/*/post /target 301");
        assert!(e.message.contains("trailing '/*'"), "{}", e.message);
    }

    #[test]
    fn rejects_relative_to_on_200() {
        let e = err("/from to 200");
        assert!(e.message.contains("absolute asset path"), "{}", e.message);
    }

    #[test]
    fn rejects_relative_to_on_4xx() {
        let e = err("/from target.html 404");
        assert!(e.message.contains("absolute asset path"), "{}", e.message);
    }

    #[test]
    fn rejects_unparseable_to_on_3xx() {
        // Not absolute, not a URL — `Url::parse` rejects relative URLs.
        let e = err("/from not-a-url 301");
        assert!(e.message.contains("absolute path"), "{}", e.message);
    }

    #[test]
    fn error_reports_line_number() {
        let input = "\
# comment
/good /good 301
/bad /bad 999
/another /another 302
";
        let e = err(input);
        assert_eq!(e.line, 3);
    }

    #[test]
    fn error_carries_source_line_for_display() {
        // The plugin echoes parse errors verbatim to the user; the source line
        // must be embedded so a line-number alone isn't the only hint.
        let input = "\
/good /good 301
/incomplete /target
";
        let e = err(input);
        assert_eq!(e.line, 2);
        assert_eq!(e.source, "/incomplete /target");
        let rendered = format!("{e}");
        assert!(rendered.contains("/incomplete /target"), "{rendered}");
        assert!(rendered.contains("line 2"), "{rendered}");
    }
}
