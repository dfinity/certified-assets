//! Glob pattern matched against asset keys, used by `_headers` to attach
//! both response headers and Content-Type overrides to assets.
//!
//! Syntax: leading `/`, then literal characters and a single greedy `*`.
//! `*` matches any sequence of characters including `/` and empty; every
//! other character matches literally. No `**`, no `?`, no `:placeholder` —
//! per Cloudflare Pages / Netlify `_headers` precedent.

/// Compiled glob. `parts.len() == 1` means no `*` (exact match); otherwise
/// consecutive entries are joined by an implicit `*`. Matcher is
/// `O(parts * key)` with no per-call allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPattern {
    /// Original pattern source, kept for Debug output and error reporting.
    source: String,
    /// Literal chunks of the pattern. Between consecutive entries the
    /// implicit `*` matches any sequence including `/` and empty.
    parts: Vec<String>,
}

impl KeyPattern {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn matches(&self, key: &str) -> bool {
        if self.parts.len() == 1 {
            return key == self.parts[0];
        }
        let Some(mut tail) = key.strip_prefix(self.parts[0].as_str()) else {
            return false;
        };
        let middles = &self.parts[1..self.parts.len() - 1];
        let last = &self.parts[self.parts.len() - 1];
        for middle in middles {
            match tail.find(middle.as_str()) {
                Some(idx) => tail = &tail[idx + middle.len()..],
                None => return false,
            }
        }
        tail.len() >= last.len() && tail.ends_with(last.as_str())
    }
}

pub fn parse(token: &str) -> Result<KeyPattern, String> {
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
    if token.contains("**") {
        return Err(format!(
            "'**' in pattern ('{token}') is not supported — a single '*' already matches any character sequence including '/'"
        ));
    }
    let parts: Vec<String> = token.split('*').map(String::from).collect();
    Ok(KeyPattern {
        source: token.to_string(),
        parts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(token: &str) -> KeyPattern {
        parse(token).unwrap()
    }

    #[test]
    fn exact_match_when_no_star() {
        let p = pat("/about");
        assert!(p.matches("/about"));
        assert!(!p.matches("/about/"));
        assert!(!p.matches("/aboutus"));
        assert!(!p.matches("/about/team"));
    }

    #[test]
    fn trailing_star_matches_subtree() {
        let p = pat("/blog/*");
        assert!(p.matches("/blog/post"));
        assert!(p.matches("/blog/nested/post"));
        assert!(!p.matches("/blogger"));
    }

    #[test]
    fn root_star_matches_everything() {
        let p = pat("/*");
        assert!(p.matches("/anywhere"));
        assert!(p.matches("/deep/nested/path"));
    }

    #[test]
    fn extension_glob_matches_by_suffix() {
        let p = pat("/*.md");
        assert!(p.matches("/llms.md"));
        assert!(p.matches("/docs/intro.md"));
        assert!(p.matches("/a/b/c.md"));
        assert!(!p.matches("/llms.txt"));
        // Anchored suffix — `.md` mid-path is not a match.
        assert!(!p.matches("/a.md.html"));
    }

    #[test]
    fn mid_path_wildcard_matches() {
        let p = pat("/api/*/v1");
        assert!(p.matches("/api/users/v1"));
        assert!(p.matches("/api/nested/path/v1"));
        assert!(!p.matches("/api/v1"));
        assert!(!p.matches("/api/users/v2"));
    }

    #[test]
    fn rejects_relative_pattern() {
        assert!(parse("about").unwrap_err().contains("absolute path"));
    }

    #[test]
    fn rejects_double_star() {
        assert!(parse("/foo/**/bar").unwrap_err().contains("'**'"));
    }

    #[test]
    fn rejects_placeholder() {
        assert!(parse("/blog/:slug").unwrap_err().contains("placeholders"));
    }
}
