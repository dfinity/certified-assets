pub mod canister;
pub mod content;
pub mod glob;
pub mod headers;
pub mod html_handling;
pub mod redirects;
pub mod scan;
pub mod sync;

/// Strips a Netlify-style trailing comment from a single line of a `_redirects`
/// or `_headers` file. A `#` only starts a comment when it sits at the start of
/// the line or is preceded by whitespace; a `#` inside a token (e.g. the URL
/// fragment in `/to/#topic`, or a CSP `report-uri /csp#endpoint`) is preserved.
pub(crate) fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut prev_is_ws = true;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && prev_is_ws {
            return &line[..i];
        }
        prev_is_ws = b.is_ascii_whitespace();
    }
    line
}

#[cfg(test)]
mod strip_comment_tests {
    use super::strip_comment;

    #[test]
    fn leading_hash_strips_whole_line() {
        assert_eq!(strip_comment("# full-line comment"), "");
    }

    #[test]
    fn hash_after_space_starts_comment() {
        assert_eq!(strip_comment("/old /new 301 # tail"), "/old /new 301 ");
    }

    #[test]
    fn hash_after_tab_starts_comment() {
        assert_eq!(strip_comment("/old /new 301\t# tail"), "/old /new 301\t");
    }

    #[test]
    fn hash_inside_token_is_preserved() {
        assert_eq!(
            strip_comment("/from /to/#topic 301"),
            "/from /to/#topic 301"
        );
    }

    #[test]
    fn no_hash_returns_input_unchanged() {
        assert_eq!(strip_comment("/from /to 301"), "/from /to 301");
    }

    #[test]
    fn empty_input() {
        assert_eq!(strip_comment(""), "");
    }
}
