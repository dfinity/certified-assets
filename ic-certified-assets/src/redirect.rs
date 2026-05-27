//! User-supplied redirect/rewrite/error rules expressed as `_redirects` entries.
//!
//! Step 1.1: types, validation, and storage only — rules are accepted by
//! `commit_batch`, persist across upgrades, and round-trip through
//! `get_redirect_rules`, but they don't yet affect certification or
//! `http_request` resolution. Later steps in Part 1 wire the rules into the
//! certified tree (1.2: 3xx/4xx; 1.3: status-200 rewrites) and remove the
//! canister's built-in aliasing (1.4).

use candid::{CandidType, Deserialize};
use serde::Serialize;

/// A single rule, mirroring one line of a Netlify-style `_redirects` file.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub struct RedirectRule {
    /// Request-side pattern.
    pub from: RulePattern,
    /// Target. Interpretation depends on `status`:
    /// - 200: absolute asset path
    /// - 3xx: absolute URL or absolute path (sent as `Location`)
    /// - 4xx: ignored (no target needed for an error response)
    pub to: String,
    /// One of 200, 301, 302, 307, 308, 404, 410.
    pub status: u16,
    /// Extra response headers on top of status-intrinsic ones.
    pub headers: Option<Vec<(String, String)>>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub enum RulePattern {
    /// Matches a single absolute path, e.g. `/old-page`.
    Exact(String),
    /// Matches any URL whose path starts with this prefix. The prefix must end
    /// with `/` so the subtree boundary is unambiguous.
    Subtree(String),
}

const SUPPORTED_STATUS_CODES: [u16; 7] = [200, 301, 302, 307, 308, 404, 410];

/// Shape-checks a rule. Step 1.1 only checks invariants that don't need rule
/// semantics — later steps grow this with header/target rules.
pub fn validate(rule: &RedirectRule) -> Result<(), String> {
    let from_path = match &rule.from {
        RulePattern::Exact(p) => p,
        RulePattern::Subtree(p) => {
            if !p.ends_with('/') {
                return Err(format!(
                    "subtree pattern '{p}' must end with '/' for unambiguous prefix semantics"
                ));
            }
            p
        }
    };
    if !from_path.starts_with('/') {
        return Err(format!(
            "'from' pattern '{from_path}' must be an absolute path (start with '/')"
        ));
    }

    if !SUPPORTED_STATUS_CODES.contains(&rule.status) {
        return Err(format!(
            "unsupported status code {} (expected one of 200, 301, 302, 307, 308, 404, 410)",
            rule.status
        ));
    }

    if rule.to.contains(":splat") || rule.to.contains(":placeholder") {
        return Err(
            "dynamic substitution (:splat / :placeholder) is not supported in this version, \
             see follow-up plan"
                .to_string(),
        );
    }

    if let Some(headers) = &rule.headers {
        for (k, v) in headers {
            if k.is_empty() {
                return Err("header name must not be empty".to_string());
            }
            if v.is_empty() {
                return Err(format!("header '{k}' has empty value"));
            }
            if !k.bytes().all(is_valid_header_name_byte) {
                return Err(format!("header name '{k}' contains invalid characters"));
            }
            if !v.bytes().all(is_valid_header_value_byte) {
                return Err(format!("header '{k}' value contains invalid characters"));
            }
        }
    }

    Ok(())
}

fn is_valid_header_name_byte(b: u8) -> bool {
    // RFC 7230 token characters.
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
    )
}

fn is_valid_header_value_byte(b: u8) -> bool {
    // Visible ASCII plus space/tab — matches RFC 7230 `field-value` for the
    // common single-line case. We deliberately reject CR/LF so a rule can't
    // smuggle header injection through the canister.
    b == b'\t' || (0x20..=0x7e).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{decode_one, encode_one};

    fn rule(from: RulePattern, to: &str, status: u16) -> RedirectRule {
        RedirectRule {
            from,
            to: to.to_string(),
            status,
            headers: None,
        }
    }

    #[test]
    fn validate_accepts_supported_shapes() {
        for status in [200, 301, 302, 307, 308, 404, 410] {
            validate(&rule(RulePattern::Exact("/a".into()), "/b", status)).unwrap();
            validate(&rule(RulePattern::Subtree("/a/".into()), "/b", status)).unwrap();
        }
    }

    #[test]
    fn validate_rejects_relative_from() {
        let err = validate(&rule(RulePattern::Exact("relative".into()), "/b", 301)).unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn validate_rejects_subtree_without_trailing_slash() {
        let err =
            validate(&rule(RulePattern::Subtree("/blog".into()), "/b", 301)).unwrap_err();
        assert!(err.contains("must end with '/'"), "got: {err}");
    }

    #[test]
    fn validate_rejects_unsupported_status() {
        let err = validate(&rule(RulePattern::Exact("/a".into()), "/b", 418)).unwrap_err();
        assert!(err.contains("unsupported status code 418"), "got: {err}");
    }

    #[test]
    fn validate_rejects_splat_in_target() {
        let err =
            validate(&rule(RulePattern::Subtree("/a/".into()), "/b/:splat", 301)).unwrap_err();
        assert!(err.contains("dynamic substitution"), "got: {err}");
    }

    #[test]
    fn validate_rejects_placeholder_in_target() {
        let err = validate(&rule(
            RulePattern::Subtree("/a/".into()),
            "/b/:placeholder",
            301,
        ))
        .unwrap_err();
        assert!(err.contains("dynamic substitution"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_header_name() {
        let mut r = rule(RulePattern::Exact("/a".into()), "/b", 301);
        r.headers = Some(vec![("".into(), "v".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("header name must not be empty"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_header_value() {
        let mut r = rule(RulePattern::Exact("/a".into()), "/b", 301);
        r.headers = Some(vec![("X-Foo".into(), "".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("empty value"), "got: {err}");
    }

    #[test]
    fn validate_rejects_crlf_in_header_value() {
        let mut r = rule(RulePattern::Exact("/a".into()), "/b", 301);
        r.headers = Some(vec![("X-Foo".into(), "bar\r\nX-Evil: 1".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("invalid characters"), "got: {err}");
    }

    #[test]
    fn validate_rejects_non_token_header_name() {
        let mut r = rule(RulePattern::Exact("/a".into()), "/b", 301);
        r.headers = Some(vec![("X Foo".into(), "bar".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("invalid characters"), "got: {err}");
    }

    #[test]
    fn candid_roundtrip_preserves_rule() {
        let r = RedirectRule {
            from: RulePattern::Subtree("/blog/".into()),
            to: "/home".into(),
            status: 308,
            headers: Some(vec![("X-Trace".into(), "1".into())]),
        };
        let bytes = encode_one(&r).unwrap();
        let back: RedirectRule = decode_one(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn serde_roundtrip_preserves_rule() {
        // The stable-state serializer uses serde, not Candid.
        let r = RedirectRule {
            from: RulePattern::Exact("/old".into()),
            to: "/new".into(),
            status: 301,
            headers: None,
        };
        let bytes = serde_cbor::to_vec(&r).unwrap();
        let back: RedirectRule = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(r, back);
    }
}
