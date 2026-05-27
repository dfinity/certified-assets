//! User-supplied redirect/rewrite/error rules expressed as `_redirects` entries.
//!
//! Step 1.1: types, validation, and storage only — rules are accepted by
//! `commit_batch`, persist across upgrades, and round-trip through
//! `get_redirect_rules`, but they don't yet affect certification or
//! `http_request` resolution. Later steps in Part 1 wire the rules into the
//! certified tree (1.2: 3xx/4xx; 1.3: status-200 rewrites) and remove the
//! canister's built-in aliasing (1.4).

use crate::certification::{
    build_ic_certificate_expression_from_headers, build_ic_certificate_expression_header,
    response_hash, CertificateExpression, HashTreePath, NestedTreeKey,
};
use candid::{CandidType, Deserialize};
use ic_representation_independent_hash::Value;
use serde::Serialize;
use sha2::Digest;

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

    if rule.status == 200 && !rule.to.starts_with('/') {
        return Err(format!(
            "'to' for a status-200 rewrite must be an absolute asset path (got '{}')",
            rule.to
        ));
    }

    if let Some(headers) = &rule.headers {
        let is_redirect = (301..=308).contains(&rule.status);
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
            if k.eq_ignore_ascii_case("location") {
                return Err(if is_redirect {
                    "'Location' header must not be set on a 3xx rule; \
                     the canister derives it from the rule's 'to' field"
                        .to_string()
                } else {
                    format!(
                        "'Location' header is only valid on 3xx rules (status {})",
                        rule.status
                    )
                });
            }
            if rule.status == 200 && k.eq_ignore_ascii_case("content-type") {
                return Err(
                    "'content-type' header must not be overridden on a status-200 rewrite; \
                     the canister takes it from the target asset"
                        .to_string(),
                );
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

impl RedirectRule {
    /// Does this rule's `from` pattern match the given request path?
    pub fn matches(&self, request_path: &str) -> bool {
        match &self.from {
            RulePattern::Exact(p) => p == request_path,
            RulePattern::Subtree(prefix) => request_path.starts_with(prefix.as_str()),
        }
    }

    /// Source path the rule is anchored at (the `from` pattern, without the
    /// trailing `/` for subtrees).
    pub fn source(&self) -> &str {
        match &self.from {
            RulePattern::Exact(p) | RulePattern::Subtree(p) => p.as_str(),
        }
    }

    /// Tree location for this rule's certified entry — segments through the
    /// terminator (`<$>` for exact matches, `<*>` for subtrees), without the
    /// per-response (expr_hash, req_hash, resp_hash) tail.
    pub fn tree_location(&self) -> HashTreePath {
        let (path, sentinel) = match &self.from {
            RulePattern::Exact(p) => (p.as_str(), "<$>"),
            RulePattern::Subtree(p) => (p.trim_end_matches('/'), "<*>"),
        };
        let mut segs: Vec<NestedTreeKey> = vec!["http_expr".into()];
        for s in path.split('/').filter(|s| !s.is_empty()) {
            segs.push(NestedTreeKey::String(s.to_string()));
        }
        segs.push(NestedTreeKey::String(sentinel.to_string()));
        HashTreePath::from(segs)
    }

    /// Headers that are part of the certified response for this rule. The
    /// `ic-certificateexpression` header is appended at certification time and
    /// is not included here.
    ///
    /// Step 1.2: 3xx rules carry `content-type` + `Location`, 4xx rules carry
    /// `content-type`. Status-200 rules (step 1.3) borrow their headers from
    /// the target asset; this method is not used in that path.
    pub fn certified_headers(&self) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> =
            vec![("content-type".to_string(), "text/plain".to_string())];
        if (301..=308).contains(&self.status) {
            headers.push(("location".to_string(), self.to.clone()));
        }
        if let Some(extras) = &self.headers {
            for (k, v) in extras {
                headers.push((k.to_lowercase(), v.clone()));
            }
        }
        headers
    }

    /// Synthesized response body for the rule's status.
    pub fn body(&self) -> Vec<u8> {
        match self.status {
            404 => b"Not Found".to_vec(),
            410 => b"Gone".to_vec(),
            _ => Vec::new(),
        }
    }
}

/// Precomputed certified-tree entries for a single rule.
///
/// `tree_paths` holds every leaf the rule owns — one for a synthetic
/// (3xx/4xx) response, or one per encoding for a status-200 rewrite that
/// mirrors a multi-encoding target asset.
#[derive(Clone, Debug)]
pub struct CertifiedRuleEntry {
    pub tree_paths: Vec<HashTreePath>,
    /// Location prefix (`["http_expr", segs.., "<$>"|"<*>"]`) — used as the
    /// `expr_path` field of the `IC-Certificate` response header.
    pub location: HashTreePath,
    pub kind: CertifiedRuleEntryKind,
}

#[derive(Clone, Debug)]
pub enum CertifiedRuleEntryKind {
    /// 3xx / 4xx rule: response body and headers are synthesized by the rule.
    Synthetic { expression: CertificateExpression },
    /// Status-200 rule: response borrows everything from the target asset.
    AliasOf { target_key: String },
}

/// Build the certified-tree entries for a non-status-200 rule. The rule's
/// body and headers come from the rule itself.
pub(crate) fn build_synthetic_entry(rule: &RedirectRule) -> CertifiedRuleEntry {
    let headers = rule.certified_headers();
    let header_values: Vec<(String, Value)> = headers
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();

    let body = rule.body();
    let body_hash: [u8; 32] = sha2::Sha256::digest(&body).into();

    let expression = build_ic_certificate_expression_from_headers(&header_values);

    // Mirror `certify_fallback_response`: the synthesized
    // `ic-certificateexpression` header is itself part of the certified
    // response.
    let cert_expr_header = build_ic_certificate_expression_header(&expression);
    let mut certified = header_values.clone();
    certified.push((cert_expr_header.0, Value::String(cert_expr_header.1)));
    let resp_hash = response_hash(&certified, rule.status, &body_hash);

    let location = rule.tree_location();
    let mut full_segs = location.0.clone();
    full_segs.push(NestedTreeKey::Hash(expression.expression_hash));
    full_segs.push(NestedTreeKey::String(String::new())); // empty request hash sentinel
    full_segs.push(NestedTreeKey::Hash(resp_hash.0));

    CertifiedRuleEntry {
        tree_paths: vec![HashTreePath::from(full_segs)],
        location,
        kind: CertifiedRuleEntryKind::Synthetic { expression },
    }
}

/// Build a tree path slot for the rule's location with the given expression
/// hash and response hash. Used by the status-200 path to mirror each
/// encoding of a target asset.
pub(crate) fn alias_tree_path(
    location: &HashTreePath,
    expression_hash: [u8; 32],
    response_hash: [u8; 32],
) -> HashTreePath {
    let mut segs = location.0.clone();
    segs.push(NestedTreeKey::Hash(expression_hash));
    segs.push(NestedTreeKey::String(String::new()));
    segs.push(NestedTreeKey::Hash(response_hash));
    HashTreePath::from(segs)
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
    fn validate_rejects_location_header_on_3xx() {
        let mut r = rule(RulePattern::Exact("/a".into()), "/b", 301);
        r.headers = Some(vec![("Location".into(), "/other".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("derives it from the rule's 'to' field"), "got: {err}");
    }

    #[test]
    fn validate_rejects_location_header_on_4xx() {
        let mut r = rule(RulePattern::Exact("/a".into()), "/b", 404);
        r.headers = Some(vec![("Location".into(), "/other".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("only valid on 3xx rules"), "got: {err}");
    }

    #[test]
    fn tree_location_exact() {
        let r = rule(RulePattern::Exact("/old".into()), "/new", 301);
        let segs = r.tree_location().0;
        let names: Vec<&str> = segs
            .iter()
            .map(|k| match k {
                NestedTreeKey::String(s) => s.as_str(),
                _ => panic!("expected string segment"),
            })
            .collect();
        assert_eq!(names, vec!["http_expr", "old", "<$>"]);
    }

    #[test]
    fn tree_location_subtree() {
        let r = rule(RulePattern::Subtree("/blog/".into()), "/home", 308);
        let segs = r.tree_location().0;
        let names: Vec<&str> = segs
            .iter()
            .map(|k| match k {
                NestedTreeKey::String(s) => s.as_str(),
                _ => panic!("expected string segment"),
            })
            .collect();
        assert_eq!(names, vec!["http_expr", "blog", "<*>"]);
    }

    #[test]
    fn tree_location_root_subtree() {
        let r = rule(RulePattern::Subtree("/".into()), "/home", 308);
        let segs = r.tree_location().0;
        let names: Vec<&str> = segs
            .iter()
            .map(|k| match k {
                NestedTreeKey::String(s) => s.as_str(),
                _ => panic!("expected string segment"),
            })
            .collect();
        assert_eq!(names, vec!["http_expr", "<*>"]);
    }

    #[test]
    fn certified_headers_3xx_includes_location() {
        let r = rule(RulePattern::Exact("/old".into()), "/new", 301);
        let headers = r.certified_headers();
        assert!(headers.iter().any(|(k, v)| k == "location" && v == "/new"));
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
    }

    #[test]
    fn certified_headers_4xx_no_location() {
        let r = rule(RulePattern::Exact("/missing".into()), "", 404);
        let headers = r.certified_headers();
        assert!(headers.iter().all(|(k, _)| k != "location"));
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
    }

    #[test]
    fn body_4xx_nonempty() {
        let r404 = rule(RulePattern::Exact("/missing".into()), "", 404);
        let r410 = rule(RulePattern::Exact("/gone".into()), "", 410);
        assert_eq!(r404.body(), b"Not Found");
        assert_eq!(r410.body(), b"Gone");
    }

    #[test]
    fn body_3xx_empty() {
        let r = rule(RulePattern::Exact("/old".into()), "/new", 301);
        assert!(r.body().is_empty());
    }

    #[test]
    fn build_synthetic_entry_distinct_per_status() {
        // Different status codes must yield different response hashes so the
        // tree can disambiguate identical paths.
        let exact = RulePattern::Exact("/x".into());
        let e301 = build_synthetic_entry(&rule(exact.clone(), "/y", 301));
        let e302 = build_synthetic_entry(&rule(exact.clone(), "/y", 302));
        let e404 = build_synthetic_entry(&rule(exact, "", 404));
        // All three sit at the same tree location prefix.
        assert_eq!(e301.location.0, e302.location.0);
        assert_eq!(e301.location.0, e404.location.0);
        // ...but their full tree paths differ in expr_hash / resp_hash.
        assert_ne!(e301.tree_paths[0].0, e302.tree_paths[0].0);
        assert_ne!(e301.tree_paths[0].0, e404.tree_paths[0].0);
    }

    #[test]
    fn validate_rejects_status_200_to_external_url() {
        let r = rule(
            RulePattern::Exact("/foo".into()),
            "https://example.com/",
            200,
        );
        let err = validate(&r).unwrap_err();
        assert!(err.contains("absolute asset path"), "got: {err}");
    }

    #[test]
    fn validate_rejects_content_type_override_on_200() {
        let mut r = rule(RulePattern::Exact("/foo".into()), "/target.html", 200);
        r.headers = Some(vec![("Content-Type".into(), "text/plain".into())]);
        let err = validate(&r).unwrap_err();
        assert!(err.contains("content-type"), "got: {err}");
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
