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
    response_hash, AssetPath, CertificateExpression, HashTreePath, NestedTreeKey,
};
use candid::{CandidType, Deserialize};
use http::{HeaderName, HeaderValue, StatusCode};
use ic_representation_independent_hash::Value;
use serde::Serialize;
use sha2::Digest;

/// A single rule, mirroring one line of a Netlify-style `_redirects` file.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub struct RedirectRule {
    /// Request-side pattern.
    pub from: RulePattern,
    /// Target. Interpretation depends on `status`:
    /// - 200: absolute asset path (rewrite — serve target's body)
    /// - 3xx: absolute URL or absolute path (sent as `Location`)
    /// - 4xx: absolute asset path to serve as the custom error page
    ///   (e.g. `/404.html`); if the asset doesn't exist the rule stays
    ///   inert and unmatched paths fall through to the canister's
    ///   built-in 404
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

const SUPPORTED_STATUS_CODES: &[StatusCode] = &[
    StatusCode::OK,
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::FOUND,
    StatusCode::TEMPORARY_REDIRECT,
    StatusCode::PERMANENT_REDIRECT,
    StatusCode::NOT_FOUND,
    StatusCode::GONE,
];

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

    let status = StatusCode::from_u16(rule.status)
        .ok()
        .filter(|s| SUPPORTED_STATUS_CODES.contains(s))
        .ok_or_else(|| {
            format!(
                "unsupported status code {} (expected one of 200, 301, 302, 307, 308, 404, 410)",
                rule.status
            )
        })?;

    if rule.to.contains(":splat") || rule.to.contains(":placeholder") {
        return Err(
            "dynamic substitution (:splat / :placeholder) is not supported in this version, \
             see follow-up plan"
                .to_string(),
        );
    }

    if status == StatusCode::OK && !rule.to.starts_with('/') {
        return Err(format!(
            "'to' for a status-200 rewrite must be an absolute asset path (got '{}')",
            rule.to
        ));
    }

    if status.is_client_error() && !rule.to.starts_with('/') {
        return Err(format!(
            "'to' for a 4xx rule must be an absolute asset path \
             (e.g. '/404.html'); got '{}'",
            rule.to
        ));
    }

    if let Some(headers) = &rule.headers {
        for (k, v) in headers {
            if k.is_empty() {
                return Err("header name must not be empty".to_string());
            }
            if v.is_empty() {
                return Err(format!("header '{k}' has empty value"));
            }
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| format!("header name '{k}' contains invalid characters"))?;
            // `HeaderValue` rejects CR/LF, so a rule can't smuggle header
            // injection through the canister.
            HeaderValue::from_str(v)
                .map_err(|_| format!("header '{k}' value contains invalid characters"))?;
            if name == http::header::LOCATION {
                return Err(if status.is_redirection() {
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
            // For rules that borrow a body from a target asset (200 rewrites
            // and 4xx custom error pages), the content-type comes from the
            // target — overriding it would split it from the certified
            // headers the verifier checks.
            let borrows_from_target = status == StatusCode::OK || status.is_client_error();
            if borrows_from_target && name == http::header::CONTENT_TYPE {
                return Err(
                    "'content-type' header must not be overridden when the rule serves an \
                     asset body; the canister takes 'content-type' from the target asset"
                        .to_string(),
                );
            }
        }
    }

    Ok(())
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
        match &self.from {
            // Mirror `AssetPath::from(path).asset_hash_path_root()` so a rule
            // at `/old` lives in the same `<$>` slot the asset at `/old`
            // would occupy.
            RulePattern::Exact(p) => AssetPath::from(p.as_str()).asset_hash_path_root(),
            RulePattern::Subtree(p) => {
                let trimmed = p.trim_matches('/');
                let mut segs: Vec<NestedTreeKey> = vec!["http_expr".into()];
                if !trimmed.is_empty() {
                    for s in trimmed.split('/') {
                        segs.push(NestedTreeKey::String(s.to_string()));
                    }
                }
                segs.push("<*>".into());
                HashTreePath::from(segs)
            }
        }
    }

    /// Headers that the rule itself synthesizes (used only by 3xx rules; 200
    /// and 4xx rules borrow their headers from the target asset). The
    /// `ic-certificateexpression` header is appended at certification time
    /// and is not included here.
    pub fn certified_headers(&self) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> =
            vec![("content-type".to_string(), "text/plain".to_string())];
        if StatusCode::from_u16(self.status).is_ok_and(|s| s.is_redirection()) {
            headers.push(("location".to_string(), self.to.clone()));
        }
        if let Some(extras) = &self.headers {
            for (k, v) in extras {
                headers.push((k.to_lowercase(), v.clone()));
            }
        }
        headers
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
    /// 3xx rule, or 4xx rule with no `to` target: response body and headers
    /// are synthesized by the rule.
    Synthetic { expression: CertificateExpression },
    /// Rule borrows its body from a target asset.
    ///
    /// `status == 200`: pure rewrite — the rule re-uses each encoding's
    /// existing certified response hash verbatim.
    ///
    /// `status` is 404 or 410: custom error page — the rule serves the
    /// target asset's body but re-certifies each encoding with the override
    /// status (different response_hash than the asset's own 200 entry).
    AliasOf { target_key: String, status: u16 },
}

/// Build the certified-tree entries for a 3xx redirect rule. The response
/// has an empty body; only the headers (content-type, Location, and any
/// rule-supplied extras) are certified.
pub(crate) fn build_synthetic_entry(rule: &RedirectRule) -> CertifiedRuleEntry {
    let headers = rule.certified_headers();
    let header_values: Vec<(String, Value)> = headers
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();

    let body_hash: [u8; 32] = sha2::Sha256::digest([]).into();

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
    fn tree_location_root_exact_matches_asset_path() {
        // An exact rule at `/` must share the same `<$>` slot the asset at
        // `/` would occupy, including the empty segment that
        // `AssetPath::from("/")` produces.
        let r = rule(RulePattern::Exact("/".into()), "/index.html", 200);
        let segs = r.tree_location().0;
        let names: Vec<&str> = segs
            .iter()
            .map(|k| match k {
                NestedTreeKey::String(s) => s.as_str(),
                _ => panic!("expected string segment"),
            })
            .collect();
        assert_eq!(names, vec!["http_expr", "", "<$>"]);
    }

    #[test]
    fn certified_headers_3xx_includes_location() {
        let r = rule(RulePattern::Exact("/old".into()), "/new", 301);
        let headers = r.certified_headers();
        assert!(headers.iter().any(|(k, v)| k == "location" && v == "/new"));
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
    }

    #[test]
    fn build_synthetic_entry_distinct_per_status() {
        // Different 3xx status codes must yield different response hashes so
        // the tree can disambiguate identical paths.
        let exact = RulePattern::Exact("/x".into());
        let e301 = build_synthetic_entry(&rule(exact.clone(), "/y", 301));
        let e302 = build_synthetic_entry(&rule(exact.clone(), "/y", 302));
        let e307 = build_synthetic_entry(&rule(exact, "/y", 307));
        assert_eq!(e301.location.0, e302.location.0);
        assert_eq!(e301.location.0, e307.location.0);
        assert_ne!(e301.tree_paths[0].0, e302.tree_paths[0].0);
        assert_ne!(e301.tree_paths[0].0, e307.tree_paths[0].0);
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
    fn validate_rejects_4xx_empty_target() {
        // `_redirects` always provides a target — empty `to` is a misuse.
        for status in [404, 410] {
            let err = validate(&rule(RulePattern::Exact("/x".into()), "", status)).unwrap_err();
            assert!(
                err.contains("must be an absolute asset path"),
                "got: {err}"
            );
        }
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
