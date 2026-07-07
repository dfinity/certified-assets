//! Auto-synthesised redirect rules implementing Cloudflare's
//! `auto-trailing-slash` HTML handling default.
//!
//! Given the set of `.html` asset keys in the project, this module emits the
//! redirect rules that turn each HTML file's filesystem path into a canonical
//! URL plus 307 aliases for every other "obvious" form. The exact table comes
//! from the Cloudflare docs:
//!
//! - <https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/#automatic-trailing-slashes-default>
//!
//! For asset `/foo.html` (canonical `/foo`):
//!   - `/foo            -> 200  /foo.html`
//!   - `/foo.html       -> 307  /foo`              (inert: see below)
//!   - `/foo/           -> 307  /foo`
//!   - `/foo/index      -> 307  /foo`
//!   - `/foo/index.html -> 307  /foo`
//!
//! For asset `/bar/index.html` (canonical `/bar/`):
//!   - `/bar/            -> 200  /bar/index.html`
//!   - `/bar             -> 307  /bar/`
//!   - `/bar.html        -> 307  /bar`             (chains via /bar)
//!   - `/bar/index       -> 307  /bar`             (chains via /bar)
//!   - `/bar/index.html  -> 307  /bar`             (inert; chains via /bar)
//!
//! For asset `/index.html` (canonical `/`):
//!   - `/                -> 200  /index.html`
//!   - `/index           -> 307  /`
//!   - `/index.html      -> 307  /`                (inert)
//!
//! The two "inert" entries collide with the asset at the same key. Today the
//! canister's `build_http_response` matches assets before rules, so a request
//! for `/foo.html` still serves the asset directly with a 200 rather than the
//! 307 Cloudflare would emit. We synthesise the rules anyway so the ruleset
//! reflects the full table and self-activates if that precedence ever changes;
//! `docs/routing.md` documents the gap for users who care about strict URL
//! canonicalisation.
//!
//! Synthesised rules are prepended **before** the user's `_redirects` (see
//! `sync.rs`), so the html-handling defaults win at the exact paths they cover
//! and user rules catch what's left. A user-declared rule with the same `from`
//! as a synthesised rule is therefore shadowed by the synth rule.

use wire_types::{RedirectRule, RulePattern};

const HTML_EXT: &str = ".html";
const INDEX_HTML: &str = "/index.html";

/// Builds the Cloudflare `auto-trailing-slash` rule set for every `.html`
/// asset key in `asset_keys`. Keys are processed in sorted order so the
/// resulting rule list is deterministic across runs (and across two HTML
/// files that would claim the same canonical URL — first one alphabetically
/// wins via declaration order).
pub fn synthesize(asset_keys: &[String]) -> Vec<RedirectRule> {
    let mut html_keys: Vec<&str> = asset_keys
        .iter()
        .filter(|k| k.ends_with(HTML_EXT))
        .map(String::as_str)
        .collect();
    html_keys.sort_unstable();

    let mut rules = Vec::new();
    for key in html_keys {
        rules.extend(rules_for_html_asset(key));
    }
    rules
}

fn rules_for_html_asset(asset_key: &str) -> Vec<RedirectRule> {
    if asset_key == INDEX_HTML {
        return root_index_rules();
    }
    if let Some(stem) = asset_key.strip_suffix(INDEX_HTML) {
        // `/foo/index.html` → stem is `/foo` (never empty here — empty is the
        // root case handled above).
        return directory_index_rules(stem, asset_key);
    }
    // `/foo.html` (and any nested non-index HTML).
    let canonical = asset_key
        .strip_suffix(HTML_EXT)
        .expect("filtered to .html upstream");
    non_index_rules(canonical, asset_key)
}

fn root_index_rules() -> Vec<RedirectRule> {
    vec![
        rewrite("/", INDEX_HTML),
        redirect_307("/index", "/"),
        // Inert under current precedence — the asset at /index.html shadows.
        redirect_307(INDEX_HTML, "/"),
    ]
}

fn directory_index_rules(stem: &str, asset_key: &str) -> Vec<RedirectRule> {
    // stem = "/bar"; canonical = "/bar/".
    let canonical = format!("{stem}/");
    vec![
        rewrite(&canonical, asset_key),
        redirect_307(stem, &canonical),
        redirect_307(&format!("{stem}.html"), stem),
        redirect_307(&format!("{canonical}index"), stem),
        // Inert under current precedence — the asset shadows.
        redirect_307(asset_key, stem),
    ]
}

fn non_index_rules(canonical: &str, asset_key: &str) -> Vec<RedirectRule> {
    vec![
        rewrite(canonical, asset_key),
        // Inert under current precedence — the asset shadows.
        redirect_307(asset_key, canonical),
        redirect_307(&format!("{canonical}/"), canonical),
        redirect_307(&format!("{canonical}/index"), canonical),
        redirect_307(&format!("{canonical}/index.html"), canonical),
    ]
}

fn rewrite(from: &str, target: &str) -> RedirectRule {
    RedirectRule {
        from: RulePattern::Exact(from.to_string()),
        to: target.to_string(),
        status: 200,
        headers: vec![],
    }
}

fn redirect_307(from: &str, target: &str) -> RedirectRule {
    RedirectRule {
        from: RulePattern::Exact(from.to_string()),
        to: target.to_string(),
        status: 307,
        headers: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(s: &str) -> RulePattern {
        RulePattern::Exact(s.to_string())
    }

    /// Collapses a rule to `(from, to, status)` for compact assertions.
    fn triple(r: &RedirectRule) -> (RulePattern, String, u16) {
        (r.from.clone(), r.to.clone(), r.status)
    }

    #[test]
    fn ignores_non_html_keys() {
        let keys = vec![
            "/app.js".to_string(),
            "/styles.css".to_string(),
            "/image.png".to_string(),
        ];
        assert!(synthesize(&keys).is_empty());
    }

    #[test]
    fn empty_input_yields_no_rules() {
        assert!(synthesize(&[]).is_empty());
    }

    #[test]
    fn non_index_html_produces_cf_table() {
        let rules = synthesize(&["/foo.html".to_string()]);
        let actual: Vec<_> = rules.iter().map(triple).collect();
        assert_eq!(
            actual,
            vec![
                (exact("/foo"), "/foo.html".into(), 200),
                (exact("/foo.html"), "/foo".into(), 307),
                (exact("/foo/"), "/foo".into(), 307),
                (exact("/foo/index"), "/foo".into(), 307),
                (exact("/foo/index.html"), "/foo".into(), 307),
            ]
        );
    }

    #[test]
    fn directory_index_produces_cf_table() {
        let rules = synthesize(&["/bar/index.html".to_string()]);
        let actual: Vec<_> = rules.iter().map(triple).collect();
        assert_eq!(
            actual,
            vec![
                (exact("/bar/"), "/bar/index.html".into(), 200),
                (exact("/bar"), "/bar/".into(), 307),
                (exact("/bar.html"), "/bar".into(), 307),
                (exact("/bar/index"), "/bar".into(), 307),
                (exact("/bar/index.html"), "/bar".into(), 307),
            ]
        );
    }

    #[test]
    fn root_index_produces_minimal_cf_table() {
        // Root index has no "bare" form — /index, /index.html only.
        let rules = synthesize(&["/index.html".to_string()]);
        let actual: Vec<_> = rules.iter().map(triple).collect();
        assert_eq!(
            actual,
            vec![
                (exact("/"), "/index.html".into(), 200),
                (exact("/index"), "/".into(), 307),
                (exact("/index.html"), "/".into(), 307),
            ]
        );
    }

    #[test]
    fn nested_directory_index() {
        // `/a/b/index.html` should canonicalise to `/a/b/`.
        let rules = synthesize(&["/a/b/index.html".to_string()]);
        let actual: Vec<_> = rules.iter().map(triple).collect();
        assert_eq!(
            actual,
            vec![
                (exact("/a/b/"), "/a/b/index.html".into(), 200),
                (exact("/a/b"), "/a/b/".into(), 307),
                (exact("/a/b.html"), "/a/b".into(), 307),
                (exact("/a/b/index"), "/a/b".into(), 307),
                (exact("/a/b/index.html"), "/a/b".into(), 307),
            ]
        );
    }

    #[test]
    fn nested_non_index_html() {
        let rules = synthesize(&["/docs/guide.html".to_string()]);
        let actual: Vec<_> = rules.iter().map(triple).collect();
        assert_eq!(
            actual,
            vec![
                (exact("/docs/guide"), "/docs/guide.html".into(), 200),
                (exact("/docs/guide.html"), "/docs/guide".into(), 307),
                (exact("/docs/guide/"), "/docs/guide".into(), 307),
                (exact("/docs/guide/index"), "/docs/guide".into(), 307),
                (exact("/docs/guide/index.html"), "/docs/guide".into(), 307),
            ]
        );
    }

    #[test]
    fn ordering_is_sorted_by_asset_key() {
        // /foo.html sorts before /foo/index.html (`.` < `/` in ASCII), so
        // /foo.html's rules emit first. When both contribute a rule with the
        // same `from`, the first one wins via declaration order at the
        // canister.
        let keys = vec!["/foo/index.html".to_string(), "/foo.html".to_string()];
        let rules = synthesize(&keys);
        let first_foo_rule = rules
            .iter()
            .find(|r| r.from == exact("/foo"))
            .expect("a rule at /foo");
        // The 200 rewrite from /foo.html beats the 307 from /foo/index.html.
        assert_eq!(first_foo_rule.status, 200);
        assert_eq!(first_foo_rule.to, "/foo.html");
    }

    #[test]
    fn mixed_html_and_assets_only_synthesises_for_html() {
        let keys = vec![
            "/app.js".to_string(),
            "/foo.html".to_string(),
            "/styles.css".to_string(),
        ];
        let rules = synthesize(&keys);
        // 5 rules for /foo.html, none for the others.
        assert_eq!(rules.len(), 5);
        assert!(
            rules
                .iter()
                .all(|r| matches!(&r.from, RulePattern::Exact(p) if p.starts_with("/foo")))
        );
    }

    #[test]
    fn no_headers_on_synthesised_rules() {
        let rules = synthesize(&[
            "/index.html".to_string(),
            "/foo.html".to_string(),
            "/bar/index.html".to_string(),
        ]);
        for r in rules {
            assert!(
                r.headers.is_empty(),
                "synthesised rule should not carry headers; the sync layer \
                 resolves _headers against the rule's `from` for 3xx rules"
            );
        }
    }
}
