//! Plugin-side "always certified 404" convention (root-only).
//!
//! The canister has no built-in 404 fallback: an HTTP request for a path with
//! no matching asset and no matching redirect rule produces an *uncertified*
//! response, which the HTTP gateway rejects. To guarantee that every request
//! resolves to a certified response, the plugin ensures the root wildcard
//! (`/*`) is always backed by a real `404.html` asset plus a redirect rule.
//!
//! Mirrors Netlify's `404.html` convention, entirely plugin-side — the canister
//! stays a dumb "assets + rules" store:
//!
//! - If the project ships a root `/404.html`, append `/* /404.html 404` so it
//!   serves as the site-wide not-found page.
//! - If it does not — and the user has not declared their own root `/*` rule
//!   (e.g. a SPA `/* /index.html 200`) — inject a branded default `/404.html`
//!   asset and append the same catch-all rule.
//! - If the user already declares a root `/*` rule, leave everything alone:
//!   their rule covers the whole path space, so the certified-response
//!   guarantee already holds (and a SPA's `/* … 200` must win, not a 404).
//!
//! The catch-all is appended **after** the user's `_redirects` so explicit user
//! rules (and the prepended html-handling rules) win first; it only fires for
//! paths nothing else claims.

use wire_types::{RedirectRule, RulePattern};

/// Asset key for the site-wide not-found page.
pub const ROOT_404_KEY: &str = "/404.html";

/// Default not-found page injected when a project ships no root `404.html`.
/// Self-contained (no external assets) so it renders even when nothing else
/// on the site resolves.
pub const DEFAULT_404_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 — Not Found</title>
<style>
  :root { color-scheme: light dark; }
  html, body { height: 100%; margin: 0; }
  body {
    display: flex; align-items: center; justify-content: center;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: Canvas; color: CanvasText;
  }
  main { text-align: center; padding: 2rem; max-width: 32rem; }
  h1 { font-size: 4rem; margin: 0; font-weight: 700; letter-spacing: -0.05em; }
  p { margin: 0.5rem 0 0; font-size: 1.1rem; opacity: 0.8; }
  .hint { margin-top: 1.5rem; font-size: 0.85rem; opacity: 0.55; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<main>
  <h1>404</h1>
  <p>The page you requested could not be found.</p>
  <p class="hint">This is the default page served by the assets canister. Add a <code>404.html</code> to your project to customize it.</p>
</main>
</body>
</html>
"#;

/// True if `rules` already contain a root-wildcard (`/*`) rule. Such a rule
/// matches the entire path space, so it already covers the root `<*>` slot and
/// makes a synthesized catch-all redundant (and, for a SPA `/* … 200`, the
/// user's rule must be the one that wins).
pub fn has_root_catchall(rules: &[RedirectRule]) -> bool {
    rules
        .iter()
        .any(|r| matches!(&r.from, RulePattern::Subtree(p) if p == "/"))
}

/// What the root-only 404 convention should do for a given project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Upload a branded default `/404.html` asset (the project ships none).
    pub inject_branded_asset: bool,
    /// Append the `/* /404.html 404` catch-all rule.
    pub append_catchall: bool,
}

/// Decide the 404 actions from the scanned asset keys and the user's parsed
/// `_redirects` rules:
///
/// - User already declares a root `/*` rule → do nothing (their rule covers the
///   whole path space and must win).
/// - Otherwise append the catch-all, and inject the branded `/404.html` unless
///   the project already ships a root `404.html`.
pub fn plan(asset_keys: &[String], user_rules: &[RedirectRule]) -> Plan {
    if has_root_catchall(user_rules) {
        return Plan {
            inject_branded_asset: false,
            append_catchall: false,
        };
    }
    let ships_root_404 = asset_keys.iter().any(|k| k == ROOT_404_KEY);
    Plan {
        inject_branded_asset: !ships_root_404,
        append_catchall: true,
    }
}

/// The catch-all rule mapping every otherwise-unmatched path to the root
/// not-found page with a 404 status.
pub fn catchall_rule() -> RedirectRule {
    RedirectRule {
        from: RulePattern::Subtree("/".to_string()),
        to: ROOT_404_KEY.to_string(),
        status: 404,
        headers: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redirects;

    #[test]
    fn catchall_rule_targets_root_404() {
        let r = catchall_rule();
        assert_eq!(r.from, RulePattern::Subtree("/".to_string()));
        assert_eq!(r.to, ROOT_404_KEY);
        assert_eq!(r.status, 404);
        assert!(r.headers.is_empty());
    }

    #[test]
    fn has_root_catchall_detects_user_root_wildcard() {
        // `/*` parses to a root subtree, regardless of the target/status.
        let spa = redirects::parse("/* /index.html 200\n").unwrap();
        assert!(has_root_catchall(&spa));
        let custom_404 = redirects::parse("/* /404.html 404\n").unwrap();
        assert!(has_root_catchall(&custom_404));
    }

    #[test]
    fn has_root_catchall_ignores_non_root_rules() {
        // A nested subtree and exact rules do not cover the whole path space.
        let nested = redirects::parse("/blog/* /blog/index.html 200\n").unwrap();
        assert!(!has_root_catchall(&nested));
        let exact = redirects::parse("/old /new 301\n").unwrap();
        assert!(!has_root_catchall(&exact));
        assert!(!has_root_catchall(&[]));
    }

    fn keys(ks: &[&str]) -> Vec<String> {
        ks.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn plan_injects_and_appends_when_no_404_and_no_catchall() {
        // Bare project: must both inject the branded page and append the rule.
        let p = plan(&keys(&["/index.html"]), &[]);
        assert_eq!(
            p,
            Plan {
                inject_branded_asset: true,
                append_catchall: true
            }
        );
    }

    #[test]
    fn plan_appends_only_when_project_ships_root_404() {
        // A user-supplied root 404.html is wired up by the catch-all, but we
        // must not overwrite it with the branded default.
        let p = plan(&keys(&["/index.html", ROOT_404_KEY]), &[]);
        assert_eq!(
            p,
            Plan {
                inject_branded_asset: false,
                append_catchall: true
            }
        );
    }

    #[test]
    fn plan_does_nothing_when_user_declares_root_catchall() {
        // A SPA `/* … 200` (or the user's own `/* … 404`) already covers the
        // whole path space — leave it untouched, even with no 404.html.
        let spa = redirects::parse("/* /index.html 200\n").unwrap();
        let p = plan(&keys(&["/index.html"]), &spa);
        assert_eq!(
            p,
            Plan {
                inject_branded_asset: false,
                append_catchall: false
            }
        );
    }

    #[test]
    fn plan_ignores_a_nested_404_for_root_coverage() {
        // A `404.html` in a subdirectory does not cover the root, so the root
        // path still needs the branded default + catch-all.
        let p = plan(&keys(&["/blog/404.html"]), &[]);
        assert_eq!(
            p,
            Plan {
                inject_branded_asset: true,
                append_catchall: true
            }
        );
    }

    #[test]
    fn catchall_rule_passes_redirect_parser_shape() {
        // The synthesized rule must be a shape the canister accepts: a root
        // subtree (`/`, trailing slash) with an absolute 4xx target. Confirm
        // it matches what the parser produces for the equivalent `_redirects`
        // line, so the canister validates it identically.
        let parsed = redirects::parse("/* /404.html 404\n").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], catchall_rule());
    }
}
