//! Environment cookie: capturing the canister's env snapshot and re-certifying
//! whatever it affects. The rendered `ic_env` cookie is a certified header on
//! `text/html` responses (and on any redirect rule that rewrites to an HTML
//! asset), so a changed snapshot must re-certify those before it is served.
//! Callers refresh `certified_data` afterwards.

use super::State;

impl State {
    /// Stores the rendered env cookie from a freshly captured snapshot **without**
    /// re-certifying. Used by `post_upgrade` *before* `post_upgrade_rebuild`, so
    /// the rebuild — which re-certifies every asset from scratch — picks the
    /// cookie up through `effective_headers`.
    pub fn store_env(&mut self, env: &crate::runtime::CanisterEnv) {
        self.certifier.set_env_cookie(env.render_cookie());
    }

    /// Captures the env at the **start of a sync**, so the operations that follow
    /// certify their assets against the current cookie (no end-of-sync re-cert
    /// pass). If the rendered cookie is unchanged — the common case, since env
    /// vars rarely change between syncs — this is a no-op: existing certs are
    /// already correct and the sync's own ops will re-use the same cookie. Only
    /// when it *changed* must we re-certify here (via [`Self::refresh_env`]):
    /// otherwise HTML assets the sync doesn't touch would keep an old-cookie
    /// certificate while `effective_headers` serves the new cookie, and the
    /// gateway would reject them. Caller publishes `certified_data` afterwards.
    pub fn capture_env_at_sync_start(&mut self, env: &crate::runtime::CanisterEnv) {
        if self.certifier.env_cookie() != Some(env.render_cookie().as_str()) {
            self.refresh_env(env);
        }
    }

    /// Captures a new env snapshot on an already-running canister and re-certifies
    /// everything it affects: every `text/html` asset (its effective header set
    /// changed) and the redirect-rule entries (a 200-rewrite to an HTML asset
    /// borrows the cookie). Non-HTML assets are untouched. Caller must refresh
    /// `certified_data` afterwards. Mirrors `set_redirect_rules` →
    /// `on_redirect_rules_change`.
    pub fn refresh_env(&mut self, env: &crate::runtime::CanisterEnv) {
        self.store_env(env);
        let keys = self.store.asset_keys();
        for key in keys {
            if let Some(meta) = self.store.get_asset(&key)
                && crate::asset::is_html_content_type(&meta.content_type)
            {
                self.certifier.recertify_asset(&self.store, &key, &meta);
            }
        }
        // Rebuild rule entries: a 200-rewrite (e.g. the `/` SPA alias) to an HTML
        // target must pick up the cookie via its now-changed certified response.
        self.on_redirect_rules_change();
    }
}
