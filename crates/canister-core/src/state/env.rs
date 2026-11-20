//! Environment cookie: capturing the canister's env snapshot and re-certifying
//! whatever it affects. The rendered `ic_env` cookie is a certified header on
//! `text/html` responses (and on any redirect rule that rewrites to an HTML
//! asset), so a changed snapshot must re-certify those before it is served.
//! Callers refresh `certified_data` afterwards.

use super::State;
use crate::cert::AssetScope;
use crate::runtime::SystemContext;
use candid::Principal;
use wire_types::SessionId;

impl State {
    /// Stores the rendered env cookie from a freshly captured snapshot **without**
    /// re-certifying. Used by `post_upgrade` *before* `post_upgrade_rebuild`, so
    /// the rebuild — which re-certifies every asset from scratch — picks the
    /// cookies up through `effective_headers`.
    pub fn store_env(&mut self, env: &crate::runtime::CanisterEnv) {
        self.certifier.set_env_cookie(env.render_cookies());
    }

    /// Captures the env at the **start of a sync** (or of an `upload_assets`
    /// call). If the rendered cookie is unchanged — the common case, since env
    /// vars rarely change between syncs — this is a no-op. If it changed, the
    /// HTML assets (and the rules) are marked stale, and the sync's
    /// `execute_operations` re-certifies them at the end of its first call,
    /// spread across messages: otherwise HTML assets the sync doesn't touch
    /// would keep an old-cookie certificate while `effective_headers` serves the
    /// new cookie, and the gateway would reject them. A sync always follows
    /// `start_sync` with at least one (final) `execute_operations` call.
    pub fn capture_env_at_sync_start(&mut self, env: &crate::runtime::CanisterEnv) {
        if self.certifier.env_cookie() != Some(env.render_cookies().as_slice()) {
            self.store_env(env);
            self.certifier.mark_assets_stale(AssetScope::Html);
        }
    }

    /// Captures a new env snapshot on an already-running canister, outside a
    /// sync: takes the sync lock and marks stale everything the cookie affects —
    /// every `text/html` asset (its effective header set changed) and the
    /// redirect-rule entries (a 200-rewrite to an HTML asset borrows the
    /// cookie). Non-HTML assets are untouched. The caller drives the returned
    /// maintenance session to completion (see [`Self::maintenance_step`]), which
    /// re-certifies them and releases the lock, then refreshes `certified_data`.
    pub fn refresh_env(
        &mut self,
        owner: Principal,
        env: &crate::runtime::CanisterEnv,
        system_context: &SystemContext,
    ) -> Result<SessionId, String> {
        let session_id = self.begin_maintenance(owner, system_context)?;
        self.store_env(env);
        self.certifier.mark_assets_stale(AssetScope::Html);
        Ok(session_id)
    }
}
