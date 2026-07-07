//! Upgrade: rebuilding all derived heap state from the durable store. There is
//! no serialize/deserialize step across upgrades — the certified tree, the
//! redirect-rule entries, the 404 fallback, and the access-protection token index are all
//! reconstructed from stable memory here.

use super::State;

impl State {
    /// Rebuilds all derived heap state from the durable stable-memory state
    /// after an upgrade: the certified-response tree for every asset, the
    /// redirect-rule certified entries, the built-in 404 fallback (the last two
    /// via `on_redirect_rules_change`), and the access-protection token index. The caller
    /// publishes `certified_data` afterwards.
    pub fn post_upgrade_rebuild(&mut self) {
        self.certifier.recertify_all_assets(&self.store);
        self.on_redirect_rules_change();
        self.rebuild_token_index();
        // If protection is on but the login page asset isn't present, the asset
        // loop above didn't re-assert its redeem responses — do it explicitly so
        // the redeem endpoint survives the upgrade even in the degraded state.
        if let Some(login_page) = self.protection_login_page()
            && !self.store.contains_asset(&login_page)
        {
            self.certifier
                .reassert_login_responses(&self.store, &login_page);
        }
    }

    /// Rebuilds the in-heap access-protection index (`token_id → expires_at`) from the durable
    /// `tokens` store after an upgrade. Lossless: every entry is derivable from a
    /// `TokenMeta`. Cheap — the token set is small.
    fn rebuild_token_index(&mut self) {
        self.token_index = self
            .store
            .iter_tokens()
            .map(|(_, meta)| (meta.token_id, meta.expires_at))
            .collect();
    }
}
