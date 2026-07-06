//! Access protection ("private app"): the serve side and the controller-driven
//! state management — the `State`-bound half of the access-protection domain.
//!
//! This is the `impl State` half. It builds the certified unauthenticated/redeem
//! responses served ahead of resolution (access protection itself runs in
//! [`State::http_request`], in [`super::serving`]), and it owns the
//! enable/disable/issue/revoke lifecycle. Byte-level response *shapes* and the
//! cookie/form parsing live in the data-layer [`crate::protection`]; the *tree*
//! mutations (certifying/removing those leaves) go through
//! [`crate::cert::Certifier`]. The hot-path access-protection index
//! (`token_index`) lives on `State` and is read here.

use super::State;
use crate::cert::{build_ic_certificate_expression_header, AssetPath, HashTreePath};
use crate::http::{HttpRequest, HttpResponse};
use crate::protection::{
    access_cookie_values, parse_form_token, token_id, ProtectionResponse, ProtectionStatus,
    TokenInfo, TokenMeta,
};
use serde_bytes::ByteBuf;

impl State {
    // ---- serve helpers ----

    /// Builds the served `HttpResponse` for a [`ProtectionResponse`], attaching the
    /// `IC-CertificateExpression` header and the `IC-Certificate` witness for
    /// `location`. The bytes match the certified leaf exactly (same constructor),
    /// so the gateway verifies it.
    fn serve_protection_response(
        &self,
        resp: &ProtectionResponse,
        request_path: &str,
        location: &HashTreePath,
        certificate: &[u8],
    ) -> HttpResponse {
        let cert_expr = resp.cert_expr();
        let cert_expr_header = build_ic_certificate_expression_header(&cert_expr);
        let cert_header =
            self.certifier
                .witness_to_header_with_location(request_path, location, certificate);
        let mut headers = resp.headers.clone();
        headers.push(cert_expr_header);
        headers.push(cert_header);
        HttpResponse {
            status_code: resp.status,
            headers,
            body: ByteBuf::from(resp.body.clone()),
            upgrade: None,
        }
    }

    /// Whether the request carries a currently-valid `certified_assets_access` cookie: some
    /// presented value hashes to a stored, unexpired token. Plain string parsing
    /// of the `Cookie` header, so `ic_env` and any other cookie are irrelevant.
    pub(super) fn cookie_token_valid(&self, req: &HttpRequest, now: u64) -> bool {
        access_cookie_values(req).into_iter().any(|value| {
            self.token_index
                .get(&token_id(&value))
                .is_some_and(|&expires_at| expires_at > now)
        })
    }

    /// Serves the certified unauthenticated response for `path`, mirroring the
    /// resolution order of [`State::http_request`]'s serve path so the witness
    /// lands at the most-specific certified location: an asset's sibling, a
    /// matching rule's `307`, or the universal root `<*>` `307`.
    pub(super) fn serve_unauthenticated(
        &self,
        path: &str,
        login_page: &str,
        certificate: &[u8],
    ) -> HttpResponse {
        // 1. Exact asset at this path → its 307/401 sibling.
        if let Some(meta) = self.store.get_asset(&path.to_string()) {
            let resp = if crate::asset::is_html_content_type(&meta.content_type) {
                ProtectionResponse::redirect_to_login(login_page)
            } else {
                ProtectionResponse::unauthorized()
            };
            let location = AssetPath::from(path).asset_hash_path_root();
            return self.serve_protection_response(&resp, path, &location, certificate);
        }
        // 2. Matching redirect rule → a 307 at the rule's location instead of
        //    following the rule (which could leak content). Same rule the serve
        //    path would pick; here we only need that one exists.
        if let Some((rule, _entry)) = self.matching_rule(path) {
            let resp = ProtectionResponse::redirect_to_login(login_page);
            let location = crate::redirect::tree_location(rule);
            return self.serve_protection_response(&resp, path, &location, certificate);
        }
        // 3. No asset, no rule → the universal root `<*>` 307.
        let resp = ProtectionResponse::redirect_to_login(login_page);
        let location = HashTreePath::not_found_base_path();
        self.serve_protection_response(&resp, path, &location, certificate)
    }

    /// Handles `POST <login_page>` (a certified query — no upgrade). Reads the
    /// presented value from the form body and returns this token's certified
    /// `302 + Set-Cookie` on success, or the certified `401` re-prompt otherwise.
    pub(super) fn serve_redeem(
        &self,
        req: &HttpRequest,
        login_page: &str,
        certificate: &[u8],
        now: u64,
    ) -> HttpResponse {
        let location = AssetPath::from(login_page).asset_hash_path_root();
        if let Some(value) = parse_form_token(req.body.as_ref()) {
            if self
                .token_index
                .get(&token_id(&value))
                .is_some_and(|&expires_at| expires_at > now)
            {
                let resp = ProtectionResponse::redeem_success(&value);
                return self.serve_protection_response(&resp, login_page, &location, certificate);
            }
        }
        let resp = ProtectionResponse::redeem_failure();
        self.serve_protection_response(&resp, login_page, &location, certificate)
    }

    // ---- state management (controller-driven) ----

    /// Removes every certified response under the login page's subtree (redeem
    /// `302`s, the `401`, and the `200` page if synced) and drops all tokens. A
    /// following recertify re-adds the `200` for a still-present asset.
    fn clear_tokens_and_login_responses(&mut self, login_page: &str) {
        // The whole login subtree (redeem 302s, the 401, the 200 page) goes in one
        // shot, so per-token cert removal isn't needed — just empty the store and
        // the (heap) access-protection index.
        self.certifier.remove_responses_for_path(login_page);
        self.store.clear_tokens();
        self.token_index.clear();
    }

    /// Turns access protection **on** with the given login page (controller-guarded at the
    /// endpoint). Enabling on a fresh canister before the first sync is the secure
    /// ordering — no window in which assets are world-readable. Idempotent if
    /// already enabled at the same page; re-pointing to a different page drops the
    /// old tokens (their redeem certs live under the old subtree). Caller
    /// publishes `certified_data` afterwards.
    pub fn enable_protection(&mut self, login_page: String) {
        let previous = self.protection_login_page();
        if previous.as_deref() == Some(login_page.as_str()) {
            return;
        }
        if let Some(old) = previous {
            self.clear_tokens_and_login_responses(&old);
        }
        self.store
            .set_protection_login_page(Some(login_page.clone()));
        self.certifier.recertify_all_assets(&self.store);
        self.on_redirect_rules_change();
        // Enable-first: if the page isn't synced yet, the asset loop didn't touch
        // it, but the redeem endpoint must still work — assert its responses.
        if !self.store.contains_asset(&login_page) {
            self.certifier
                .reassert_login_responses(&self.store, &login_page);
        }
    }

    /// Turns access protection **off** and drops all tokens, restoring a fully public app.
    /// Caller publishes `certified_data` afterwards.
    pub fn disable_protection(&mut self) {
        let Some(login_page) = self.protection_login_page() else {
            return;
        };
        self.store.set_protection_login_page(None);
        self.clear_tokens_and_login_responses(&login_page);
        self.certifier.recertify_all_assets(&self.store);
        self.on_redirect_rules_change();
    }

    /// Mints a token under `label`: stores the record (`token_id`, expiry,
    /// redeem-cert path) and the access-protection index entry (`token_id → expiry`), certifies
    /// this token's redeem response, and first sweeps expired tokens so the
    /// store/tree track only live tokens. The plaintext `value` is supplied by the
    /// caller (random or chosen) and is never stored. Errors if protection is off.
    /// Caller publishes `certified_data` afterwards.
    pub fn issue_token(
        &mut self,
        value: String,
        label: String,
        ttl_secs: u32,
        now: u64,
    ) -> Result<(), String> {
        let Some(login_page) = self.protection_login_page() else {
            return Err("protection is not enabled".to_string());
        };
        self.sweep_expired_tokens(now);
        // Labels are the unique identifier: re-issuing under an existing label
        // rotates it — drop the old token's access-protection index entry and redeem cert first.
        self.remove_token(&label);
        let expires_at = now.saturating_add((ttl_secs as u64).saturating_mul(1_000_000_000));
        let location = AssetPath::from(login_page.as_str()).asset_hash_path_root();
        let redeem_tp = self
            .certifier
            .certify_protection_response(&location, &ProtectionResponse::redeem_success(&value));
        let token_id = token_id(&value);
        self.token_index.insert(token_id, expires_at);
        self.store.insert_token(
            label,
            TokenMeta {
                token_id,
                expires_at,
                redeem_path: redeem_tp.0,
            },
        );
        Ok(())
    }

    /// Removes the token with `label` from the store and access-protection index and drops its
    /// redeem cert. No-op if absent. The single place token removal happens —
    /// shared by `revoke_token`, the rotate path of `issue_token`, and the GC
    /// sweep. O(log n).
    fn remove_token(&mut self, label: &str) {
        if let Some(meta) = self.store.remove_token(label) {
            self.token_index.remove(&meta.token_id);
            self.certifier
                .remove_response(&HashTreePath(meta.redeem_path));
        }
    }

    /// Drops every token at or past expiry. Run at the start of `issue_token` (the
    /// op that grows the store) to bound growth. The full scan here is over the
    /// rare management map, not the hot access-protection path.
    fn sweep_expired_tokens(&mut self, now: u64) {
        let expired: Vec<String> = self
            .store
            .iter_tokens()
            .filter_map(|(label, meta)| (meta.expires_at <= now).then_some(label))
            .collect();
        for label in expired {
            self.remove_token(&label);
        }
    }

    /// Revokes the token with the given label (live — the next request bearing it
    /// fails access protection). O(log n) by label. Caller publishes `certified_data`.
    pub fn revoke_token(&mut self, label: &str) {
        self.remove_token(label);
    }

    /// Live tokens (label + expiry) for the management UI. Controller-guarded at
    /// the endpoint.
    pub fn list_tokens(&self) -> Vec<TokenInfo> {
        self.store
            .iter_tokens()
            .map(|(label, meta)| TokenInfo {
                label,
                expires_at: meta.expires_at,
            })
            .collect()
    }

    /// Whether protection is off, on-and-healthy, or on-but-degraded (login page
    /// asset absent).
    pub fn check_protection_status(&self) -> ProtectionStatus {
        match self.protection_login_page() {
            None => ProtectionStatus::Disabled,
            Some(login_page) => {
                if self.store.contains_asset(&login_page) {
                    ProtectionStatus::Enabled { login_page }
                } else {
                    ProtectionStatus::EnabledLoginPageMissing { login_page }
                }
            }
        }
    }
}
