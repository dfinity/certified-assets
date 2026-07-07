//! The certification layer: the in-memory certified-response tree plus the
//! policy that decides *what* to certify.
//!
//! [`Certifier`] owns the derived heap state that mirrors the served content —
//! the [`CertifiedResponses`] tree (`asset_hashes`), the per-rule certified
//! entries (`rule_certified_entries`), and the rendered env cookie (`env_cookie`,
//! the one input to a certified response that isn't in the [`Store`]) — and every
//! operation that mutates them: (re)certifying an asset's encodings, rebuilding
//! the redirect-rule entries + built-in 404 fallback, and the access-protection
//! siblings/redeem leaves.
//!
//! The invariant this module exists to protect is that **the leaf the canister
//! certifies is byte-identical to the response it serves**. Certification and
//! serving both funnel header derivation through [`Certifier::effective_headers`]
//! and share the same response-hash helpers in [`crate::asset`] /
//! [`crate::protection`], so the two can't drift. Keeping the whole certify side
//! in one type makes that reviewable in one place.
//!
//! It is *derived* state: nothing here is persisted. Everything is rebuilt from
//! the durable [`Store`] after an upgrade (see `State::post_upgrade_rebuild`),
//! which is why the certify ops take `&Store` rather than caching metadata. All
//! reads the store needs — asset metadata, chunk certs, redirect rules,
//! protection settings, live tokens — come in through that borrow; the `env`
//! cookie is the sole non-store input, so it lives here.
//!
//! Serving stays on [`crate::state::State`] and reaches the tree only through the
//! read accessors below (`witness_to_header*`, `rule_entry`, `root_hash`,
//! `effective_headers`), so it can produce witnesses without being able to mutate
//! the certified set.

use ic_certification::{AsHashTree, Hash};
use ic_representation_independent_hash::Value;

use super::primitives::{
    AssetKey, AssetPath, CertificateExpression, CertifiedResponses, HashTreePath, NestedTreeKey,
    RequestHash, ResponseHash, response_hash,
};
use crate::asset::{
    AssetMeta, EncodingMeta, certificate_expression_for, headers_for,
    range_certificate_expression_for, range_response_hash, response_hashes_for,
};
use crate::http::{HeaderField, HttpResponse};
use crate::protection::ProtectionResponse;
use crate::store::Store;
use wire_types::{Encoding, RedirectRule, RulePattern};

/// The certified-response tree and the policy that maintains it. See the module
/// docs for the "certified == served" invariant it protects.
#[derive(Default)]
pub struct Certifier {
    /// The in-memory tree of certified responses. Read by serving to build
    /// witnesses; written by every certify op here.
    asset_hashes: CertifiedResponses,
    /// Per-rule certified-tree entries, parallel to the stored redirect rules. A
    /// `None` slot means the rule has no certified entry — either because an
    /// asset shadows an exact rule at the same path, or because an alias rule
    /// (200/4xx) points at a target asset that doesn't exist yet.
    rule_certified_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>>,
    /// The fully rendered `Set-Cookie: ic_env=…` value layered onto every
    /// `text/html` response, or `None` before any env snapshot has been captured.
    /// Owned here (never stored in `meta.headers`) and recomputed on capture; the
    /// env vars themselves survive an upgrade as canister settings, so this is
    /// rebuilt from the live system API in `post_upgrade` like the rest of the
    /// tree. See [`Self::effective_headers`].
    env_cookie: Option<String>,
}

impl Certifier {
    // ---- read accessors (serving reaches the tree only through these) ----

    /// Root hash of the certified tree, published as `certified_data`.
    pub fn root_hash(&self) -> Hash {
        self.asset_hashes.root_hash()
    }

    /// The `IC-Certificate` header witnessing `path` (whatever is certified
    /// there, or the fallback proof), for a response served at the request URL.
    pub fn witness_to_header(&self, path: &str, certificate: &[u8]) -> HeaderField {
        self.asset_hashes.witness_to_header(path, certificate).0
    }

    /// The `IC-Certificate` header witnessing `request_path`, with `expr_path`
    /// pinned to an explicit tree `location` (a rule or protection sibling served
    /// from a `<*>` ancestor rather than the request URL's own slot).
    pub fn witness_to_header_with_location(
        &self,
        request_path: &str,
        location: &HashTreePath,
        certificate: &[u8],
    ) -> HeaderField {
        self.asset_hashes
            .witness_to_header_with_location(request_path, location, certificate)
    }

    /// The certified entry for the redirect rule at `idx`, if it has one. Backs
    /// `State::matching_rule` (the shared serve/access-protection rule scan).
    pub fn rule_entry(&self, idx: usize) -> Option<&crate::redirect::CertifiedRuleEntry> {
        self.rule_certified_entries
            .get(idx)
            .and_then(|e| e.as_ref())
    }

    /// The rendered env cookie, if a snapshot has been captured.
    pub fn env_cookie(&self) -> Option<&str> {
        self.env_cookie.as_deref()
    }

    /// The header list a response actually certifies and serves: the asset's own
    /// `meta.headers`, plus the canister-owned env cookie on `text/html` assets
    /// when a snapshot exists, plus a forced `Cache-Control: no-store` while
    /// access protection is on. The cookie is *never* stored in `meta.headers`
    /// (`_headers` remains the sole owner of that field); it is layered on here at
    /// the single point every cert/serve site funnels through, guaranteeing the
    /// certified set and the served set agree. A user's own `_headers`
    /// `Set-Cookie` coexists as a separate entry (per-asset headers are a `Vec`,
    /// not a name-keyed map, so neither overwrites the other).
    ///
    /// Under protection the `no-store` override matters because the boundary
    /// cache is cookie-blind (keys on path+range, no `Vary`): a cached `200`
    /// could be replayed to a no-token request (asset leak) or a cached
    /// `307`/`401` to an authorized user. `no-store` is certified like any other
    /// header, so an honest gateway can't strip it. Public apps
    /// (`protection == None`) are untouched.
    pub fn effective_headers(&self, store: &Store, meta: &AssetMeta) -> Vec<(String, String)> {
        let mut headers = meta.headers.clone();
        if let Some(cookie) = &self.env_cookie
            && crate::asset::is_html_content_type(&meta.content_type)
        {
            headers.push(("set-cookie".to_string(), cookie.clone()));
        }
        if store.protection_enabled() {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cache-control"));
            headers.push(("cache-control".to_string(), "no-store".to_string()));
        }
        headers
    }

    // ---- small tree edits used by State orchestration ----

    /// Stores the rendered env cookie without re-certifying (the caller re-certs
    /// separately). Used by `post_upgrade` before the rebuild, and by the env
    /// refresh path.
    pub fn set_env_cookie(&mut self, cookie: String) {
        self.env_cookie = Some(cookie);
    }

    /// Removes every certified response under `path`'s subtree.
    pub fn remove_responses_for_path(&mut self, path: &str) {
        self.asset_hashes.remove_responses_for_path(path);
    }

    /// Removes one precomputed certified response (e.g. a revoked token's redeem
    /// leaf).
    pub fn remove_response(&mut self, tp: &HashTreePath) {
        self.asset_hashes.remove_response_precomputed(tp);
    }

    /// Certifies one [`ProtectionResponse`] as a response-only leaf at `location`
    /// (an asset `<$>`, a rule `<$>`/`<*>`, or the root `<*>`). Returns the leaf's
    /// `HashTreePath` so per-token redeem leaves can be stored for later removal.
    pub fn certify_protection_response(
        &mut self,
        location: &HashTreePath,
        resp: &ProtectionResponse,
    ) -> HashTreePath {
        let cert_expr = resp.cert_expr();
        let resp_hash = resp.response_hash();
        let tp = crate::redirect::alias_tree_path(location, cert_expr.expression_hash, resp_hash);
        self.asset_hashes.certify_response_precomputed(&tp);
        tp
    }

    // ---- asset (re)certification ----

    /// Removes and recomputes every certified response for one asset from its
    /// metadata. Recompute is cheap: it reads only headers/content_type/sha256,
    /// never content bytes.
    pub fn recertify_asset(&mut self, store: &Store, key: &AssetKey, meta: &AssetMeta) {
        self.asset_hashes.remove_responses_for_path(key);
        if !meta.encodings.is_empty() {
            self.certify_asset_encodings(store, key, meta);
        }

        // Access protection: this path may also carry its certified
        // unauthenticated sibling — or, for the login page itself, its redeem
        // responses (which share this subtree and were wiped above).
        if let Some(login_page) = store.protection_login_page() {
            if key.as_str() == login_page {
                self.reassert_login_responses(store, &login_page);
            } else {
                self.certify_unauth_sibling(key, meta, &login_page);
            }
        }
    }

    /// Re-certifies every asset from its metadata. Shared by the protection
    /// toggles and `post_upgrade_rebuild`.
    pub fn recertify_all_assets(&mut self, store: &Store) {
        let keys = store.asset_keys();
        for key in keys {
            if let Some(meta) = store.get_asset(&key) {
                self.recertify_asset(store, &key, &meta);
            }
        }
    }

    /// Certifies the 200/304 (single-chunk) or N×206 (multi-chunk) responses for
    /// every encoding of an asset. Split out of [`Self::recertify_asset`] so the
    /// access-protection tail there runs even for a content-less asset.
    fn certify_asset_encodings(&mut self, store: &Store, key: &AssetKey, meta: &AssetMeta) {
        let effective_headers = self.effective_headers(store, meta);
        let path = AssetPath::from(key.as_str());
        for (&encoding, enc) in &meta.encodings {
            let cert_expr = certificate_expression_for(&effective_headers, encoding, &enc.sha256);
            let response_hashes = response_hashes_for(
                &effective_headers,
                &meta.content_type,
                encoding,
                &cert_expr,
                &enc.sha256,
            );
            // Always certify the 304 (empty body). Certify the full 200 only for
            // single-chunk encodings — a multi-chunk asset is served as N×206 (the
            // gateway reassembles them into a 200), so a full 200 is never served
            // and certifying it would be dead weight in the tree.
            let hash_304 = path.hash_tree_path(
                &cert_expr,
                &RequestHash::default(),
                ResponseHash::from(&response_hashes[&304]),
            );
            self.asset_hashes.certify_response_precomputed(&hash_304);
            if enc.num_chunks == 1 {
                let hash_200 = path.hash_tree_path(
                    &cert_expr,
                    &RequestHash::default(),
                    ResponseHash::from(&response_hashes[&200]),
                );
                self.asset_hashes.certify_response_precomputed(&hash_200);
            } else {
                // Multi-chunk: certify one 206 per chunk (response-only).
                let (range_cert_expr, resp_hashes) = self.range_response_certs(
                    store,
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    enc,
                );
                for resp_hash in resp_hashes {
                    let hash_path = path.hash_tree_path(
                        &range_cert_expr,
                        &RequestHash::default(),
                        ResponseHash::from(&resp_hash),
                    );
                    self.asset_hashes.certify_response_precomputed(&hash_path);
                }
            }
        }
    }

    /// Content-free per-chunk 206 certification data for a multi-chunk encoding:
    /// the shared range certificate expression plus one response hash per chunk,
    /// in chunk order. Derived from `chunk_certs` + `content_len`, so it never
    /// reads chunk bytes. Both the direct-asset path (`certify_asset_encodings`)
    /// and the alias path (`build_alias_rule_entry`) use it, each placing the
    /// resulting leaves at its own tree location.
    fn range_response_certs(
        &self,
        store: &Store,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> (CertificateExpression, Vec<[u8; 32]>) {
        let range_cert_expr =
            range_certificate_expression_for(effective_headers, encoding, &enc.sha256);
        let total = enc.content_len;
        let chunk_infos: Vec<(u32, [u8; 32])> = store
            .chunk_certs_of(enc.content_id)
            .map(|(_, cc)| (cc.len, cc.sha256))
            .collect();
        let mut resp_hashes = Vec::with_capacity(chunk_infos.len());
        let mut offset: u64 = 0;
        for (len, sha256) in chunk_infos {
            let len = len as u64;
            let content_range = format!("bytes {}-{}/{}", offset, offset + len - 1, total);
            resp_hashes.push(range_response_hash(
                effective_headers,
                content_type,
                encoding,
                &enc.sha256,
                &content_range,
                &sha256,
            ));
            offset += len;
        }
        (range_cert_expr, resp_hashes)
    }

    // ---- access-protection certify helpers ----

    /// Certifies the unauthenticated sibling for a protected asset path: a
    /// `307 → <login_page>` for HTML (humans navigate to documents) or a `401`
    /// for anything else (a redirect would hand a subresource the wrong content
    /// type).
    fn certify_unauth_sibling(&mut self, key: &AssetKey, meta: &AssetMeta, login_page: &str) {
        let resp = if crate::asset::is_html_content_type(&meta.content_type) {
            ProtectionResponse::redirect_to_login(login_page)
        } else {
            ProtectionResponse::unauthorized()
        };
        let location = AssetPath::from(key.as_str()).asset_hash_path_root();
        self.certify_protection_response(&location, &resp);
    }

    /// (Re)certifies the login page's `POST` responses: the shared redeem-failure
    /// `401` plus each live token's `302 + Set-Cookie` redeem response. The `200`
    /// page comes from the sync at the same subtree, so this must run whenever
    /// that subtree is rebuilt (and on upgrade). Token redeem leaves are
    /// re-inserted from their stored paths — no plaintext needed.
    pub fn reassert_login_responses(&mut self, store: &Store, login_page: &str) {
        let location = AssetPath::from(login_page).asset_hash_path_root();
        self.certify_protection_response(&location, &ProtectionResponse::redeem_failure());
        let paths: Vec<Vec<NestedTreeKey>> = store
            .iter_tokens()
            .map(|(_, meta)| meta.redeem_path)
            .collect();
        for path in paths {
            self.asset_hashes
                .certify_response_precomputed(&HashTreePath(path));
        }
    }

    /// Adds the protection layer's redirect-rule siblings after a rule rebuild:
    /// the universal root `<*>` `307 → login`, plus a `307` at every non-root rule
    /// location (whose exact entry would otherwise reject the root wildcard). The
    /// per-rule siblings are tracked on the rule entry so the next rebuild removes
    /// them; the root one is re-added each rebuild (cleared by
    /// `remove_fallback_responses`). Only called while protection is on.
    fn certify_rule_unauth_siblings(&mut self, login_page: &str) {
        let redirect = ProtectionResponse::redirect_to_login(login_page);
        let root = HashTreePath::not_found_base_path();
        self.certify_protection_response(&root, &redirect);
        for idx in 0..self.rule_certified_entries.len() {
            let Some(location) = self
                .rule_certified_entries
                .get(idx)
                .and_then(|e| e.as_ref())
                .map(|e| e.location.clone())
            else {
                continue;
            };
            if location.0 == root.0 {
                continue; // root <*> already covered by the universal sibling
            }
            let tp = self.certify_protection_response(&location, &redirect);
            if let Some(entry) = self.rule_certified_entries[idx].as_mut() {
                entry.tree_paths.push(tp);
            }
        }
    }

    // ---- redirect rules ----

    /// Rebuild the certified-tree entries for the redirect rules. Called whenever
    /// the rule list changes (in `execute_operations`) or assets are restored
    /// from stable memory (in `post_upgrade_rebuild`). Caller must refresh
    /// `certified_data` after this.
    ///
    /// Status-200 rules borrow each encoding's certificate expression and
    /// response hash from the target asset, so this also has to run after any
    /// asset change that could affect those values.
    ///
    /// This is also the single owner of the root `<*>` fallback slot: a root `/*`
    /// rule and the built-in 404 are mutually exclusive occupants of it, so after
    /// rebuilding the rules we (re)certify the built-in 404 exactly when no active
    /// rule claims `<*>`. That keeps `build_http_response`'s fallthrough certified
    /// — the gateway rejects uncertified responses, so an uncertified fallback 404
    /// would be unservable.
    pub fn on_redirect_rules_change(&mut self, store: &Store) {
        for entry in self.rule_certified_entries.drain(..).flatten() {
            for tp in &entry.tree_paths {
                self.asset_hashes.remove_response_precomputed(tp);
            }
        }
        // Drop any built-in 404 before rebuilding so a rule taking over `<*>`
        // doesn't leave a stale fallback hash beside it (and removing it now is
        // safe — we re-add below if `<*>` ends up rule-free).
        self.asset_hashes.remove_fallback_responses();

        let rules = store.redirect_rules().to_vec();
        let mut new_entries: Vec<Option<crate::redirect::CertifiedRuleEntry>> =
            Vec::with_capacity(rules.len());
        for rule in &rules {
            new_entries.push(self.build_rule_entry(store, rule));
        }
        self.rule_certified_entries = new_entries;

        if !self.asset_hashes.has_fallback_response() {
            self.certify_not_found_fallback();
        }

        // Under protection, every certified path needs an unauthenticated sibling
        // (and a universal root `<*>` fallback) so access protection can serve a
        // verifiable 307/401 there. Added after the rules + built-in 404 so it layers on top.
        if let Some(login_page) = store.protection_login_page() {
            self.certify_rule_unauth_siblings(&login_page);
        }
    }

    /// Certifies the canister's built-in last-resort 404 ("not found") at the
    /// root `<*>` fallback path. Callers must ensure `<*>` is otherwise free;
    /// `on_redirect_rules_change` is the only caller and guarantees that.
    fn certify_not_found_fallback(&mut self) {
        let response = HttpResponse::uncertified_404();
        let headers: Vec<_> = response
            .headers
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
        self.asset_hashes.certify_fallback_response(
            response.status_code,
            &headers,
            &response.body,
            None,
        );
    }

    fn build_rule_entry(
        &mut self,
        store: &Store,
        rule: &RedirectRule,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        if let RulePattern::Exact(src) = &rule.from
            && store.contains_asset(src)
        {
            // Asset at the source path shadows the rule.
            return None;
        }
        match rule.status {
            // 200 rewrites and 4xx custom error pages both borrow body + headers
            // from the target asset (4xx re-certifies with the override status;
            // see `build_alias_rule_entry`).
            200 | 404 | 410 => self.build_alias_rule_entry(store, rule, rule.status),
            // 3xx redirects synthesize an empty body; only the headers
            // (content-type, Location) are certified.
            _ => {
                let entry = crate::redirect::build_synthetic_entry(rule);
                for tp in &entry.tree_paths {
                    self.asset_hashes.certify_response_precomputed(tp);
                }
                Some(entry)
            }
        }
    }

    fn build_alias_rule_entry(
        &mut self,
        store: &Store,
        rule: &RedirectRule,
        status: u16,
    ) -> Option<crate::redirect::CertifiedRuleEntry> {
        let target_key = rule.to.clone();
        let meta = store.get_asset(&target_key)?;
        // Mirror the target asset's effective headers (incl. the env cookie on
        // an HTML target) so the alias reuses the same certified response the
        // direct hit / serve path produces.
        let effective_headers = self.effective_headers(store, &meta);
        let location = crate::redirect::tree_location(rule);
        let mut tree_paths = Vec::new();
        for (&encoding, enc) in &meta.encodings {
            // A 4xx custom error page is served as a single inline body with the
            // override status — 206 reassembly always yields a 200, so a
            // multi-chunk encoding can't carry it. Mirror the serve-side
            // `acceptable` filter and skip such encodings; certifying them here
            // would leave an unservable leaf the serve path never reproduces (it
            // falls back to the built-in 404), so the gateway would reject the
            // mismatched response. If *every* encoding is multi-chunk the rule
            // gets no leaves and goes inert (built-in 404 fallthrough). The sync
            // op guard rejects this combination up front; this keeps the
            // certified tree sound even if some other caller slips it through.
            if status != 200 && enc.num_chunks > 1 {
                continue;
            }
            let cert_expr = certificate_expression_for(&effective_headers, encoding, &enc.sha256);

            // A 200-rewrite to a multi-chunk target serves N×206 (the gateway
            // reassembles them into a 200), exactly like a direct hit. Certify
            // those 206 leaves at the alias location and move on.
            if status == 200 && enc.num_chunks > 1 {
                let (range_cert_expr, resp_hashes) = self.range_response_certs(
                    store,
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    enc,
                );
                for resp_hash in resp_hashes {
                    let tp = crate::redirect::alias_tree_path(
                        &location,
                        range_cert_expr.expression_hash,
                        resp_hash,
                    );
                    self.asset_hashes.certify_response_precomputed(&tp);
                    tree_paths.push(tp);
                }
                continue;
            }

            let resp_hash = if status == 200 {
                // The encoding's already-certified 200 response hash.
                response_hashes_for(
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    &cert_expr,
                    &enc.sha256,
                )[&200]
            } else {
                // 4xx custom error page: re-certify with the override status
                // using the same headers and body the asset would serve at 200.
                let base_headers: Vec<(String, Value)> = headers_for(
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    &enc.sha256,
                )
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
                response_hash(&base_headers, status, &enc.sha256).0
            };
            let tp =
                crate::redirect::alias_tree_path(&location, cert_expr.expression_hash, resp_hash);
            self.asset_hashes.certify_response_precomputed(&tp);
            tree_paths.push(tp);
        }
        if tree_paths.is_empty() {
            return None;
        }
        Some(crate::redirect::CertifiedRuleEntry {
            tree_paths,
            location,
            kind: crate::redirect::CertifiedRuleEntryKind::AliasOf { target_key, status },
        })
    }
}
