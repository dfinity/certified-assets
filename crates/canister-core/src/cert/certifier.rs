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
use std::collections::{BTreeSet, HashSet};

use super::primitives::{
    AssetKey, AssetPath, CertificateExpression, CertifiedResponses, HashTreePath, NestedTreeKey,
    response_hash,
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
    /// The fully rendered `Set-Cookie: ic_env=…` values layered onto every
    /// `text/html` response, or `None` before any env snapshot has been captured.
    /// One entry per attribute variant the snapshot is served under; see
    /// [`crate::asset::render_env_cookies`].
    /// Owned here (never stored in `meta.headers`) and recomputed on capture; the
    /// env vars themselves survive an upgrade as canister settings, so this is
    /// rebuilt from the live system API in `post_upgrade` like the rest of the
    /// tree. See [`Self::effective_headers`].
    env_cookie: Option<Vec<String>>,
    /// Rule entries known to be out of date, owed a rebuild by the next
    /// [`Self::recertification_step`]. See [`StaleRules`].
    stale_rules: StaleRules,
    /// Assets whose certified responses are out of date, owed a re-certification
    /// pass by the next [`Self::recertification_step`]: every asset after a
    /// protection toggle (which changes every effective header set), the HTML
    /// ones after an env change (the cookie). Kept set until a pass completes,
    /// so an abandoned pass is finished by the next driver.
    stale_assets: Option<AssetScope>,
    /// The re-certification in progress, if one was started and not finished.
    /// Held here rather than by whichever call drives it, so every driver — two
    /// `execute_operations` calls of one sync interleaving their steps, or a
    /// sync taking over an abandoned maintenance job — advances the same job
    /// instead of racing its own over the shared tree. Dropped by any new mark,
    /// since it was planned before that change; see [`Self::recertification_step`].
    job: Option<RecertificationStage>,
}

/// Which assets a re-certification pass covers. Ordered: `All` subsumes `Html`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetScope {
    /// Only `text/html` assets — the ones that carry the env cookie.
    Html,
    /// Every asset.
    All,
}

/// A re-certification in progress, resumable one asset or rule at a time so it
/// can be spread across messages: a pass over the stale assets (if any), then a
/// rebuild of the stale redirect rules. Driven by
/// [`Certifier::recertification_step`].
#[derive(Clone, Debug)]
enum RecertificationStage {
    /// Re-certifying the assets in `scope`, in key order, resuming strictly
    /// after `resume_after`.
    Assets {
        scope: AssetScope,
        resume_after: Option<AssetKey>,
    },
    Rules(RulesRebuild),
}

/// Which redirect-rule entries are out of date.
///
/// A sync defers rule certification to the end of each `execute_operations`
/// call rather than rebuilding every rule after every change, because a full
/// rebuild is linear in the rule count with a large constant (every leaf insert
/// rehashes its tree path) and a site with thousands of HTML pages synthesises
/// thousands of rules — far more than one message can certify. Tracking *what*
/// went stale lets the end-of-call rebuild touch only the rules that depend on
/// the keys the call changed, and step through them across messages.
struct StaleRules {
    /// The whole list must be rebuilt: the rules themselves changed, a rebuild
    /// was interrupted and left the entries in an unknown state, or none has run
    /// yet (a fresh tree lacks even the built-in 404).
    all: bool,
    /// Asset keys changed since the last rebuild. Only rules whose exact `from`
    /// (the slot an asset at that key clobbers or shadows) or whose `to` (the
    /// target an alias rule borrows its response from) is one of these depend
    /// on them.
    keys: BTreeSet<AssetKey>,
}

impl Default for StaleRules {
    fn default() -> Self {
        Self {
            all: true,
            keys: BTreeSet::new(),
        }
    }
}

/// A redirect-rule rebuild in progress, resumable one rule at a time so a
/// many-rule rebuild can be spread across messages. The rule stage of a
/// [`RecertificationStage`].
#[derive(Clone, Debug)]
struct RulesRebuild {
    /// The rule indices to rebuild, ascending, or `None` for the whole list.
    targets: Option<Vec<usize>>,
    /// Whether the rebuild touches the root `<*>` slot, which it shares with
    /// the built-in 404 (cleared before building, re-added at the end if no
    /// rule claims it).
    clears_fallback: bool,
    phase: RebuildPhase,
}

#[derive(Clone, Debug)]
enum RebuildPhase {
    /// Dropping the `n`th target's old leaves. Every old leaf goes before any
    /// new one is inserted: a rule that merely moved index certifies the very
    /// same leaves, which a later removal would otherwise delete.
    Remove(usize),
    /// Certifying the `n`th target.
    Build(usize),
    /// The built-in 404 and the protection root sibling.
    Finish,
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

    /// The rendered env cookies, if a snapshot has been captured.
    pub fn env_cookie(&self) -> Option<&[String]> {
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
        if let Some(cookies) = &self.env_cookie
            && crate::asset::is_html_content_type(&meta.content_type)
        {
            for cookie in cookies {
                headers.push(("set-cookie".to_string(), cookie.clone()));
            }
        }
        if store.protection_enabled() {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cache-control"));
            headers.push(("cache-control".to_string(), "no-store".to_string()));
        }
        headers
    }

    // ---- small tree edits used by State orchestration ----

    /// Stores the rendered env cookies without re-certifying (the caller re-certs
    /// separately). Used by `post_upgrade` before the rebuild, and by the env
    /// refresh path.
    pub fn set_env_cookie(&mut self, cookies: Vec<String>) {
        self.env_cookie = Some(cookies);
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
        let tp =
            crate::redirect::response_leaf_path(location, cert_expr.expression_hash, resp_hash);
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
        // The asset's own `<$>` slot — the same location a 200-rewrite rule to
        // this path would mirror (see `redirect::tree_location`).
        let location = AssetPath::from(key.as_str()).asset_hash_path_root();
        for (&encoding, enc) in &meta.encodings {
            self.certify_ok_leaves(
                store,
                &location,
                &effective_headers,
                &meta.content_type,
                encoding,
                enc,
            );
        }
    }

    /// Content-free per-chunk 206 certification data for a multi-chunk encoding:
    /// the shared range certificate expression plus one response hash per chunk,
    /// in chunk order. Derived from `chunk_certs` + `content_len`, so it never
    /// reads chunk bytes. Used by [`Self::certify_ok_leaves`], which places the
    /// resulting leaves at whichever tree location its caller passes (an asset's
    /// own slot or an alias's).
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

    /// Certifies the OK-family response leaves for one encoding at `location`:
    /// the 304 (empty body) always, plus either the full 200 (single-chunk) or
    /// the N×206 range leaves (multi-chunk — the 200 is delivered as reassembled
    /// 206s and never served whole, so certifying it would be dead weight).
    /// Shared by the direct-asset path ([`Self::certify_asset_encodings`]) and the
    /// 200-rewrite alias path ([`Self::build_alias_rule_entry`]) so the two always
    /// certify the *identical* leaf set — only `location` differs (an asset's own
    /// `<$>` vs the alias's `<$>`/`<*>`). Returns every leaf it certified.
    ///
    /// The 304 uses the non-range expression at every location: a conditional
    /// request short-circuits the 206 path in `build_ok_http_response`, so a
    /// matching `If-None-Match` yields a 304 regardless of chunk count.
    fn certify_ok_leaves(
        &mut self,
        store: &Store,
        location: &HashTreePath,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> Vec<HashTreePath> {
        let cert_expr = certificate_expression_for(effective_headers, encoding, &enc.sha256);
        let resp_hashes = response_hashes_for(
            effective_headers,
            content_type,
            encoding,
            &cert_expr,
            &enc.sha256,
        );

        let leaf = |expr_hash, resp_hash| {
            crate::redirect::response_leaf_path(location, expr_hash, resp_hash)
        };
        let mut leaves = vec![leaf(cert_expr.expression_hash, resp_hashes[&304])];
        if enc.num_chunks == 1 {
            leaves.push(leaf(cert_expr.expression_hash, resp_hashes[&200]));
        } else {
            let (range_cert_expr, resp_206) =
                self.range_response_certs(store, effective_headers, content_type, encoding, enc);
            leaves.extend(
                resp_206
                    .into_iter()
                    .map(|h| leaf(range_cert_expr.expression_hash, h)),
            );
        }
        for tp in &leaves {
            self.asset_hashes.certify_response_precomputed(tp);
        }
        leaves
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

    // ---- redirect rules ----

    /// Rebuild the certified-tree entries for every redirect rule, in one go.
    /// Called by the single-message paths that change what every rule certifies
    /// — an upgrade (`post_upgrade_rebuild`), the protection toggles, an env
    /// refresh, a governance commit. A sync instead marks rules stale and steps
    /// through [`Self::begin_rules_rebuild`] / [`Self::rules_rebuild_step`] so a
    /// many-rule rebuild can span messages. Caller must refresh `certified_data`
    /// after this.
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
    ///
    /// Any assets still marked stale (by an interrupted re-certification) are
    /// re-certified first.
    pub fn on_redirect_rules_change(&mut self, store: &Store) {
        self.mark_all_rules_stale();
        while self.recertification_step(store) {}
    }

    /// Whether anything is still owed re-certification — stale assets or rule
    /// entries, or a job partway through. While it is, the tree is not
    /// consistent with the stored state, so nothing may publish its root as
    /// `certified_data`.
    pub fn has_pending_work(&self) -> bool {
        self.job.is_some()
            || self.stale_assets.is_some()
            || self.stale_rules.all
            || !self.stale_rules.keys.is_empty()
    }

    /// Marks the assets in `scope` stale — and with them every rule entry, since
    /// alias rules borrow their target's effective headers.
    pub fn mark_assets_stale(&mut self, scope: AssetScope) {
        self.stale_assets = self.stale_assets.max(Some(scope));
        self.mark_all_rules_stale();
    }

    /// Does one asset or rule (or a closing step) of re-certifying whatever is
    /// stale, starting a job if none is in progress. Returns `false`, having
    /// done nothing, once nothing is stale. Each step does a bounded amount of
    /// tree work, so a caller can yield between steps; it must refresh
    /// `certified_data` once this returns `false`.
    ///
    /// The job lives on the certifier, so concurrent drivers share it. A mark
    /// made while it runs drops it (the plan predates the change — a shortened
    /// rule list would even leave it indexing past the end), and the next step
    /// plans afresh. Every entry stays marked stale until a job finishes, so a
    /// fresh plan after a dropped job covers whatever the dropped one had
    /// already torn down.
    pub fn recertification_step(&mut self, store: &Store) -> bool {
        let job = match self.job.take() {
            Some(job) => job,
            None => match self.plan_recertification(store) {
                Some(job) => job,
                None => return false,
            },
        };
        self.job = self.advance(store, job);
        true
    }

    /// Plans a re-certification of whatever is stale, or `None` if nothing is.
    fn plan_recertification(&mut self, store: &Store) -> Option<RecertificationStage> {
        match self.stale_assets {
            Some(scope) => Some(RecertificationStage::Assets {
                scope,
                resume_after: None,
            }),
            None => self
                .begin_rules_rebuild(store)
                .map(RecertificationStage::Rules),
        }
    }

    /// Advances `job` by one step and returns what is left of it.
    fn advance(
        &mut self,
        store: &Store,
        job: RecertificationStage,
    ) -> Option<RecertificationStage> {
        match job {
            RecertificationStage::Assets {
                scope,
                resume_after,
            } => {
                if let Some((key, meta)) = store.assets_from(resume_after.as_ref()).next() {
                    if scope == AssetScope::All
                        || crate::asset::is_html_content_type(&meta.content_type)
                    {
                        self.recertify_asset(store, &key, &meta);
                    }
                    return Some(RecertificationStage::Assets {
                        scope,
                        resume_after: Some(key),
                    });
                }
                // Under protection the login page's redeem responses must be
                // certified even while the page itself isn't synced (the asset
                // pass re-asserts them only for a present page).
                if let Some(login_page) = store.protection_login_page()
                    && !store.contains_asset(&login_page)
                {
                    self.reassert_login_responses(store, &login_page);
                }
                self.stale_assets = None;
                self.plan_recertification(store)
            }
            RecertificationStage::Rules(r) => self
                .rules_rebuild_step(store, r)
                .map(RecertificationStage::Rules),
        }
    }

    /// Marks every rule entry stale: the rule list itself was replaced.
    pub fn mark_all_rules_stale(&mut self) {
        self.job = None;
        self.stale_rules.all = true;
    }

    /// Marks stale the rule entries that depend on the asset at `key` — call
    /// after any change to that asset (created, deleted, content or headers).
    pub fn mark_rules_stale_for(&mut self, key: &str) {
        self.job = None;
        if !self.stale_rules.all {
            self.stale_rules.keys.insert(key.to_string());
        }
    }

    /// Plans a rebuild of the stale rule entries, or `None` if none are stale.
    ///
    /// Beyond the rules that depend on a changed key, the plan takes in every
    /// rule sharing a tree location with one of them: rules at the same location
    /// can certify identical leaves (a duplicate rule, or the protection sibling
    /// every rule at a location gets), so dropping one rule's leaves can take
    /// another's with it. A rule at the root `<*>` also clears the built-in 404
    /// there (see [`Self::on_redirect_rules_change`]), which removes every
    /// root-subtree leaf, so those are all rebuilt together.
    ///
    /// Until the rebuild finishes, every entry counts as stale, so an
    /// interrupted rebuild is redone in full by the next one.
    fn begin_rules_rebuild(&mut self, store: &Store) -> Option<RulesRebuild> {
        let rules = store.redirect_rules();
        let targets = if self.stale_rules.all || self.rule_certified_entries.len() != rules.len() {
            None
        } else {
            let keys = std::mem::take(&mut self.stale_rules.keys);
            if keys.is_empty() {
                return None;
            }
            let depends = |rule: &RedirectRule| {
                keys.contains(&rule.to)
                    || matches!(&rule.from, RulePattern::Exact(from) if keys.contains(from))
            };
            let locations: Vec<HashTreePath> =
                rules.iter().map(crate::redirect::tree_location).collect();
            let stale_locations: HashSet<&HashTreePath> = rules
                .iter()
                .zip(&locations)
                .filter(|(rule, _)| depends(rule))
                .map(|(_, location)| location)
                .collect();
            if stale_locations.is_empty() {
                return None;
            }
            Some(
                (0..rules.len())
                    .filter(|&idx| stale_locations.contains(&locations[idx]))
                    .collect::<Vec<_>>(),
            )
        };
        let clears_fallback = match &targets {
            None => true,
            Some(targets) => {
                let root = HashTreePath::not_found_base_path();
                targets
                    .iter()
                    .any(|&idx| crate::redirect::tree_location(&rules[idx]) == root)
            }
        };
        self.stale_rules.all = true;
        Some(RulesRebuild {
            targets,
            clears_fallback,
            phase: RebuildPhase::Remove(0),
        })
    }

    /// Advances `rebuild` by one rule (or its closing step) and returns what is
    /// left, or `None` once every planned entry is rebuilt. Each step does a
    /// bounded amount of tree work, so a caller can yield between steps. Caller
    /// must refresh `certified_data` once the rebuild is done.
    fn rules_rebuild_step(
        &mut self,
        store: &Store,
        mut rebuild: RulesRebuild,
    ) -> Option<RulesRebuild> {
        match rebuild.phase {
            RebuildPhase::Remove(n) => {
                let idx = match &rebuild.targets {
                    // A full rebuild drops every *old* entry, however many
                    // rules there are now.
                    None => (n < self.rule_certified_entries.len()).then_some(n),
                    Some(targets) => targets.get(n).copied(),
                };
                if let Some(idx) = idx {
                    if let Some(entry) = self.rule_certified_entries[idx].take() {
                        for tp in &entry.tree_paths {
                            self.asset_hashes.remove_response_precomputed(tp);
                        }
                    }
                    rebuild.phase = RebuildPhase::Remove(n + 1);
                } else {
                    if rebuild.targets.is_none() {
                        self.rule_certified_entries = Vec::new();
                        self.rule_certified_entries
                            .resize_with(store.redirect_rules().len(), || None);
                    }
                    // Drop any built-in 404 before rebuilding so a rule taking
                    // over `<*>` doesn't leave a stale fallback hash beside it
                    // (re-added in `Finish` if `<*>` ends up rule-free).
                    if rebuild.clears_fallback {
                        self.asset_hashes.remove_fallback_responses();
                    }
                    rebuild.phase = RebuildPhase::Build(0);
                }
            }
            RebuildPhase::Build(n) => {
                let idx = match &rebuild.targets {
                    None => (n < self.rule_certified_entries.len()).then_some(n),
                    Some(targets) => targets.get(n).copied(),
                };
                if let Some(idx) = idx {
                    let rule = &store.redirect_rules()[idx];
                    let mut entry = self.build_rule_entry(store, rule);
                    // Under protection, every certified rule location needs an
                    // unauthenticated `307 → login` sibling (its exact entry
                    // would otherwise reject the root wildcard). Tracked on the
                    // entry so the next rebuild removes it.
                    if let (Some(entry), Some(login_page)) =
                        (entry.as_mut(), store.protection_login_page())
                        && entry.location != HashTreePath::not_found_base_path()
                    {
                        let redirect = ProtectionResponse::redirect_to_login(&login_page);
                        let tp = self.certify_protection_response(&entry.location, &redirect);
                        entry.tree_paths.push(tp);
                    }
                    self.rule_certified_entries[idx] = entry;
                    rebuild.phase = RebuildPhase::Build(n + 1);
                } else {
                    rebuild.phase = RebuildPhase::Finish;
                }
            }
            RebuildPhase::Finish => {
                if !self.asset_hashes.has_fallback_response() {
                    self.certify_not_found_fallback();
                }
                // Under protection the root `<*>` carries a universal
                // `307 → login` sibling too, layered on top of the rules and the
                // built-in 404. Re-added every rebuild (it is cleared along with
                // the fallback; re-inserting an existing leaf is a no-op).
                if let Some(login_page) = store.protection_login_page() {
                    let redirect = ProtectionResponse::redirect_to_login(&login_page);
                    self.certify_protection_response(
                        &HashTreePath::not_found_base_path(),
                        &redirect,
                    );
                }
                self.stale_rules = StaleRules {
                    all: false,
                    keys: BTreeSet::new(),
                };
                return None;
            }
        }
        Some(rebuild)
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
            if status == 200 {
                // A 200-rewrite serves the target asset unchanged, so it must
                // certify the very same leaves a direct hit does — the 200/206
                // *and* the 304. Without the 304 leaf a normal browser refresh of
                // an aliased path (e.g. `/` → `/index.html`) sends `If-None-Match`,
                // is served a 304, and fails response verification. Reuse the exact
                // direct-hit certification, only at the alias location.
                tree_paths.extend(self.certify_ok_leaves(
                    store,
                    &location,
                    &effective_headers,
                    &meta.content_type,
                    encoding,
                    enc,
                ));
                continue;
            }

            // 4xx custom error page: re-certify with the override status using
            // the same headers and body the asset would serve at 200. Only
            // single-chunk encodings reach here (multi-chunk 4xx was skipped
            // above), and an error page never takes the etag/304 path.
            let cert_expr = certificate_expression_for(&effective_headers, encoding, &enc.sha256);
            let base_headers: Vec<(String, Value)> = headers_for(
                &effective_headers,
                &meta.content_type,
                encoding,
                &enc.sha256,
            )
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
            let resp_hash = response_hash(&base_headers, status, &enc.sha256).0;
            let tp = crate::redirect::response_leaf_path(
                &location,
                cert_expr.expression_hash,
                resp_hash,
            );
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
