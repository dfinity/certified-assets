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
//! read accessors below (`witness_to_header*`, `rule_entry`, `served_rules`,
//! `served_login_page`, `served_headers`, `root_hash`), so it can produce
//! witnesses without being able to mutate the certified set.
//!
//! ## Working state and the published snapshot
//!
//! Re-certifying a large site takes many messages, and between them the tree
//! is half-updated. So the certifier keeps two copies:
//!
//! - the **working** state — the tree, rule entries and env cookie that every
//!   certify op and staged re-certification step mutates;
//! - the **published** snapshot ([`Published`]) — what serving reads, and whose
//!   root is `certified_data`. It holds not just the tree but every input a
//!   certified response depends on that can change ahead of the tree: the rule
//!   list its rule entries index, the env cookie and the protection login page.
//!
//! [`Certifier::publish`] is the only thing that changes the snapshot, and it
//! does so only when nothing is owed re-certification. So **serving always
//! reads a complete tree together with the exact inputs it was built from**,
//! and `certified_data` may be set to [`Certifier::root_hash`] at any time. A
//! re-certification that is slow, interrupted or abandoned only delays the
//! next publish; it never makes a served response unverifiable. Finishing such
//! work is a liveness concern, handled by whoever drives the next step.
//!
//! The snapshot does not cover asset content, which serving reads from the
//! [`Store`]: an asset a sync just rewrote fails verification until the
//! publish at the end of that `execute_operations` call, as it always has.

use ic_certification::{AsHashTree, Hash};
use ic_representation_independent_hash::Value;
use std::collections::{BTreeSet, HashMap, HashSet};

use super::primitives::{
    AssetKey, AssetPath, CertifiedResponses, HashTreePath, NestedTreeKey, fallback_response_path,
    response_hash,
};
use crate::asset::{
    AssetMeta, EncodingMeta, certificate_expression_for, headers_for,
    range_certificate_expression_for, range_response_hash, response_hashes_for,
};
use crate::http::{HeaderField, HttpResponse};
use crate::protection::ProtectionResponse;
use crate::redirect::CertifiedRuleEntry;
use crate::store::Store;
use wire_types::{Encoding, RedirectRule, RulePattern};

/// The certified-response tree and the policy that maintains it. See the module
/// docs for the "certified == served" invariant it protects, and for the
/// working/published split.
#[derive(Default)]
pub struct Certifier {
    /// The working tree of certified responses, written by every certify op
    /// here. Serving never reads it: it reads [`Published::tree`].
    asset_hashes: CertifiedResponses,
    /// Per-rule certified-tree entries, parallel to the stored redirect rules. A
    /// `None` slot means the rule has no certified entry — either because an
    /// asset shadows an exact rule at the same path, or because an alias rule
    /// (200/4xx) points at a target asset that doesn't exist yet.
    rule_certified_entries: Vec<Option<CertifiedRuleEntry>>,
    /// The leaves at the root `<*>` that belong to no rule: the built-in 404
    /// (while no rule claims `<*>`) and, under protection, the universal
    /// `307 → login` sibling. Recorded so a rule rebuild retracts exactly them.
    fallback_leaves: Vec<HashTreePath>,
    /// The fully rendered `Set-Cookie: ic_env=…` values layered onto every
    /// `text/html` response, or `None` before any env snapshot has been captured.
    /// One entry per attribute variant the snapshot is served under; see
    /// [`crate::asset::render_env_cookies`].
    /// Owned here (never stored in `meta.headers`) and recomputed on capture; the
    /// env vars themselves survive an upgrade as canister settings, so this is
    /// rebuilt from the live system API in `post_upgrade` like the rest of the
    /// tree. See [`Self::effective_headers`].
    env_cookie: Option<Vec<String>>,
    /// The OK-family leaves last computed for each asset encoding, with the
    /// inputs they were computed from. A 200-rewrite rule certifies the very
    /// leaves its target does (only the tree location differs), so it reuses
    /// these instead of re-hashing; see [`Self::ok_leaf_hashes`].
    ok_leaves: HashMap<AssetKey, Vec<(Encoding, OkLeaves)>>,
    /// Rule entries known to be out of date, owed a rebuild by the next
    /// [`Self::recertification_step`]. See [`StaleRules`].
    stale_rules: StaleRules,
    /// Assets whose certified responses are out of date, owed a re-certification
    /// pass by the next [`Self::recertification_step`]: every asset after a
    /// protection toggle (which changes every effective header set), the HTML
    /// ones after an env change (the cookie). Kept set until a pass completes.
    stale_assets: Option<AssetScope>,
    /// The re-certification in progress, if one was started and not finished.
    /// Held here rather than by whichever call drives it, so every driver — two
    /// `execute_operations` calls of one sync interleaving their steps, or a
    /// sync taking over an abandoned maintenance job — advances the same job
    /// instead of racing its own over the shared tree. See
    /// [`Self::recertification_step`] for when a new mark drops it.
    job: Option<RecertificationStage>,
    /// What serving reads. See the module docs.
    published: Published,
    /// Whether the working state may differ from [`Self::published`]. Set by
    /// every mutating method, cleared by [`Self::publish`], so a publish with
    /// nothing new to publish costs nothing.
    dirty: bool,
}

/// The certified state serving reads: a complete tree and every input its
/// responses were certified with. Replaced whole by [`Certifier::publish`].
#[derive(Default)]
struct Published {
    tree: CertifiedResponses,
    rule_entries: Vec<Option<CertifiedRuleEntry>>,
    /// The redirect rules `rule_entries` is parallel to.
    rules: Vec<RedirectRule>,
    env_cookie: Option<Vec<String>>,
    /// The access-protection login page, or `None` while protection is off.
    login_page: Option<String>,
}

/// One encoding's OK-family leaf hashes (see [`Certifier::certify_ok_leaves`])
/// and the inputs they were derived from. Reusable only while every input
/// matches.
struct OkLeaves {
    effective_headers: Vec<(String, String)>,
    content_type: String,
    sha256: [u8; 32],
    num_chunks: u32,
    content_id: u64,
    /// `(expression hash, response hash)` per leaf, in certification order.
    hashes: Vec<([u8; 32], [u8; 32])>,
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
#[derive(Debug)]
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
#[derive(Debug)]
struct StaleRules {
    /// The whole list must be rebuilt: the rules themselves changed, or none
    /// has been built yet (a fresh tree lacks even the built-in 404).
    all: bool,
    /// Asset keys changed since the last rebuild. Only rules whose exact `from`
    /// (the slot an asset at that key clobbers or shadows) or whose `to` (the
    /// target an alias rule borrows its response from) is one of these depend
    /// on them.
    keys: BTreeSet<AssetKey>,
}

impl StaleRules {
    fn none() -> Self {
        Self {
            all: false,
            keys: BTreeSet::new(),
        }
    }

    fn is_empty(&self) -> bool {
        !self.all && self.keys.is_empty()
    }

    fn merge(&mut self, other: StaleRules) {
        self.all |= other.all;
        if self.all {
            self.keys.clear();
        } else {
            self.keys.extend(other.keys);
        }
    }
}

impl Default for StaleRules {
    fn default() -> Self {
        Self {
            all: true,
            keys: BTreeSet::new(),
        }
    }
}

/// A redirect-rule rebuild in progress, resumable one rule or leaf at a time so
/// a many-rule rebuild can be spread across messages. The rule stage of a
/// [`RecertificationStage`].
///
/// It runs in two phases. [`RebuildPhase::Build`] computes every planned
/// rule's new entry *off-tree*; nothing certified changes, so a new mark may
/// simply drop the job and hand its marks back. [`RebuildPhase::Apply`] then
/// edits the tree by difference — retracting the old leaves that no new entry
/// keeps, then certifying the new leaves not already present — so a rebuild
/// that changes little costs little. Once applying has begun the job runs to
/// completion (new marks wait for the next one): its plan is fixed by then and
/// no longer reads the rule list.
#[derive(Debug)]
struct RulesRebuild {
    /// The rule indices to rebuild, ascending, or `None` for the whole list.
    targets: Option<Vec<usize>>,
    /// The rule count when planned: the length of the entry list a whole-list
    /// rebuild installs.
    rule_count: usize,
    /// Whether the rebuild covers the root `<*>`, which it shares with the
    /// built-in 404 and the protection root sibling ([`Certifier::fallback_leaves`]).
    clears_fallback: bool,
    /// The marks this job took on, handed back if it is dropped while building.
    taken: StaleRules,
    phase: RebuildPhase,
}

#[derive(Debug)]
enum RebuildPhase {
    /// Computing the `n`th target's new entry, off-tree.
    Build {
        n: usize,
        built: Vec<Option<CertifiedRuleEntry>>,
    },
    /// Editing the tree: retracting `remove[..]` from `next`, then certifying
    /// `insert[..]` from `next - remove.len()`.
    Apply {
        built: Vec<Option<CertifiedRuleEntry>>,
        fallback: Vec<HashTreePath>,
        remove: Vec<HashTreePath>,
        insert: Vec<HashTreePath>,
        next: usize,
    },
}

impl Certifier {
    // ---- read accessors (serving reaches the tree only through these) ----
    //
    // Everything here reads the published snapshot, never the working state.

    /// Root hash of the published tree — always safe to set as `certified_data`.
    pub fn root_hash(&self) -> Hash {
        self.published.tree.root_hash()
    }

    /// The `IC-Certificate` header witnessing `path` (whatever is certified
    /// there, or the fallback proof), for a response served at the request URL.
    pub fn witness_to_header(&self, path: &str, certificate: &[u8]) -> HeaderField {
        self.published.tree.witness_to_header(path, certificate).0
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
        self.published
            .tree
            .witness_to_header_with_location(request_path, location, certificate)
    }

    /// The redirect rules serving matches against, in declaration order: the
    /// list the published rule entries were built from.
    pub fn served_rules(&self) -> &[RedirectRule] {
        &self.published.rules
    }

    /// The published certified entry for the `idx`th of [`Self::served_rules`],
    /// if it has one. Backs `State::matching_rule` (the shared
    /// serve/access-protection rule scan).
    pub fn rule_entry(&self, idx: usize) -> Option<&CertifiedRuleEntry> {
        self.published
            .rule_entries
            .get(idx)
            .and_then(|e| e.as_ref())
    }

    /// The access-protection login page the published tree was certified
    /// under, or `None` if it was certified public. Serving enforces protection
    /// from this, not from the stored setting, so a toggle takes effect exactly
    /// when its re-certified tree is published.
    pub fn served_login_page(&self) -> Option<&str> {
        self.published.login_page.as_deref()
    }

    /// Whether `resp` is certified at `location` in the published tree, so
    /// serving it would verify.
    pub fn serves_protection_response(
        &self,
        location: &HashTreePath,
        resp: &ProtectionResponse,
    ) -> bool {
        self.published
            .tree
            .contains_leaf(protection_leaf(location, resp).as_vec())
    }

    /// The header list a response is served with — [`Self::effective_headers`]
    /// under the published env cookie and protection setting.
    pub fn served_headers(&self, meta: &AssetMeta) -> Vec<(String, String)> {
        layer_headers(
            meta,
            self.published.env_cookie.as_deref(),
            self.published.login_page.is_some(),
        )
    }

    /// The rendered env cookies of the working state, if a snapshot has been
    /// captured.
    pub fn env_cookie(&self) -> Option<&[String]> {
        self.env_cookie.as_deref()
    }

    /// The header list a response certifies: the asset's own `meta.headers`,
    /// plus the canister-owned env cookie on `text/html` assets when a snapshot
    /// exists, plus a forced `Cache-Control: no-store` while access protection
    /// is on. The cookie is *never* stored in `meta.headers` (`_headers` remains
    /// the sole owner of that field); it is layered on here at the single point
    /// every cert site funnels through — and serving through
    /// [`Self::served_headers`], the same layering under the published inputs —
    /// guaranteeing the certified set and the served set agree. A user's own
    /// `_headers` `Set-Cookie` coexists as a separate entry (per-asset headers
    /// are a `Vec`, not a name-keyed map, so neither overwrites the other).
    ///
    /// Under protection the `no-store` override matters because the boundary
    /// cache is cookie-blind (keys on path+range, no `Vary`): a cached `200`
    /// could be replayed to a no-token request (asset leak) or a cached
    /// `307`/`401` to an authorized user. `no-store` is certified like any other
    /// header, so an honest gateway can't strip it. Public apps
    /// (`protection == None`) are untouched.
    fn effective_headers(&self, store: &Store, meta: &AssetMeta) -> Vec<(String, String)> {
        layer_headers(meta, self.env_cookie.as_deref(), store.protection_enabled())
    }

    /// Every leaf of the published tree, in key order. Unlike
    /// [`Self::root_hash`] this doesn't depend on the order the leaves were
    /// inserted in (the tree's shape does), so it compares an incrementally
    /// maintained tree with one built from scratch.
    #[cfg(test)]
    pub fn published_leaves(&self) -> Vec<Vec<NestedTreeKey>> {
        self.published.tree.leaf_paths()
    }

    // ---- publication ----

    /// Publishes the working state for serving, if it is complete — nothing
    /// stale, no job in flight — and changed since the last publish. Returns
    /// whether it published. The caller sets `certified_data` to
    /// [`Self::root_hash`] (which is correct whether or not this published).
    ///
    /// The rule list and login page are taken from `store`: with nothing
    /// pending, the working rule entries were built from exactly these.
    pub fn publish(&mut self, store: &Store) -> bool {
        if !self.dirty || self.has_pending_work() {
            return false;
        }
        self.published = Published {
            tree: self.asset_hashes.clone(),
            rule_entries: self.rule_certified_entries.clone(),
            rules: store.redirect_rules().to_vec(),
            env_cookie: self.env_cookie.clone(),
            login_page: store.protection_login_page(),
        };
        self.dirty = false;
        true
    }

    // ---- small tree edits used by State orchestration ----

    /// Stores the rendered env cookies without re-certifying (the caller re-certs
    /// separately). Used by `post_upgrade` before the rebuild, and by the env
    /// refresh path.
    pub fn set_env_cookie(&mut self, cookies: Vec<String>) {
        self.dirty = true;
        self.env_cookie = Some(cookies);
    }

    /// Removes every certified response under `path`'s subtree.
    pub fn remove_responses_for_path(&mut self, path: &str) {
        self.dirty = true;
        self.asset_hashes.remove_responses_for_path(path);
        self.ok_leaves.remove(path);
    }

    /// Removes one precomputed certified response (e.g. a revoked token's redeem
    /// leaf).
    pub fn remove_response(&mut self, tp: &HashTreePath) {
        self.dirty = true;
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
        self.dirty = true;
        let tp = protection_leaf(location, resp);
        self.asset_hashes.certify_response_precomputed(&tp);
        tp
    }

    // ---- asset (re)certification ----

    /// Removes and recomputes every certified response for one asset from its
    /// metadata. Recompute is cheap: it reads only headers/content_type/sha256,
    /// never content bytes.
    pub fn recertify_asset(&mut self, store: &Store, key: &AssetKey, meta: &AssetMeta) {
        self.dirty = true;
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
            for tp in self.ok_leaves(
                store,
                key,
                &location,
                &effective_headers,
                &meta.content_type,
                encoding,
                enc,
            ) {
                self.asset_hashes.certify_response_precomputed(&tp);
            }
        }
    }

    /// Content-free per-chunk 206 certification data for a multi-chunk encoding:
    /// the shared range certificate expression hash plus one response hash per
    /// chunk, in chunk order. Derived from `chunk_certs` + `content_len`, so it
    /// never reads chunk bytes.
    fn range_response_certs(
        store: &Store,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
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
        (range_cert_expr.expression_hash, resp_hashes)
    }

    /// The OK-family response leaves for one encoding of the asset at `source`,
    /// placed at `location`: the 304 (empty body) always, plus either the full
    /// 200 (single-chunk) or the N×206 range leaves (multi-chunk — the 200 is
    /// delivered as reassembled 206s and never served whole, so certifying it
    /// would be dead weight). Computes the leaves without certifying them.
    ///
    /// Shared by the direct-asset path ([`Self::certify_asset_encodings`]) and
    /// the 200-rewrite alias path ([`Self::build_alias_rule_entry`]) so the two
    /// always certify the *identical* leaf set — only `location` differs (an
    /// asset's own `<$>` vs the alias's `<$>`/`<*>`).
    ///
    /// The 304 uses the non-range expression at every location: a conditional
    /// request short-circuits the 206 path in `build_ok_http_response`, so a
    /// matching `If-None-Match` yields a 304 regardless of chunk count.
    #[allow(clippy::too_many_arguments)]
    fn ok_leaves(
        &mut self,
        store: &Store,
        source: &AssetKey,
        location: &HashTreePath,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> Vec<HashTreePath> {
        self.ok_leaf_hashes(
            store,
            source,
            effective_headers,
            content_type,
            encoding,
            enc,
        )
        .iter()
        .map(|&(expr_hash, resp_hash)| {
            crate::redirect::response_leaf_path(location, expr_hash, resp_hash)
        })
        .collect()
    }

    /// The `(expression hash, response hash)` pairs behind [`Self::ok_leaves`],
    /// reused from the last computation for this asset encoding when every
    /// input is unchanged. A rule rebuild re-derives each 200-rewrite's leaves,
    /// and they are exactly its target's, which the target's own
    /// certification just computed.
    fn ok_leaf_hashes(
        &mut self,
        store: &Store,
        source: &AssetKey,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> &[([u8; 32], [u8; 32])] {
        let cached = self.ok_leaves.entry(source.clone()).or_default();
        let idx = match cached.iter().position(|(e, _)| *e == encoding) {
            Some(idx) => idx,
            None => {
                cached.push((encoding, OkLeaves::placeholder()));
                cached.len() - 1
            }
        };
        let slot = &mut cached[idx].1;
        if !slot.matches(effective_headers, content_type, enc) {
            *slot = OkLeaves {
                effective_headers: effective_headers.to_vec(),
                content_type: content_type.to_string(),
                sha256: enc.sha256,
                num_chunks: enc.num_chunks,
                content_id: enc.content_id,
                hashes: Self::compute_ok_leaf_hashes(
                    store,
                    effective_headers,
                    content_type,
                    encoding,
                    enc,
                ),
            };
        }
        &slot.hashes
    }

    fn compute_ok_leaf_hashes(
        store: &Store,
        effective_headers: &[(String, String)],
        content_type: &str,
        encoding: Encoding,
        enc: &EncodingMeta,
    ) -> Vec<([u8; 32], [u8; 32])> {
        let cert_expr = certificate_expression_for(effective_headers, encoding, &enc.sha256);
        let resp_hashes = response_hashes_for(
            effective_headers,
            content_type,
            encoding,
            &cert_expr,
            &enc.sha256,
        );
        let mut hashes = vec![(cert_expr.expression_hash, resp_hashes[&304])];
        if enc.num_chunks == 1 {
            hashes.push((cert_expr.expression_hash, resp_hashes[&200]));
        } else {
            let (range_expr_hash, resp_206) =
                Self::range_response_certs(store, effective_headers, content_type, encoding, enc);
            hashes.extend(resp_206.into_iter().map(|h| (range_expr_hash, h)));
        }
        hashes
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
        self.dirty = true;
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

    /// Rebuilds the certified-tree entries for every redirect rule, in one go.
    /// Called by the single-message paths that change what every rule certifies
    /// — an upgrade (`post_upgrade_rebuild`) and a governance commit. A sync
    /// instead marks rules stale and lets [`Self::recertification_step`] spread
    /// the rebuild across messages.
    ///
    /// Status-200 rules borrow each encoding's certificate expression and
    /// response hash from the target asset, so a rule rebuild must also follow
    /// any change to a target asset — which marking does.
    ///
    /// A rebuild also certifies the canister's built-in 404 at the root `<*>`
    /// whenever no rule claims `<*>`. That keeps `build_http_response`'s
    /// fallthrough certified — the gateway rejects uncertified responses, so an
    /// uncertified fallback 404 would be unservable.
    ///
    /// Anything else still stale (an unfinished job's leftovers) is finished
    /// too.
    pub fn on_redirect_rules_change(&mut self, store: &Store) {
        self.mark_all_rules_stale();
        while self.recertification_step(store) {}
    }

    /// Whether anything is still owed re-certification — stale assets or rule
    /// entries, or a job partway through. While it is, [`Self::publish`] does
    /// nothing.
    pub fn has_pending_work(&self) -> bool {
        self.job.is_some() || self.stale_assets.is_some() || !self.stale_rules.is_empty()
    }

    /// Whether an earlier driver left bulk work unfinished: an asset pass (from
    /// a protection toggle or env change) or a job partway through. Such work
    /// can be far more than one message holds. Unlike [`Self::has_pending_work`]
    /// this excludes stale rule marks alone — what a fresh canister starts
    /// with, and what a call's own changes leave for its end-of-call rebuild.
    pub fn has_unfinished_job(&self) -> bool {
        self.job.is_some() || self.stale_assets.is_some()
    }

    /// Marks the assets in `scope` stale — and with them every rule entry, since
    /// alias rules borrow their target's effective headers. An asset pass in
    /// progress restarts (its scope may have grown).
    pub fn mark_assets_stale(&mut self, scope: AssetScope) {
        self.dirty = true;
        self.stale_assets = self.stale_assets.max(Some(scope));
        if matches!(self.job, Some(RecertificationStage::Assets { .. })) {
            self.job = None;
        }
        self.mark_all_rules_stale();
    }

    /// Marks every rule entry stale: the rule list itself was replaced.
    pub fn mark_all_rules_stale(&mut self) {
        self.dirty = true;
        self.stale_rules.all = true;
        self.stale_rules.keys.clear();
        self.drop_building_rules_job();
    }

    /// Marks stale the rule entries that depend on the asset at `key` — call
    /// after any change to that asset (created, deleted, content or headers).
    pub fn mark_rules_stale_for(&mut self, key: &str) {
        self.dirty = true;
        if !self.stale_rules.all {
            self.stale_rules.keys.insert(key.to_string());
        }
        self.drop_building_rules_job();
    }

    /// A rule mark arrived. A rules job still building was planned before it
    /// (a shortened rule list would even leave it indexing past the end), and
    /// has changed nothing yet, so it is dropped and its marks handed back for
    /// the next plan to take in along with the new one. A job already applying
    /// runs on: its plan no longer reads the rule list, and the new mark waits
    /// for the job after it.
    fn drop_building_rules_job(&mut self) {
        if let Some(RecertificationStage::Rules(RulesRebuild {
            phase: RebuildPhase::Build { .. },
            ..
        })) = &self.job
            && let Some(RecertificationStage::Rules(job)) = self.job.take()
        {
            self.stale_rules.merge(job.taken);
        }
    }

    /// Does one asset or rule (or one leaf edit) of re-certifying whatever is
    /// stale, starting a job if none is in progress. Returns `false`, having
    /// done nothing, once nothing is stale. Each step does a bounded amount of
    /// work, so a caller can yield between steps.
    ///
    /// The job lives on the certifier, so concurrent drivers share it. What a
    /// new mark does to it is up to the mark: see [`Self::mark_assets_stale`]
    /// and [`Self::drop_building_rules_job`].
    pub fn recertification_step(&mut self, store: &Store) -> bool {
        let job = match self.job.take() {
            Some(job) => job,
            None => match self.plan_recertification(store) {
                Some(job) => job,
                None => return false,
            },
        };
        self.dirty = true;
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

    /// Plans a rebuild of the stale rule entries, taking over their marks, or
    /// `None` if none are stale.
    ///
    /// Beyond the rules that depend on a changed key, the plan takes in every
    /// rule sharing a tree location with one of them: rules at the same location
    /// can certify identical leaves (a duplicate rule, or the protection sibling
    /// every rule at a location gets), so retracting one rule's leaves can take
    /// another's with it. A rule at the root `<*>` shares it with the built-in
    /// 404 and the protection root sibling, so those are planned with it.
    fn begin_rules_rebuild(&mut self, store: &Store) -> Option<RulesRebuild> {
        if self.stale_rules.is_empty() {
            return None;
        }
        let taken = std::mem::replace(&mut self.stale_rules, StaleRules::none());
        let rules = store.redirect_rules();
        let targets = if taken.all || self.rule_certified_entries.len() != rules.len() {
            None
        } else {
            let depends = |rule: &RedirectRule| {
                taken.keys.contains(&rule.to)
                    || matches!(&rule.from, RulePattern::Exact(from) if taken.keys.contains(from))
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
        Some(RulesRebuild {
            targets,
            rule_count: rules.len(),
            clears_fallback,
            taken,
            phase: RebuildPhase::Build {
                n: 0,
                built: Vec::new(),
            },
        })
    }

    /// Advances `rebuild` by one step and returns what is left, or `None` once
    /// every planned entry is rebuilt and installed.
    fn rules_rebuild_step(
        &mut self,
        store: &Store,
        mut rebuild: RulesRebuild,
    ) -> Option<RulesRebuild> {
        match rebuild.phase {
            RebuildPhase::Build { n, mut built } => {
                let idx = match &rebuild.targets {
                    None => (n < rebuild.rule_count).then_some(n),
                    Some(targets) => targets.get(n).copied(),
                };
                rebuild.phase = match idx {
                    Some(idx) => {
                        built.push(self.build_rule_entry(store, &store.redirect_rules()[idx]));
                        RebuildPhase::Build { n: n + 1, built }
                    }
                    None => {
                        self.plan_apply(store, &rebuild.targets, rebuild.clears_fallback, built)
                    }
                };
            }
            RebuildPhase::Apply {
                built,
                fallback,
                remove,
                insert,
                next,
            } => {
                if let Some(tp) = remove.get(next) {
                    self.asset_hashes.remove_response_precomputed(tp);
                } else if let Some(tp) = insert.get(next - remove.len()) {
                    self.asset_hashes.certify_response_precomputed(tp);
                } else {
                    self.install(rebuild.targets, built, rebuild.clears_fallback, fallback);
                    return None;
                }
                rebuild.phase = RebuildPhase::Apply {
                    built,
                    fallback,
                    remove,
                    insert,
                    next: next + 1,
                };
            }
        }
        Some(rebuild)
    }

    /// Ends the build phase: works out the root `<*>` leaves the new entries
    /// leave to the canister, and the leaf edits that take the tree from the
    /// old entries to the new ones.
    ///
    /// Only leaves no new entry keeps are retracted. Every new leaf is listed
    /// for certifying, kept or not: an asset op may have wiped a kept leaf from
    /// the tree (it clears its whole path, which an exact rule shares), and
    /// certifying a leaf that is present is a cheap no-op.
    fn plan_apply(
        &self,
        store: &Store,
        targets: &Option<Vec<usize>>,
        clears_fallback: bool,
        built: Vec<Option<CertifiedRuleEntry>>,
    ) -> RebuildPhase {
        let root = HashTreePath::not_found_base_path();
        let mut fallback = Vec::new();
        if clears_fallback {
            // Every rule at the root `<*>` is planned along with it, so `built`
            // alone says whether one claims it.
            if !built.iter().flatten().any(|entry| entry.location == root) {
                fallback.push(not_found_fallback_leaf());
            }
            // Under protection the root `<*>` carries a universal
            // `307 → login` sibling too, layered on top of the rules and the
            // built-in 404.
            if let Some(login_page) = store.protection_login_page() {
                fallback.push(protection_leaf(
                    &root,
                    &ProtectionResponse::redirect_to_login(&login_page),
                ));
            }
        }

        let old: Vec<&HashTreePath> = match targets {
            None => self
                .rule_certified_entries
                .iter()
                .flatten()
                .flat_map(|entry| &entry.tree_paths)
                .collect(),
            Some(targets) => targets
                .iter()
                .filter_map(|&idx| self.rule_certified_entries[idx].as_ref())
                .flat_map(|entry| &entry.tree_paths)
                .collect(),
        };
        let old_fallback: &[HashTreePath] = if clears_fallback {
            &self.fallback_leaves
        } else {
            &[]
        };

        let mut new: HashSet<&HashTreePath> = HashSet::new();
        let mut insert = Vec::new();
        for tp in built
            .iter()
            .flatten()
            .flat_map(|entry| &entry.tree_paths)
            .chain(&fallback)
        {
            if new.insert(tp) {
                insert.push(tp.clone());
            }
        }
        let mut removed: HashSet<&HashTreePath> = HashSet::new();
        let remove: Vec<HashTreePath> = old
            .into_iter()
            .chain(old_fallback)
            .filter(|tp| !new.contains(tp) && removed.insert(tp))
            .cloned()
            .collect();

        RebuildPhase::Apply {
            built,
            fallback,
            remove,
            insert,
            next: 0,
        }
    }

    /// Records a finished rebuild's entries (and root `<*>` leaves) as the
    /// ones in the tree.
    fn install(
        &mut self,
        targets: Option<Vec<usize>>,
        built: Vec<Option<CertifiedRuleEntry>>,
        clears_fallback: bool,
        fallback: Vec<HashTreePath>,
    ) {
        match targets {
            None => self.rule_certified_entries = built,
            Some(targets) => {
                for (idx, entry) in targets.into_iter().zip(built) {
                    self.rule_certified_entries[idx] = entry;
                }
            }
        }
        if clears_fallback {
            self.fallback_leaves = fallback;
        }
    }

    /// Computes the certified entry for one rule — every leaf it certifies,
    /// including its protection sibling — without touching the tree, or `None`
    /// if it certifies nothing.
    fn build_rule_entry(
        &mut self,
        store: &Store,
        rule: &RedirectRule,
    ) -> Option<CertifiedRuleEntry> {
        if let RulePattern::Exact(src) = &rule.from
            && store.contains_asset(src)
        {
            // Asset at the source path shadows the rule.
            return None;
        }
        let mut entry = match rule.status {
            // 200 rewrites and 4xx custom error pages both borrow body + headers
            // from the target asset (4xx re-certifies with the override status;
            // see `build_alias_rule_entry`).
            200 | 404 | 410 => self.build_alias_rule_entry(store, rule, rule.status)?,
            // 3xx redirects synthesize an empty body; only the headers
            // (content-type, Location) are certified.
            _ => crate::redirect::build_synthetic_entry(rule),
        };
        // Under protection, every certified rule location needs an
        // unauthenticated `307 → login` sibling (its exact entry would otherwise
        // reject the root wildcard). The root `<*>` is covered by the universal
        // sibling instead (see `plan_apply`).
        if let Some(login_page) = store.protection_login_page()
            && entry.location != HashTreePath::not_found_base_path()
        {
            let redirect = ProtectionResponse::redirect_to_login(&login_page);
            entry
                .tree_paths
                .push(protection_leaf(&entry.location, &redirect));
        }
        Some(entry)
    }

    fn build_alias_rule_entry(
        &mut self,
        store: &Store,
        rule: &RedirectRule,
        status: u16,
    ) -> Option<CertifiedRuleEntry> {
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
                tree_paths.extend(self.ok_leaves(
                    store,
                    &target_key,
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
            tree_paths.push(tp);
        }
        if tree_paths.is_empty() {
            return None;
        }
        Some(CertifiedRuleEntry {
            tree_paths,
            location,
            kind: crate::redirect::CertifiedRuleEntryKind::AliasOf { target_key, status },
        })
    }
}

/// Layers the canister-owned headers onto an asset's own: the env cookie on
/// `text/html`, and `Cache-Control: no-store` under protection. Shared by
/// [`Certifier::effective_headers`] (working inputs) and
/// [`Certifier::served_headers`] (published inputs) so the two can't drift.
fn layer_headers(
    meta: &AssetMeta,
    env_cookie: Option<&[String]>,
    protected: bool,
) -> Vec<(String, String)> {
    let mut headers = meta.headers.clone();
    if let Some(cookies) = env_cookie
        && crate::asset::is_html_content_type(&meta.content_type)
    {
        for cookie in cookies {
            headers.push(("set-cookie".to_string(), cookie.clone()));
        }
    }
    if protected {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cache-control"));
        headers.push(("cache-control".to_string(), "no-store".to_string()));
    }
    headers
}

/// The leaf certifying `resp` at `location`.
fn protection_leaf(location: &HashTreePath, resp: &ProtectionResponse) -> HashTreePath {
    let cert_expr = resp.cert_expr();
    crate::redirect::response_leaf_path(location, cert_expr.expression_hash, resp.response_hash())
}

impl OkLeaves {
    /// An entry no input matches, filled in by its first lookup.
    fn placeholder() -> Self {
        Self {
            effective_headers: Vec::new(),
            content_type: String::new(),
            sha256: [0; 32],
            num_chunks: 0,
            content_id: 0,
            hashes: Vec::new(),
        }
    }

    /// Whether these leaves were computed from exactly these inputs. Everything
    /// [`Certifier::compute_ok_leaf_hashes`] reads is compared; a multi-chunk
    /// encoding's chunk certs are fixed by its `content_id`.
    fn matches(
        &self,
        effective_headers: &[(String, String)],
        content_type: &str,
        enc: &EncodingMeta,
    ) -> bool {
        self.num_chunks != 0
            && self.sha256 == enc.sha256
            && self.num_chunks == enc.num_chunks
            && self.content_id == enc.content_id
            && self.content_type == content_type
            && self.effective_headers == effective_headers
    }
}

/// The leaf certifying the canister's built-in last-resort 404 ("not found") at
/// the root `<*>` fallback path.
fn not_found_fallback_leaf() -> HashTreePath {
    let response = HttpResponse::uncertified_404();
    let headers: Vec<_> = response
        .headers
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();
    fallback_response_path(response.status_code, &headers, &response.body, None)
}
