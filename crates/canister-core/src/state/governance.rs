//! Governance mode: the `impl State` half of by-proposal deploys.
//!
//! Three groups of methods live here:
//!
//! - **the switch** — reading and setting the approver, and the `by_proposal()`
//!   predicate the sync path consults;
//! - **the overlay** — the `effective_*` accessors that let the asset mutations
//!   in [`super::assets`] write to the pending overlay instead of the live
//!   store, and the merged live+overlay iteration the prospective state hash is
//!   folded over;
//! - **the transitions** — opening, staging, committing, and discarding a
//!   prepared batch.
//!
//! The pure data types are in [`crate::governance`]. Nothing here is reachable
//! from the serving path: the overlay is metadata parked beside the live
//! keyspace, and `http_request` never looks at it.

use super::State;
use crate::asset::AssetMeta;
use crate::cert::AssetKey;
use crate::governance::{PendingAsset, PreparedBatch};
use candid::Principal;
use wire_types::ProposedState;

impl State {
    // ---- the switch ----

    /// The configured governance approver, or `None` when by-proposal deploys
    /// are off.
    pub fn governance_approver(&self) -> Option<Principal> {
        self.store.governance_approver()
    }

    /// Whether `principal` is the configured approver. Always false when
    /// governance mode is off, so an unset approver can never be matched by the
    /// anonymous principal or any other caller.
    pub fn is_governance_approver(&self, principal: &Principal) -> bool {
        self.store.governance_approver() == Some(*principal)
    }

    /// Turns by-proposal deploys on (with `Some`) or off (with `None`).
    ///
    /// Refused while a batch is prepared: the pending overlay only means
    /// anything in governance mode, so switching out from under one would strand
    /// its content. Discard it first.
    pub fn set_governance_approver(&mut self, approver: Option<Principal>) -> Result<(), String> {
        if self.store.prepared_batch().is_some() {
            return Err(
                "a prepared batch is pending; commit or discard it before changing governance"
                    .to_string(),
            );
        }
        self.store.set_governance_approver(approver);
        Ok(())
    }

    /// Whether the canister is in by-proposal mode, i.e. whether a sync prepares
    /// rather than publishes. Consulted by every asset mutation, so it reads the
    /// settings cell's cached value rather than stable memory.
    pub(super) fn by_proposal(&self) -> bool {
        self.store.governance_approver().is_some()
    }

    /// What `proposed_state` reports.
    pub fn proposed_state(&self) -> ProposedState {
        match self.store.prepared_batch() {
            None => ProposedState::None,
            Some(batch) if !batch.staged => ProposedState::Preparing { owner: batch.owner },
            Some(batch) => ProposedState::Staged {
                owner: batch.owner,
                base_state_hash: hex::encode(batch.base_hash),
                prospective_state_hash: hex::encode(batch.prospective_hash),
                changed_assets: self.store.pending_asset_count(),
                prepared_at: batch.prepared_at_ns,
            },
        }
    }

    // ---- the overlay: what a sync in progress sees ----

    /// The asset metadata a sync operates on at `key`.
    ///
    /// In governance mode that is the overlay's view — a staged `Upsert`, or
    /// `None` for a staged `Delete` — falling through to the live store for keys
    /// the prepare hasn't touched. Off governance mode it is just the live
    /// store. This is what lets the mutations in [`super::assets`] be written
    /// once and run in both modes.
    pub(super) fn effective_asset(&self, key: &AssetKey) -> Option<AssetMeta> {
        if self.by_proposal() {
            match self.store.get_pending_asset(key) {
                Some(PendingAsset::Upsert(meta)) => return Some(meta),
                Some(PendingAsset::Delete) => return None,
                None => {}
            }
        }
        self.store.get_asset(key)
    }

    /// Whether an asset exists in the view a sync operates on.
    ///
    /// Deliberately **not** `effective_asset(key).is_some()`: that would
    /// deserialize the whole `AssetMeta` out of stable memory and throw it away,
    /// on a check every `CreateAsset` and `SetAssetContent` performs. Falling
    /// through to `contains_asset` keeps the ordinary-deploy path a bare BTree
    /// key lookup, as it was before governance mode existed.
    pub(super) fn effective_contains_asset(&self, key: &AssetKey) -> bool {
        if self.by_proposal() {
            match self.store.get_pending_asset(key) {
                Some(PendingAsset::Upsert(_)) => return true,
                Some(PendingAsset::Delete) => return false,
                None => {}
            }
        }
        self.store.contains_asset(key)
    }

    /// Writes `meta` for `key` in the view a sync operates on: staged into the
    /// overlay in governance mode (uncertified — nothing serves it yet), or
    /// published and re-certified live otherwise.
    ///
    /// For a **new** asset use [`Self::create_effective_asset`] instead: this one
    /// re-certifies, which is only needed when a response for `key` may already
    /// exist.
    pub(super) fn write_effective_asset(&mut self, key: AssetKey, meta: AssetMeta) {
        if self.by_proposal() {
            self.store
                .put_pending_asset(key, PendingAsset::Upsert(meta));
        } else {
            self.certifier.recertify_asset(&self.store, &key, &meta);
            self.store.put_asset(key, meta);
        }
    }

    /// Writes the metadata of an asset that did not exist a moment ago.
    ///
    /// Deliberately skips re-certification. A fresh asset carries no encodings,
    /// so there is no response to certify — and because the key was just proven
    /// absent, none to clear either. Routing a create through
    /// [`Self::write_effective_asset`] would still pay `remove_responses_for_path`,
    /// a hash-tree mutation, on every `CreateAsset` of a deploy. Content arrives
    /// next via `SetAssetContent`, which certifies then.
    pub(super) fn create_effective_asset(&mut self, key: AssetKey, meta: AssetMeta) {
        if self.by_proposal() {
            self.store
                .put_pending_asset(key, PendingAsset::Upsert(meta));
        } else {
            self.store.put_asset(key, meta);
        }
    }

    /// Deletes `key` in the view a sync operates on.
    ///
    /// In governance mode this stages a `Delete` and frees nothing: the live
    /// asset is still being served, and only the commit that displaces it may
    /// release its content. A `Delete` is staged even for a key that doesn't
    /// exist live, which is harmless — the commit treats it as the no-op it is.
    pub(super) fn delete_effective_asset(&mut self, key: &AssetKey) {
        if self.by_proposal() {
            // Content this same prepare allocated for the key is dead the moment
            // the key is deleted again, and is safe to reclaim now.
            if let Some(PendingAsset::Upsert(staged)) = self.store.get_pending_asset(key) {
                for enc in staged.encodings.values() {
                    self.release_prepared_content(enc.content_id);
                }
            }
            self.store
                .put_pending_asset(key.clone(), PendingAsset::Delete);
            return;
        }
        if let Some(meta) = self.store.remove_asset(key) {
            self.certifier.remove_responses_for_path(key);
            for enc in meta.encodings.values() {
                self.store.delete_content_group(enc.content_id);
            }
        }
    }

    /// Releases a content group displaced by a sync operation.
    ///
    /// Off governance mode the displaced content is dead immediately. In
    /// governance mode it is only dead if *this prepare* allocated it (a key
    /// written twice within one prepare); anything older is still serving the
    /// live response and may only be freed by the commit that replaces it.
    pub(super) fn release_displaced_content(&mut self, content_id: u64) {
        if self.by_proposal() {
            self.release_prepared_content(content_id);
        } else {
            self.store.delete_content_group(content_id);
        }
    }

    /// Frees `content_id` only if the in-flight prepare allocated it. Content
    /// ids come from a monotonic counter, so the comparison against the batch's
    /// opening watermark is an exact test for "never live".
    fn release_prepared_content(&mut self, content_id: u64) {
        let is_ours = self
            .store
            .prepared_batch()
            .is_some_and(|b| content_id >= b.first_content_id);
        if is_ours {
            self.store.delete_content_group(content_id);
        }
    }

    // ---- the overlay: folding the prospective hash ----

    /// Number of assets the state will hold once the overlay is applied — the
    /// `asset_count` written into the digest header.
    ///
    /// Off governance mode this is just the live count. Otherwise it is the live
    /// count adjusted by the overlay: an `Upsert` of a key that isn't live adds
    /// one, a `Delete` of a key that is live removes one, and everything else
    /// leaves the count alone. One pass over the overlay, which holds only the
    /// assets a deploy actually changed.
    pub(super) fn effective_asset_count(&self) -> u64 {
        if !self.by_proposal() {
            return self.state_hash_asset_count();
        }
        let mut count = self.state_hash_asset_count() as i64;
        for (key, pending) in self.store.pending_assets_from(None) {
            let live = self.store.contains_asset(&key);
            match pending {
                PendingAsset::Upsert(_) if !live => count += 1,
                PendingAsset::Delete if live => count -= 1,
                _ => {}
            }
        }
        count.max(0) as u64
    }

    /// The next asset, in ascending key order strictly after `resume_after`, as
    /// the state will look once the overlay is applied — shaped as a
    /// `ManifestAsset` ready to fold into the digest.
    ///
    /// Merges the live keyspace with the overlay: at a shared key the overlay
    /// wins, a staged `Delete` skips the key entirely, and a staged `Upsert` of
    /// a key that isn't live is yielded in its own sort position. Deletes are
    /// skipped in a loop rather than returned, so the caller always makes
    /// progress and the fold covers exactly the post-commit keyspace.
    pub(super) fn next_effective_manifest_asset(
        &self,
        resume_after: &Option<AssetKey>,
    ) -> Option<(AssetKey, state_hash::ManifestAsset)> {
        if !self.by_proposal() {
            return self.next_manifest_asset(resume_after);
        }

        let mut cursor = resume_after.clone();
        loop {
            let live = self.store.assets_from(cursor.as_ref()).next();
            let pending = self.store.pending_assets_from(cursor.as_ref()).next();

            let (key, meta) = match (live, pending) {
                (None, None) => return None,
                // Only the overlay has anything left.
                (None, Some((key, pending))) => match pending {
                    PendingAsset::Upsert(meta) => (key, meta),
                    PendingAsset::Delete => {
                        cursor = Some(key);
                        continue;
                    }
                },
                // Only the live store has anything left.
                (Some((key, meta)), None) => (key, meta),
                (Some((live_key, live_meta)), Some((pending_key, pending))) => {
                    if live_key < pending_key {
                        (live_key, live_meta)
                    } else {
                        // The overlay's key comes first, or is the same key —
                        // either way the overlay's view is the one that counts.
                        match pending {
                            PendingAsset::Upsert(meta) => (pending_key, meta),
                            PendingAsset::Delete => {
                                cursor = Some(pending_key);
                                continue;
                            }
                        }
                    }
                }
            };

            let asset = self.manifest_asset(&key, &meta);
            return Some((key, asset));
        }
    }

    /// Folds the redirect rules the state will have once the overlay is applied:
    /// the prepare's staged rules when it replaced them, else the live ones.
    pub(super) fn fold_effective_redirect_rules(&self, hasher: &mut state_hash::StateHasher) {
        // Short-circuit before touching the batch: off governance mode there is
        // never one, and this runs on every sync's finalization.
        let staged = self
            .by_proposal()
            .then(|| self.store.prepared_batch())
            .flatten()
            .and_then(|b| b.rules);
        match staged {
            Some(rules) => hasher.write_redirect_rules(&rules),
            None => self.fold_redirect_rules(hasher),
        }
    }

    // ---- the transitions ----

    /// Opens a prepared batch for a sync that is starting in governance mode,
    /// marking where this prepare's content allocations begin.
    pub(super) fn open_prepared_batch(&mut self, owner: Principal) {
        let first_content_id = self.store.peek_next_content_id();
        self.store
            .set_prepared_batch(Some(PreparedBatch::opened(owner, first_content_id)));
    }

    /// Records a redirect-rule replacement into the prepared batch instead of
    /// installing it live.
    pub(super) fn stage_redirect_rules(&mut self, rules: Vec<wire_types::RedirectRule>) {
        if let Some(mut batch) = self.store.prepared_batch() {
            batch.rules = Some(rules);
            self.store.set_prepared_batch(Some(batch));
        }
    }

    /// Records a preparation canary into the prepared batch instead of storing
    /// it live.
    pub(super) fn stage_preparation_canary(&mut self, canary: [u8; 32]) {
        if let Some(mut batch) = self.store.prepared_batch() {
            batch.canary = Some(canary);
            self.store.set_prepared_batch(Some(batch));
        }
    }

    /// Marks the in-flight prepare complete and committable, recording the state
    /// hash it was prepared against and the one committing it will produce.
    pub(super) fn stage_prepared_batch(&mut self, prospective_hash: [u8; 32], now_ns: u64) {
        if let Some(mut batch) = self.store.prepared_batch() {
            batch.stage(self.store.cached_state_hash(), prospective_hash, now_ns);
            self.store.set_prepared_batch(Some(batch));
        }
    }

    /// Applies the prepared batch, making its content live.
    ///
    /// This is the single point at which served content changes. It runs in one
    /// message and does metadata work only — no content is copied and no hash is
    /// recomputed, because `prospective_hash` was folded at prepare time over
    /// exactly the state this produces. Every precondition is checked before the
    /// first mutation, and the caller turns any `Err` into a trap, so a rejected
    /// commit leaves the canister untouched.
    pub fn commit_proposed_state(&mut self, expected_hash: [u8; 32]) -> Result<[u8; 32], String> {
        let batch = self
            .store
            .prepared_batch()
            .ok_or_else(|| "no prepared batch to commit".to_string())?;

        if !batch.staged {
            return Err("the prepared batch is incomplete — its sync never finished".to_string());
        }
        if self.sync_session.is_some() {
            return Err("a sync is in progress; retry once it finishes".to_string());
        }
        if batch.prospective_hash != expected_hash {
            return Err(format!(
                "state hash mismatch: the prepared batch commits to {}, the proposal to {}",
                hex::encode(batch.prospective_hash),
                hex::encode(expected_hash)
            ));
        }
        // The prospective hash describes the live state *plus* this overlay, so
        // it is only meaningful against the state it was folded over.
        if self.store.cached_state_hash() != batch.base_hash {
            return Err(format!(
                "the canister state changed since this batch was prepared \
                 (prepared against {}, now {})",
                hex::encode(batch.base_hash),
                hex::encode(self.store.cached_state_hash())
            ));
        }

        for key in self.store.pending_asset_keys() {
            let Some(pending) = self.store.get_pending_asset(&key) else {
                continue;
            };
            match pending {
                PendingAsset::Upsert(meta) => {
                    // Free whatever this replaces, except encodings the prepare
                    // carried over unchanged (same content group, still needed).
                    if let Some(old) = self.store.get_asset(&key) {
                        for enc in old.encodings.values() {
                            let retained = meta
                                .encodings
                                .values()
                                .any(|e| e.content_id == enc.content_id);
                            if !retained {
                                self.store.delete_content_group(enc.content_id);
                            }
                        }
                    }
                    self.certifier.recertify_asset(&self.store, &key, &meta);
                    self.store.put_asset(key, meta);
                }
                PendingAsset::Delete => {
                    if let Some(old) = self.store.remove_asset(&key) {
                        self.certifier.remove_responses_for_path(&key);
                        for enc in old.encodings.values() {
                            self.store.delete_content_group(enc.content_id);
                        }
                    }
                }
            }
        }

        if let Some(rules) = batch.rules {
            self.store.set_redirect_rules(rules);
        }
        if let Some(canary) = batch.canary {
            self.store.set_preparation_canary(canary);
        }
        // Asset ops may have clobbered tree entries the redirect rules own, and
        // the rules may have changed outright — rebuild them either way.
        self.on_redirect_rules_change();

        self.store.cache_state_hash(batch.prospective_hash);
        self.store.clear_pending_assets();
        self.store.set_prepared_batch(None);

        Ok(batch.prospective_hash)
    }

    /// Drops the prepared batch and frees every content group it allocated.
    ///
    /// The escape hatch for a rejected proposal or an abandoned upload: without
    /// it a prepared batch would block further syncs forever. Live state is
    /// untouched — a prepare never wrote any.
    pub fn discard_proposed_state(&mut self) {
        let Some(batch) = self.store.prepared_batch() else {
            return;
        };
        // Everything from this prepare's watermark up to the allocator's current
        // position was allocated by it and is referenced by nothing live.
        // Already-freed ids in the range are a no-op.
        for content_id in batch.first_content_id..self.store.peek_next_content_id() {
            self.store.delete_content_group(content_id);
        }
        self.store.clear_pending_assets();
        self.store.set_prepared_batch(None);
    }
}
