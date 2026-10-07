//! Governance mode: the data types behind **by-proposal deploys**, where a
//! prepared state change only takes effect when an external governance
//! principal (an SNS/NNS governance canister) commits it.
//!
//! This is the `State`-free data layer, like [`crate::sync`]; the `impl State`
//! half lives in [`crate::state`]'s private `governance` submodule, and the
//! stable cells holding these types live in [`crate::store`].
//!
//! ## The model
//!
//! With an `approver` configured, a sync no longer publishes anything. It
//! **prepares**: content bytes go into the real chunk store (durable, but
//! unreferenced by any live asset, so nothing serves them) while the metadata
//! that *would* make them live is parked in a pending overlay. The live state,
//! and therefore every served response, is untouched.
//!
//! What the developer's prepare produces is a single number: the
//! [`PreparedBatch::prospective_hash`], the canonical state hash the canister
//! *will* report once the overlay is applied. That number is the proposal
//! payload, and — unlike a batch digest — it is reproducible offline from the
//! source build with `state-hash-cli`, by anyone, before and after the vote.
//!
//! Committing applies the overlay in one message: metadata writes and
//! re-certification only, no content copying, and no hashing (the prospective
//! hash was computed at prepare time over exactly the state the overlay
//! produces). Either all of it lands or the message traps and none of it does,
//! so proposal execution is the single point at which served content changes.

use crate::asset::AssetMeta;
use candid::Principal;
use serde::{Deserialize, Serialize};
use wire_types::RedirectRule;

// `ProposedState` — the Candid shape `proposed_state` reports — is a wire type
// like `AssetDetails`, so it lives in `wire-types` where every consumer (the
// canister, operators, the e2e tests) shares one definition.
pub use wire_types::ProposedState;

/// Governance settings: one optional principal, off by default.
///
/// `None` — the default, and what every ordinary deploy runs with — means
/// governance mode is off and the canister behaves exactly as it always has.
/// `Some(p)` puts the canister in by-proposal mode: every sync prepares instead
/// of publishing, and only `p` can commit what was prepared.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSettings {
    pub approver: Option<Principal>,
}

/// One asset's pending change, as staged by a prepare.
///
/// An `Upsert` carries the asset's complete post-commit [`AssetMeta`] — not a
/// delta — so applying it is a single `put_asset` with no merge step, and the
/// overlay can be read as a plain override of the live keyspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PendingAsset {
    /// Create the asset, or replace it wholesale with this metadata.
    Upsert(AssetMeta),
    /// Delete the asset and free all of its content.
    Delete,
}

/// A prepared, not-yet-committed state change.
///
/// Created when a sync starts in governance mode and completed when that sync
/// finalizes; the per-asset metadata rides alongside it in the pending overlay
/// map (see [`crate::store::Store::put_pending_asset`]). At most one exists at a
/// time — a prepared batch blocks further syncs until it is committed or
/// discarded, mirroring the old asset canister's "batch N is already proposed".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedBatch {
    /// The principal whose sync prepared this batch.
    pub owner: Principal,
    /// First content-group id this prepare may have allocated.
    ///
    /// Content ids are handed out by a monotonic counter, so `id >=
    /// first_content_id` is exactly "allocated by this prepare" — which is what
    /// distinguishes content that is safe to free right now (never live) from
    /// content that is still being served and may only be freed by the commit
    /// that displaces it. Discarding frees the whole range in one sweep, with no
    /// per-chunk bookkeeping to keep in step.
    pub first_content_id: u64,
    /// Whether the preparing sync ran to completion. Only a `staged` batch can
    /// be committed; an unfinished one is an abandoned upload, reclaimable on
    /// the ordinary sync-staleness rules.
    ///
    /// Not derivable from the overlay being non-empty: a re-deploy of unchanged
    /// content legitimately stages an empty overlay.
    pub staged: bool,
    /// Redirect rules to install on commit, if the prepare replaced them.
    pub rules: Option<Vec<RedirectRule>>,
    /// Preparation canary to record on commit, if the prepare set one.
    pub canary: Option<[u8; 32]>,
    /// The cached state hash the live state had when this batch was staged.
    ///
    /// Re-checked at commit time. The prospective hash is only meaningful
    /// against the state it was computed over, so this is what makes trusting a
    /// prepare-time hash at commit time sound rather than merely likely.
    pub base_hash: [u8; 32],
    /// The canonical state hash the canister will report once this batch is
    /// committed — the value that goes in the proposal, and the value
    /// `state-hash-cli` prints for the same source build.
    pub prospective_hash: [u8; 32],
    /// When the batch was staged (nanoseconds), for operator visibility into how
    /// long content has been parked.
    pub prepared_at_ns: u64,
}

impl PreparedBatch {
    /// Opens a batch for a sync that is starting in governance mode. The hashes
    /// and rules are filled in by [`Self::stage`] when that sync finalizes.
    pub fn opened(owner: Principal, first_content_id: u64) -> Self {
        Self {
            owner,
            first_content_id,
            staged: false,
            rules: None,
            canary: None,
            base_hash: [0; 32],
            prospective_hash: [0; 32],
            prepared_at_ns: 0,
        }
    }

    /// Marks the batch ready to commit, recording what the commit must check
    /// against and what it will install.
    pub fn stage(&mut self, base_hash: [u8; 32], prospective_hash: [u8; 32], now_ns: u64) {
        self.staged = true;
        self.base_hash = base_hash;
        self.prospective_hash = prospective_hash;
        self.prepared_at_ns = now_ns;
    }
}

/// Parses the hex state hash carried as a proposal payload.
///
/// Hex rather than a `blob` so the payload a voter reads in the proposal is
/// character-for-character the 64-hex-digit line `state-hash-cli` prints for the
/// source build, with no re-encoding step in between to get wrong.
pub fn parse_state_hash(hex_hash: &str) -> Result<[u8; 32], String> {
    let trimmed = hex_hash.trim();
    let bytes =
        hex::decode(trimmed).map_err(|e| format!("state hash must be 64 hex characters: {e}"))?;
    bytes.as_slice().try_into().map_err(|_| {
        format!(
            "state hash must be 32 bytes (64 hex characters), got {}",
            bytes.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_hash_a_verifier_prints() {
        // `state-hash <dist>` prints 64 lowercase hex characters and nothing else.
        let hash = "8150a65e854b9bbb0102030405060708090a0b0c0d0e0f101112131415161718";
        assert_eq!(parse_state_hash(hash).unwrap(), {
            let mut expected = [0u8; 32];
            hex::decode_to_slice(hash, &mut expected).unwrap();
            expected
        });
    }

    /// A payload pasted out of a terminal or a proposal template picks up
    /// whitespace; that should not fail a vote.
    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let hash = "00".repeat(32);
        assert_eq!(parse_state_hash(&format!("  {hash}\n")).unwrap(), [0u8; 32]);
    }

    #[test]
    fn rejects_a_hash_of_the_wrong_length() {
        // Right alphabet, wrong size — a truncated paste must not silently
        // become a different commitment.
        let err = parse_state_hash(&"ab".repeat(16)).unwrap_err();
        assert!(err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn rejects_non_hex() {
        let err = parse_state_hash(&"z".repeat(64)).unwrap_err();
        assert!(err.contains("64 hex characters"), "{err}");
    }

    #[test]
    fn an_opened_batch_is_not_committable_until_staged() {
        let owner = Principal::anonymous();
        let mut batch = PreparedBatch::opened(owner, 7);
        assert!(!batch.staged);
        assert_eq!(batch.first_content_id, 7);

        batch.stage([1u8; 32], [2u8; 32], 99);
        assert!(batch.staged);
        assert_eq!(batch.base_hash, [1u8; 32]);
        assert_eq!(batch.prospective_hash, [2u8; 32]);
        assert_eq!(batch.prepared_at_ns, 99);
    }
}
