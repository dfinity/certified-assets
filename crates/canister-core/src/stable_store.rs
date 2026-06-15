//! Stable-memory storage types for the assets canister.
//!
//! These are the `Storable` representations persisted directly in stable memory
//! via `ic-stable-structures`, replacing the old CBOR-blob `StableState`. Each
//! independently-written piece of state lives in its own memory region so a
//! write touches only that piece:
//!
//! - [`AuthorizedSet`] / [`RedirectRules`] — one `StableCell` each. Kept apart
//!   from the counters because they're written rarely but `redirect_rules` can
//!   be large, and we don't want a frequent counter bump to reserialize it.
//! - the two monotonic counters — a `StableCell<u64>` each (bumped on every
//!   sync / content write, so they must be cheap to write).
//! - [`AssetMeta`] — `StableBTreeMap<AssetKey, AssetMeta>`: per-asset metadata,
//!   no content bytes.
//! - content chunks — `StableBTreeMap<ContentChunkKey, Vec<u8>>`: raw bytes,
//!   one entry per chunk.
//!
//! The certified-response tree is *not* stored here — it is derived heap state
//! rebuilt from this metadata after an upgrade (see `State::post_upgrade_rebuild`).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use candid::Principal;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};

use wire_types::{Encoding, RedirectRule};

/// Principals authorized to sync (controllers are always allowed and are not
/// stored here). Newtype so it can carry a `Storable` impl (the orphan rule
/// forbids implementing it for the bare `BTreeSet<Principal>`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthorizedSet(pub BTreeSet<Principal>);

/// The ordered redirect-rule list. Newtype for the same `Storable` reason as
/// [`AuthorizedSet`]. Stored as one cell (not a per-rule map) because serving
/// scans the whole list in order on every request and reads the cached value
/// for free, and `SetRedirectRules` replaces the list wholesale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RedirectRules(pub Vec<RedirectRule>);

/// Per-asset metadata. Content bytes live in the chunk store, grouped by each
/// encoding's `content_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetMeta {
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub encodings: BTreeMap<Encoding, EncodingMeta>,
}

/// Per-encoding metadata. The certificate expression and response hashes are
/// **not** stored — they are recomputed on demand from these fields plus the
/// asset's `headers`/`content_type`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodingMeta {
    /// Groups this encoding's chunks in the content store.
    pub content_id: u64,
    /// Number of chunks, so streaming tokens can be built without a range scan.
    pub num_chunks: u32,
    pub sha256: [u8; 32],
}

/// Key into the content chunk store, encoded big-endian (`content_id` then
/// `chunk_index`) as a fixed 12-byte key. `StableBTreeMap` orders keys by their
/// serialized bytes, so big-endian makes byte order match numeric order: a
/// range scan over one `content_id` returns its chunks in `chunk_index` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContentChunkKey {
    pub content_id: u64,
    pub chunk_index: u32,
}

impl ContentChunkKey {
    pub fn new(content_id: u64, chunk_index: u32) -> Self {
        Self {
            content_id,
            chunk_index,
        }
    }

    /// Inclusive bounds covering every chunk of `content_id`, for range scans
    /// and range deletes: `range(ContentChunkKey::range(cid))`.
    pub fn range(content_id: u64) -> std::ops::RangeInclusive<Self> {
        Self::new(content_id, 0)..=Self::new(content_id, u32::MAX)
    }
}

impl Storable for ContentChunkKey {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = [0u8; 12];
        buf[..8].copy_from_slice(&self.content_id.to_be_bytes());
        buf[8..].copy_from_slice(&self.chunk_index.to_be_bytes());
        Cow::Owned(buf.to_vec())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let content_id = u64::from_be_bytes(bytes[..8].try_into().expect("12-byte chunk key"));
        let chunk_index = u32::from_be_bytes(bytes[8..12].try_into().expect("12-byte chunk key"));
        Self {
            content_id,
            chunk_index,
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 12,
        is_fixed_size: true,
    };
}

/// `Storable` via CBOR (`ciborium`), unbounded. Used for the small/medium
/// structs whose size we don't need to bound for stable-structure node sizing.
macro_rules! impl_cbor_storable {
    ($t:ty) => {
        impl Storable for $t {
            fn to_bytes(&self) -> Cow<'_, [u8]> {
                let mut buf = Vec::new();
                ciborium::into_writer(self, &mut buf).expect("cbor serialize");
                Cow::Owned(buf)
            }

            fn into_bytes(self) -> Vec<u8> {
                let mut buf = Vec::new();
                ciborium::into_writer(&self, &mut buf).expect("cbor serialize");
                buf
            }

            fn from_bytes(bytes: Cow<[u8]>) -> Self {
                ciborium::from_reader(&bytes[..]).expect("cbor deserialize")
            }

            const BOUND: Bound = Bound::Unbounded;
        }
    };
}

impl_cbor_storable!(AuthorizedSet);
impl_cbor_storable!(RedirectRules);
impl_cbor_storable!(AssetMeta);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_chunk_key_roundtrips_and_orders_by_bytes() {
        let k = ContentChunkKey::new(0x0102_0304_0506_0708, 0x0a0b_0c0d);
        let bytes = k.to_bytes();
        assert_eq!(bytes.len(), 12);
        assert_eq!(ContentChunkKey::from_bytes(bytes), k);

        // Byte (lexicographic) order must match (content_id, chunk_index) order,
        // which is what StableBTreeMap relies on for ordered range scans.
        let a = ContentChunkKey::new(1, 5).to_bytes().into_owned();
        let b = ContentChunkKey::new(1, 6).to_bytes().into_owned();
        let c = ContentChunkKey::new(2, 0).to_bytes().into_owned();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn redirect_rules_cbor_roundtrips() {
        use wire_types::RulePattern;
        let rules = RedirectRules(vec![RedirectRule {
            from: RulePattern::Exact("/old".into()),
            to: "/new".into(),
            status: 301,
            headers: vec![],
        }]);
        let restored = RedirectRules::from_bytes(rules.to_bytes());
        assert_eq!(restored.0, rules.0);
    }
}
