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
//! - [`ProtectionSettings`] / [`TokenMeta`] — access protection: one `StableCell`
//!   for the gate's on/off + login page, and a `StableBTreeMap<label, TokenMeta>`
//!   for live tokens.
//!
//! The certified-response tree is *not* stored here — it is derived heap state
//! rebuilt from this metadata after an upgrade (see `State::post_upgrade_rebuild`).
//! The hot-path token gate index is likewise derived heap (`State::token_index`),
//! rebuilt from [`TokenMeta`] on upgrade — only the records above are durable.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use candid::Principal;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};

use crate::certification::NestedTreeKey;
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

/// The cached canonical **state hash** (see the `state-hash` crate). Recomputed
/// at the end of every final `execute_operations` and stored so the public
/// `state_hash` endpoint returns it with no recomputation. `[0; 32]` before the
/// first sync. Its own fixed 32-byte cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StateHash(pub [u8; 32]);

impl Storable for StateHash {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_vec())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Self(hash)
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

/// Access-protection configuration (see the access-protection design). When
/// `login_page` is `Some`, the gate is **on**: unauthenticated requests get a
/// certified redirect/401 instead of asset content, and the named asset is the
/// gate-exempt login surface. `None` (the default) means a fully public app —
/// the gate, the no-store override, and the unauthenticated certified siblings
/// are all absent, so a public canister is bit-for-bit unchanged.
///
/// Its own `StableCell` so toggling protection is a single small write,
/// independent of the (potentially large) asset metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProtectionSettings {
    pub login_page: Option<String>,
}

/// Per-token metadata, keyed by the token's **label** — the unique identifier a
/// controller uses to issue/revoke/list. (The hot-path gate doesn't read this; it
/// uses the in-heap `token_index`, which is rebuilt from these records on upgrade.)
/// Holds the value hash (so revoke/GC can drop the matching `token_index` entry,
/// and the index can be rebuilt), the expiry, and the certified-tree path of this
/// token's `POST <login_page>` redeem response (`302 → "/"` + `Set-Cookie`). The
/// redeem leaf's hash is derived from the plaintext cookie value, so storing the
/// *path* lets the canister re-insert it on upgrade and remove it on revoke/GC
/// **without** ever holding the plaintext. `token_id = SHA-256(value)`, so the
/// plaintext is never stored either.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMeta {
    /// `SHA-256(value)` — links this token to its `token_index` entry and lets the
    /// index be reconstructed on upgrade.
    pub token_id: [u8; 32],
    /// Absolute expiry in nanoseconds; the gate rejects once `now >= expires_at`.
    pub expires_at: u64,
    /// Full `HashTreePath` (as a `Vec<NestedTreeKey>`) of the certified redeem
    /// response for this token, at the `login_page` subtree.
    pub redeem_path: Vec<NestedTreeKey>,
}

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
    /// Total encoded length, i.e. the sum of all chunk lengths. Used as the
    /// `/total` in a 206 `Content-Range` and to reject out-of-range requests,
    /// without re-reading the chunks.
    pub content_len: u64,
}

/// Per-chunk certification data, stored in its own region keyed by the same
/// `(content_id, chunk_index)` as the content blob. Holds exactly what the 206
/// certify path and serve path need *without* reading chunk bytes: the chunk's
/// length (for `Content-Range`/offset math) and its SHA-256 (the 206 body hash).
/// Keeping this out of [`AssetMeta`] keeps the per-request metadata decode small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkCert {
    pub len: u32,
    pub sha256: [u8; 32],
}

impl Storable for ChunkCert {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = [0u8; 36];
        buf[..4].copy_from_slice(&self.len.to_le_bytes());
        buf[4..].copy_from_slice(&self.sha256);
        Cow::Owned(buf.to_vec())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let len = u32::from_le_bytes(bytes[..4].try_into().expect("36-byte ChunkCert"));
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[4..36]);
        Self { len, sha256 }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 36,
        is_fixed_size: true,
    };
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
impl_cbor_storable!(ProtectionSettings);
impl_cbor_storable!(TokenMeta);

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
