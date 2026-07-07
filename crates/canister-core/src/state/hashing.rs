//! Canonical state hash: reads the durable store into the frozen `state_hash`
//! manifest format and folds it into a digest, one asset per step so a
//! many-asset state stays within the per-message instruction limit. The live
//! path is driven across calls by `ExecuteOperationsProgress::HashingState`
//! (see [`super::sync`]); the whole-thing-at-once `recompute_state_hash` is a
//! test convenience.

use super::State;
use crate::asset::AssetMeta;
use crate::cert::AssetKey;

impl State {
    /// The cached canonical state hash (see the `state-hash` crate). `[0; 32]`
    /// before the first sync finalizes. Read by the public `state_hash` endpoint.
    pub fn cached_state_hash(&self) -> [u8; 32] {
        self.store.cached_state_hash()
    }

    /// Number of assets the staged hash will fold in — the `asset_count` written
    /// into the digest header (see `state_hash::StateHasher::begin`).
    pub(super) fn state_hash_asset_count(&self) -> u64 {
        self.store.asset_count()
    }

    /// The next asset (in ascending key order) strictly after `resume_after`,
    /// shaped as a `state_hash::ManifestAsset` ready to fold into the digest, and
    /// returning its key so the caller can resume after it. `None` once the
    /// keyspace is exhausted. Folding one asset per step keeps a many-asset state
    /// within the per-message instruction limit.
    pub(super) fn next_manifest_asset(
        &self,
        resume_after: &Option<AssetKey>,
    ) -> Option<(AssetKey, state_hash::ManifestAsset)> {
        let (key, meta) = self.store.assets_from(resume_after.as_ref()).next()?;
        let asset = self.manifest_asset(&key, &meta);
        Some((key, asset))
    }

    /// Builds the manifest view of one stored asset. Reads the per-encoding
    /// `EncodingMeta` and, for multi-chunk encodings only, scans the per-chunk
    /// `ChunkCert`s in index order — exactly the gateway-enforced hashes the
    /// digest folds in (single-chunk encodings are covered by the whole `sha256`).
    fn manifest_asset(&self, key: &str, meta: &AssetMeta) -> state_hash::ManifestAsset {
        let encodings = meta
            .encodings
            .iter()
            .map(|(&encoding, enc)| {
                if enc.num_chunks > 1 {
                    let chunks = self
                        .store
                        .chunk_certs_of(enc.content_id)
                        .map(|(_, cert)| state_hash::ManifestChunk {
                            len: cert.len,
                            sha256: cert.sha256,
                        })
                        .collect();
                    state_hash::ManifestEncoding {
                        encoding,
                        sha256: enc.sha256,
                        content_len: enc.content_len,
                        num_chunks: enc.num_chunks,
                        chunks,
                    }
                } else {
                    state_hash::ManifestEncoding::single_chunk(
                        encoding,
                        enc.sha256,
                        enc.content_len,
                    )
                }
            })
            .collect();

        state_hash::ManifestAsset {
            key: key.to_string(),
            content_type: meta.content_type.clone(),
            headers: meta.headers.clone(),
            encodings,
        }
    }

    /// Folds the stored redirect rules (in match order) into `hasher` — the final
    /// step of the staged digest, after every asset.
    pub(super) fn fold_redirect_rules(&self, hasher: &mut state_hash::StateHasher) {
        hasher.write_redirect_rules(self.store.redirect_rules());
    }

    /// Stores a freshly-computed state hash in its cell.
    pub(super) fn cache_state_hash(&mut self, hash: [u8; 32]) {
        self.store.cache_state_hash(hash);
    }

    /// Recomputes the canonical state hash in one pass and caches it. Off-staging
    /// path used by tests; production finalizes via the staged
    /// `ExecuteOperationsProgress::HashingState` machine.
    #[cfg(test)]
    pub(super) fn recompute_state_hash(&mut self) -> [u8; 32] {
        let mut hasher = state_hash::StateHasher::begin(self.state_hash_asset_count());
        let mut resume_after: Option<AssetKey> = None;
        while let Some((key, asset)) = self.next_manifest_asset(&resume_after) {
            hasher.write_asset(&asset);
            resume_after = Some(key);
        }
        self.fold_redirect_rules(&mut hasher);
        let hash = hasher.finish();
        self.cache_state_hash(hash);
        hash
    }
}
