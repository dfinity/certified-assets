//! Asset model: the create/set-content/unset/delete/set-headers mutations and
//! the paginated `get_asset_details` query. Each mutation writes the [`Store`]
//! then asks the [`Certifier`] to re-certify the affected asset, keeping the
//! certified tree in step with the durable content.
//!
//! [`Store`]: crate::store::Store
//! [`Certifier`]: crate::cert::Certifier

use super::{PAGE_SIZE, State};
use crate::asset::{AssetMeta, EncodingMeta};
use crate::cert::AssetKey;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use wire_types::{
    AssetDetails, AssetEncodingDetails, CreateAssetArguments, DeleteAssetArguments,
    SetAssetContentArguments, SetAssetHeadersArguments, UnsetAssetContentArguments,
};

impl State {
    // ---- asset mutations ----

    pub(super) fn create_asset(&mut self, arg: CreateAssetArguments) -> Result<(), String> {
        if self.store.contains_asset(&arg.key) {
            return Err("asset already exists".to_string());
        }

        self.store.put_asset(
            arg.key,
            AssetMeta {
                content_type: arg.content_type,
                headers: arg.headers,
                encodings: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Test/helper entry point that collects the staged chunks and delegates to
    /// [`Self::complete_set_asset_content`]. The live sync path collects chunks
    /// in `execute_operations` and calls that method directly.
    #[cfg(test)]
    pub(super) fn set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
    ) -> Result<(), String> {
        if arg.chunk_ids.is_empty() {
            return Err("encoding must have at least one chunk".to_string());
        }
        if !self.store.contains_asset(&arg.key) {
            return Err("asset not found".to_string());
        }

        let mut content_chunks = vec![];
        for &chunk_id in arg.chunk_ids.iter() {
            let chunk = self
                .chunks
                .get_mut(chunk_id as usize)
                .and_then(Option::take)
                .expect("chunk not found");
            content_chunks.push(chunk);
        }

        self.complete_set_asset_content(arg, content_chunks)
    }

    /// Writes an encoding's content into the chunk store and re-certifies the
    /// asset. Replacing an existing encoding frees the old content group first.
    ///
    /// The hashes in `arg` (`sha256` for the whole encoding, `chunk_sha256` per
    /// chunk) are **trusted, not recomputed** — see [`SetAssetContentArguments`]
    /// for why that's safe. The canister therefore does no content hashing on the
    /// commit path; it only validates the hashes' shape before storing them.
    pub(super) fn complete_set_asset_content(
        &mut self,
        arg: SetAssetContentArguments,
        content_chunks: Vec<ByteBuf>,
    ) -> Result<(), String> {
        let sha256: [u8; 32] = arg
            .sha256
            .as_ref()
            .try_into()
            .map_err(|_| "invalid SHA-256".to_string())?;

        let num_chunks = content_chunks.len() as u32;
        let multi_chunk = num_chunks > 1;

        // Per-chunk cert data (length + hash) is only needed to serve/certify 206
        // ranges, which only happen for multi-chunk encodings — so single-chunk
        // assets (the common case) skip the `chunk_certs` write and reuse the
        // whole-encoding `sha256`. For multi-chunk assets we trust the client's
        // per-chunk hashes; parse them up front so a malformed or wrong-length
        // list fails before any state mutation.
        let chunk_hashes: Vec<[u8; 32]> = if multi_chunk {
            if arg.chunk_sha256.len() != content_chunks.len() {
                return Err("chunk_sha256 length must match chunk_ids".to_string());
            }
            arg.chunk_sha256
                .iter()
                .map(|h| {
                    h.as_ref()
                        .try_into()
                        .map_err(|_| "invalid chunk SHA-256".to_string())
                })
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };

        let mut meta = self
            .store
            .get_asset(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        // Free the chunks of any encoding we're replacing.
        if let Some(old) = meta.encodings.get(&arg.encoding) {
            self.store.delete_content_group(old.content_id);
        }

        // Write the chunks (and, for multi-chunk encodings, their per-chunk cert
        // data) under a fresh content-group id. `chunk_hashes` is empty for
        // single-chunk encodings, so the store skips the `chunk_certs` write.
        let (content_id, content_len) = self.store.store_content(&content_chunks, &chunk_hashes);

        meta.encodings.insert(
            arg.encoding,
            EncodingMeta {
                content_id,
                num_chunks,
                sha256,
                content_len,
            },
        );
        self.certifier.recertify_asset(&self.store, &arg.key, &meta);
        self.store.put_asset(arg.key, meta);

        Ok(())
    }

    pub(super) fn unset_asset_content(
        &mut self,
        arg: UnsetAssetContentArguments,
    ) -> Result<(), String> {
        let mut meta = self
            .store
            .get_asset(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        if let Some(old) = meta.encodings.remove(&arg.encoding) {
            self.store.delete_content_group(old.content_id);
            self.certifier.recertify_asset(&self.store, &arg.key, &meta);
            self.store.put_asset(arg.key, meta);
        }

        Ok(())
    }

    pub(super) fn delete_asset(&mut self, arg: DeleteAssetArguments) {
        if let Some(meta) = self.store.remove_asset(&arg.key) {
            self.certifier.remove_responses_for_path(&arg.key);
            for enc in meta.encodings.values() {
                self.store.delete_content_group(enc.content_id);
            }
        }
    }

    pub(super) fn set_asset_headers(
        &mut self,
        arg: SetAssetHeadersArguments,
    ) -> Result<(), String> {
        let mut meta = self
            .store
            .get_asset(&arg.key)
            .ok_or_else(|| "asset not found".to_string())?;

        meta.headers = arg.headers;
        self.certifier.recertify_asset(&self.store, &arg.key, &meta);
        self.store.put_asset(arg.key, meta);

        Ok(())
    }

    // ---- queries ----

    /// Serves the `get_asset_details` endpoint: one page of assets ordered by
    /// key. `start_after` is exclusive — pass the last key of the previous page
    /// to get the next one, or `None` to start at the beginning. At most
    /// `PAGE_SIZE` assets are returned; an empty result means there is nothing
    /// after `start_after`.
    pub fn get_asset_details(&self, start_after: Option<AssetKey>) -> Vec<AssetDetails> {
        self.store
            .assets_from(start_after.as_ref())
            .take(PAGE_SIZE)
            .map(|(key, meta)| {
                let mut encodings: Vec<_> = meta
                    .encodings
                    .iter()
                    .map(|(&encoding, enc)| AssetEncodingDetails {
                        encoding,
                        sha256: ByteBuf::from(enc.sha256),
                    })
                    .collect();
                encodings.sort_by_key(|l| l.encoding);

                AssetDetails {
                    key,
                    content_type: meta.content_type,
                    encodings,
                    headers: meta.headers,
                }
            })
            .collect()
    }
}
