//! Batch / chunk machinery for the assets canister.
//!
//! Holds the data types for chunked uploads ([`Chunk`], [`Batch`]) and the
//! incremental-computation harness used by `commit_batch` to spread expensive
//! work across multiple canister calls ([`ComputationStatus`],
//! [`CommitBatchProgress`]).
//!
//! The State methods that drive batches — `create_batch`, `create_chunks`,
//! `commit_batch`, `delete_batch` — live here too, alongside the small
//! helpers they rely on. State methods unrelated to batches stay in the
//! state machine module.

use crate::asset::{is_html_key, on_asset_change, Timestamp};
use crate::certification::{AssetKey, HashTreePath};
use crate::http::HttpResponse;
use crate::rc_bytes::RcBytes;
use crate::redirect;
use crate::state::State;
use crate::system_context::SystemContext;
use crate::types::{
    BatchId, BatchOperation, ChunkId, CommitBatchArguments, CreateChunksArg, DeleteBatchArguments,
    SetAssetContentArguments,
};
use candid::{Int, Nat};
use ic_representation_independent_hash::Value;
use itertools::fold;
use serde_bytes::ByteBuf;
use sha2::Digest;

/// The amount of time a batch is kept alive. Modifying the batch
/// delays the expiry further.
pub const BATCH_EXPIRY_NANOS: u64 = 300_000_000_000;

pub struct Chunk {
    pub batch_id: BatchId,
    pub content: RcBytes,
}

pub struct Batch {
    pub expires_at: Timestamp,
    pub chunk_content_total_size: usize,
}

/// Status of an incremental computation
#[derive(Clone, Debug)]
pub enum ComputationStatus<D, P, E> {
    /// Computation completed successfully
    Done(D),
    /// Computation in progress, with progress state to resume from
    InProgress(P),
    /// Computation failed with an error
    Error(E),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default)]
pub enum CommitBatchProgress {
    /// Initial state when `commit_batch` is first called.
    ///
    /// This phase:
    /// - Reloads the canister environment
    /// - Computes and validates batch limits
    /// - Transitions to `ProcessingOperations` with the first operation
    #[default]
    Starting,
    /// Processing batch operations one at a time.
    ///
    /// When a `SetAssetContent` operation is encountered, this transitions to
    /// `HashingChunks` to hash the asset content incrementally.
    /// When all operations are processed, this transitions to `UpdatingCookies` to update the HTML assets.
    ProcessingOperations {
        batch_id: BatchId,
        operation_index: usize,
        needs_cookie_update: bool,
    },
    /// Incrementally hashing asset content chunks, one chunk per call.
    ///
    /// This phase is entered when processing a `SetAssetContent` operation to avoid
    /// instruction limits when hashing large assets. The hasher processes one chunk
    /// per call, allowing the operation to be resumed if interrupted.
    ///
    /// After all chunks are hashed, the hash is finalized, the asset encoding is created,
    /// and processing continues with the next operation in `ProcessingOperations`.
    HashingChunks {
        batch_id: BatchId,
        operation_index: usize,
        needs_cookie_update: bool,
        set_asset_content_arg: SetAssetContentArguments,
        content_chunks: Vec<RcBytes>,
        chunk_index: usize,
        dependent_keys: Vec<AssetKey>,
        hasher: sha2::Sha256,
    },
    /// Updating cookies for HTML assets that depend on the canister environment.
    ///
    /// This phase is entered after all operations complete if the canister environment
    /// changed during batch processing. HTML assets need their cookies updated to reflect
    /// the new environment.
    ///
    /// One asset is updated per call until all HTML assets are processed.
    UpdatingCookies {
        html_keys: Vec<AssetKey>,
        operation_index: usize,
    },
}

impl State {
    pub fn create_batch(&mut self, system_context: &SystemContext) -> Result<BatchId, String> {
        let now = system_context.current_timestamp_ns;
        self.batches.retain(|_, b| b.expires_at > now);
        self.chunks
            .retain(|_, c| self.batches.contains_key(&c.batch_id));

        if let Some(max_batches) = self.configuration.max_batches {
            if self.batches.len() as u64 >= max_batches {
                return Err("batch limit exceeded".to_string());
            }
        }
        let batch_id = self.next_batch_id.clone();
        self.next_batch_id += 1_u8;

        self.batches.insert(
            batch_id.clone(),
            Batch {
                expires_at: Int::from(now + BATCH_EXPIRY_NANOS),
                chunk_content_total_size: 0,
            },
        );

        Ok(batch_id)
    }

    pub fn create_chunks(
        &mut self,
        CreateChunksArg {
            batch_id,
            content: chunks,
        }: CreateChunksArg,
        system_context: &SystemContext,
    ) -> Result<Vec<ChunkId>, String> {
        self.create_chunks_helper(batch_id, chunks, system_context)
    }

    /// Post-condition: `chunks.len() == output_chunk_ids.len()`
    fn create_chunks_helper(
        &mut self,
        batch_id: Nat,
        chunks: Vec<ByteBuf>,
        system_context: &SystemContext,
    ) -> Result<Vec<ChunkId>, String> {
        self.check_batch_limits(chunks.len(), chunks.iter().map(|chunk| chunk.len()).sum())?;
        let batch = self
            .batches
            .get_mut(&batch_id)
            .ok_or_else(|| "batch not found".to_string())?;

        batch.expires_at = Int::from(system_context.current_timestamp_ns + BATCH_EXPIRY_NANOS);

        let chunks_len = chunks.len();

        let mut chunk_ids = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let chunk_id = self.next_chunk_id.clone();
            self.next_chunk_id += 1_u8;
            batch.chunk_content_total_size += chunk.len();
            self.chunks.insert(
                chunk_id.clone(),
                Chunk {
                    batch_id: batch_id.clone(),
                    content: RcBytes::from(chunk),
                },
            );
            chunk_ids.push(chunk_id);
        }

        debug_assert!(chunks_len == chunk_ids.len());
        Ok(chunk_ids)
    }

    fn check_batch_limits(&self, chunks_added: usize, bytes_added: usize) -> Result<(), String> {
        if let Some(max_chunks) = self.configuration.max_chunks {
            if self.chunks.len() + chunks_added > max_chunks as usize {
                return Err("chunk limit exceeded".to_string());
            }
        }
        if let Some(max_bytes) = self.configuration.max_bytes {
            let current_total_bytes = &self.batches.iter().fold(0, |acc, (_batch_id, batch)| {
                acc + batch.chunk_content_total_size
            });
            if current_total_bytes + bytes_added > max_bytes as usize {
                return Err("byte limit exceeded".to_string());
            }
        }
        Ok(())
    }

    /// Computes the data required to perform `self.check_batch_limits` against
    /// the data carried in `last_chunk` fields.
    fn compute_last_chunk_data(&self, arg: &CommitBatchArguments) -> (usize, usize) {
        fold(
            arg.operations.iter().map(|op| {
                if let BatchOperation::SetAssetContent(SetAssetContentArguments {
                    last_chunk: Some(content),
                    // Chunks defined in `chunk_ids` are already accounted for and can be ignored here
                    ..
                }) = op
                {
                    Some(content.len())
                } else {
                    None
                }
            }),
            (0, 0),
            |(chunks_added, bytes_added), asset_len| {
                if let Some(len) = asset_len {
                    (chunks_added + 1, bytes_added + len)
                } else {
                    (chunks_added, bytes_added)
                }
            },
        )
    }

    pub fn commit_batch(
        &mut self,
        arg: &CommitBatchArguments,
        progress: CommitBatchProgress,
        system_context: &SystemContext,
    ) -> ComputationStatus<(), CommitBatchProgress, String> {
        match progress {
            CommitBatchProgress::Starting => {
                // Reload the canister env to get the latest values
                let old_encoded_canister_env = self.encoded_canister_env.clone();
                self.encoded_canister_env = system_context.get_canister_env().to_cookie_value();

                let (chunks_added, bytes_added) = self.compute_last_chunk_data(arg);
                if let Err(e) = self.check_batch_limits(chunks_added, bytes_added) {
                    return ComputationStatus::Error(e);
                }

                let needs_cookie_update = old_encoded_canister_env != self.encoded_canister_env;
                let initial_progress = CommitBatchProgress::ProcessingOperations {
                    batch_id: arg.batch_id.clone(),
                    operation_index: 0,
                    needs_cookie_update,
                };
                ComputationStatus::InProgress(initial_progress)
            }
            CommitBatchProgress::ProcessingOperations {
                batch_id,
                operation_index,
                needs_cookie_update,
            } => {
                // Process one operation per call
                if operation_index >= arg.operations.len() {
                    // All operations processed
                    self.batches.remove(&batch_id);
                    self.certify_404_if_required();

                    // Move to cookie update phase if needed
                    if needs_cookie_update {
                        let html_keys: Vec<_> = self
                            .assets
                            .keys()
                            .filter(|key| is_html_key(key))
                            .cloned()
                            .collect();

                        if html_keys.is_empty() {
                            // No HTML files to update, we're done
                            self.last_state_update_timestamp_ns =
                                system_context.current_timestamp_ns;
                            return ComputationStatus::Done(());
                        } else {
                            let progress = CommitBatchProgress::UpdatingCookies {
                                html_keys,
                                operation_index: 0,
                            };
                            return ComputationStatus::InProgress(progress);
                        }
                    } else {
                        self.last_state_update_timestamp_ns = system_context.current_timestamp_ns;
                        return ComputationStatus::Done(());
                    }
                }

                let op = &arg.operations[operation_index];
                let result = match op {
                    BatchOperation::CreateAsset(arg) => self.create_asset(arg.clone()),
                    BatchOperation::SetAssetContent(arg) => {
                        if !self.assets.contains_key(&arg.key) {
                            return ComputationStatus::Error("asset not found".to_string());
                        }
                        if arg.chunk_ids.is_empty() && arg.last_chunk.is_none() {
                            return ComputationStatus::Error(
                                "encoding must have at least one chunk or contain last_chunk"
                                    .to_string(),
                            );
                        }

                        let dependent_keys = self.dependent_keys(&arg.key);

                        // Collect all chunks (removing them from self.chunks)
                        let mut content_chunks = vec![];
                        for chunk_id in arg.chunk_ids.iter() {
                            let chunk = match self.chunks.remove(chunk_id) {
                                Some(c) => c,
                                None => {
                                    return ComputationStatus::Error("chunk not found".to_string());
                                }
                            };
                            content_chunks.push(chunk.content);
                        }
                        if let Some(encoding_content) = arg.last_chunk.clone() {
                            content_chunks.push(encoding_content.into());
                        }

                        // Start hashing phase with an empty hasher
                        let progress = CommitBatchProgress::HashingChunks {
                            batch_id,
                            operation_index,
                            needs_cookie_update,
                            set_asset_content_arg: arg.clone(),
                            content_chunks,
                            chunk_index: 0,
                            dependent_keys,
                            hasher: sha2::Sha256::new(),
                        };
                        return ComputationStatus::InProgress(progress);
                    }
                    BatchOperation::UnsetAssetContent(arg) => self.unset_asset_content(arg.clone()),
                    BatchOperation::DeleteAsset(arg) => {
                        self.delete_asset(arg.clone());
                        Ok(())
                    }
                    BatchOperation::Clear(_) => {
                        self.clear();
                        Ok(())
                    }
                    BatchOperation::SetAssetProperties(arg) => {
                        self.set_asset_properties(arg.clone())
                    }
                    BatchOperation::SetRedirectRules(arg) => {
                        // Validate every rule before mutating state so a single
                        // bad rule fails the whole op with no partial update.
                        let mut validation: Result<(), String> = Ok(());
                        for rule in &arg.rules {
                            if let Err(e) = redirect::validate(rule) {
                                validation = Err(e);
                                break;
                            }
                        }
                        validation.map(|_| {
                            self.redirect_rules = arg.rules.clone();
                        })
                    }
                };
                if let Err(e) = result {
                    return ComputationStatus::Error(e);
                }

                let progress = CommitBatchProgress::ProcessingOperations {
                    batch_id,
                    operation_index: operation_index + 1,
                    needs_cookie_update,
                };
                ComputationStatus::InProgress(progress)
            }
            CommitBatchProgress::HashingChunks {
                batch_id,
                operation_index,
                needs_cookie_update,
                set_asset_content_arg,
                content_chunks,
                chunk_index,
                dependent_keys,
                mut hasher,
            } => {
                if chunk_index >= content_chunks.len() {
                    // All chunks hashed, finalize and complete set_asset_content
                    let sha256: [u8; 32] = hasher.finalize().into();
                    let now = Int::from(system_context.current_timestamp_ns);

                    if let Err(e) = self.complete_set_asset_content(
                        set_asset_content_arg.clone(),
                        content_chunks,
                        sha256,
                        now,
                        dependent_keys,
                    ) {
                        return ComputationStatus::Error(e);
                    }

                    // Continue with next operation
                    let progress = CommitBatchProgress::ProcessingOperations {
                        batch_id,
                        operation_index: operation_index + 1,
                        needs_cookie_update,
                    };
                    ComputationStatus::InProgress(progress)
                } else {
                    // Hash one chunk per iteration
                    hasher.update(&content_chunks[chunk_index]);
                    let progress = CommitBatchProgress::HashingChunks {
                        batch_id,
                        operation_index,
                        needs_cookie_update,
                        set_asset_content_arg,
                        content_chunks,
                        chunk_index: chunk_index + 1,
                        dependent_keys,
                        hasher,
                    };
                    ComputationStatus::InProgress(progress)
                }
            }
            CommitBatchProgress::UpdatingCookies {
                html_keys,
                operation_index,
            } => {
                // Process one cookie update per call
                if operation_index >= html_keys.len() {
                    // All cookies updated, we're done
                    self.last_state_update_timestamp_ns = system_context.current_timestamp_ns;
                    return ComputationStatus::Done(());
                }

                // Update one cookie
                let key = &html_keys[operation_index];
                let dependent_keys = self.dependent_keys(key);
                if let Some(asset) = self.assets.get_mut(key) {
                    on_asset_change(
                        &mut self.asset_hashes,
                        key,
                        asset,
                        dependent_keys,
                        Some(&self.encoded_canister_env),
                    );
                }

                let progress = CommitBatchProgress::UpdatingCookies {
                    html_keys,
                    operation_index: operation_index + 1,
                };
                ComputationStatus::InProgress(progress)
            }
        }
    }

    pub fn delete_batch(&mut self, arg: DeleteBatchArguments) -> Result<(), String> {
        if self.batches.remove(&arg.batch_id).is_none() {
            return Err("batch not found".to_string());
        }
        self.chunks.retain(|_, c| c.batch_id != arg.batch_id);
        Ok(())
    }

    fn certify_404_if_required(&mut self) {
        if !self
            .asset_hashes
            .contains_path(HashTreePath::not_found_base_path().as_vec())
        {
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
    }
}
