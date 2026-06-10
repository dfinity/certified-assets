//! Sync / chunk machinery for the assets canister.
//!
//! Holds the data types for a sync and its chunked uploads ([`Chunk`],
//! [`SyncSession`]) and the incremental-computation harness used by
//! `execute_operations` to spread expensive work across multiple canister
//! calls ([`ComputationStatus`], [`ExecuteOperationsProgress`]).
//!
//! The State methods that drive a sync — `start_sync`, `create_chunks`,
//! `execute_operations`, `cancel_sync` — live here too, alongside the small
//! helpers they rely on. State methods unrelated to syncing stay in the
//! state machine module.

use crate::certification::{AssetKey, HashTreePath};
use crate::http::HttpResponse;
use crate::rc_bytes::RcBytes;
use crate::redirect;
use crate::state::State;
use crate::system_context::SystemContext;
use crate::types::{
    BatchOperation, CancelSyncArguments, ChunkId, CreateChunksArg, ExecuteOperationsArguments,
    SessionId, SetAssetContentArguments, StartSyncResult,
};
use candid::Principal;
use ic_representation_independent_hash::Value;
use sha2::Digest;

/// How long a sync may sit idle (no calls carrying its session id) before a
/// *different* caller is allowed to reclaim it. Comfortably shorter than any
/// real deploy's inter-call gap; the owner can always reclaim their own sync
/// immediately regardless of this.
pub const SYNC_IDLE_TIMEOUT_NANOS: u64 = 30_000_000_000;

pub struct Chunk {
    pub content: RcBytes,
}

/// The single in-progress sync. The canister holds at most one at a time;
/// `start_sync` rejects a second caller while this is present and non-stale.
pub struct SyncSession {
    pub id: SessionId,
    pub owner: Principal,
    pub last_activity_ns: u64,
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
pub enum ExecuteOperationsProgress {
    /// Initial state when `execute_operations` is first called.
    ///
    /// This phase validates that the call belongs to the active sync (and
    /// records activity), then transitions to `ProcessingOperations` with the
    /// first operation.
    #[default]
    Starting,
    /// Processing operations one at a time.
    ///
    /// When a `SetAssetContent` operation is encountered, this transitions to
    /// `HashingChunks` to hash the asset content incrementally.
    ProcessingOperations { operation_index: usize },
    /// Incrementally hashing asset content chunks, one chunk per call.
    ///
    /// This phase is entered when processing a `SetAssetContent` operation to avoid
    /// instruction limits when hashing large assets. The hasher processes one chunk
    /// per call, allowing the operation to be resumed if interrupted.
    ///
    /// After all chunks are hashed, the hash is finalized, the asset encoding is created,
    /// and processing continues with the next operation in `ProcessingOperations`.
    HashingChunks {
        operation_index: usize,
        set_asset_content_arg: SetAssetContentArguments,
        content_chunks: Vec<RcBytes>,
        chunk_index: usize,
        dependent_keys: Vec<AssetKey>,
        hasher: sha2::Sha256,
    },
}

impl State {
    /// Begins a sync, returning a fresh session id.
    ///
    /// At most one sync runs at a time. If a sync is already in progress:
    /// - the **same owner** can always reclaim it immediately (retrying their
    ///   own deploy shouldn't have to wait), and
    /// - a **different** caller may reclaim it only once it has gone stale
    ///   (`SYNC_IDLE_TIMEOUT_NANOS` since its last call); otherwise the call
    ///   returns `Busy` so a teammate can't barge into an active deploy.
    ///
    /// Reclaiming clears the previous session's staged chunks. The session id
    /// counter is monotonic and never reused.
    pub fn start_sync(
        &mut self,
        owner: Principal,
        system_context: &SystemContext,
    ) -> StartSyncResult {
        let now = system_context.current_timestamp_ns;

        if let Some(active) = &self.sync_session {
            let idle = now.saturating_sub(active.last_activity_ns);
            let reclaimable = active.owner == owner || idle >= SYNC_IDLE_TIMEOUT_NANOS;
            if !reclaimable {
                return StartSyncResult::Busy {
                    owner: active.owner,
                    idle_for_secs: idle / 1_000_000_000,
                };
            }
        }

        // No active sync, or we're taking over: drop any staged chunks left by
        // the previous session before starting fresh.
        self.chunks.clear();

        let session_id = self.next_session_id;
        self.next_session_id += 1;
        self.sync_session = Some(SyncSession {
            id: session_id,
            owner,
            last_activity_ns: now,
        });

        StartSyncResult::Started { session_id }
    }

    /// Marks the active session as touched (resets its idle clock). Returns an
    /// error if `session_id` does not match the active session — the sync was
    /// superseded or never started.
    fn touch_session(&mut self, session_id: SessionId, now: u64) -> Result<(), String> {
        match &mut self.sync_session {
            Some(s) if s.id == session_id => {
                s.last_activity_ns = now;
                Ok(())
            }
            _ => Err("no active sync for this session id".to_string()),
        }
    }

    pub fn create_chunks(
        &mut self,
        CreateChunksArg {
            session_id,
            content: chunks,
        }: CreateChunksArg,
        system_context: &SystemContext,
    ) -> Result<Vec<ChunkId>, String> {
        self.touch_session(session_id, system_context.current_timestamp_ns)?;

        let chunks_len = chunks.len();

        let mut chunk_ids = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let chunk_id = self.next_chunk_id;
            self.next_chunk_id += 1;
            self.chunks.insert(
                chunk_id,
                Chunk {
                    content: RcBytes::from(chunk),
                },
            );
            chunk_ids.push(chunk_id);
        }

        debug_assert!(chunks_len == chunk_ids.len());
        Ok(chunk_ids)
    }

    pub fn execute_operations(
        &mut self,
        arg: &ExecuteOperationsArguments,
        progress: ExecuteOperationsProgress,
        system_context: &SystemContext,
    ) -> ComputationStatus<(), ExecuteOperationsProgress, String> {
        match progress {
            ExecuteOperationsProgress::Starting => {
                // Reject calls that don't belong to the active sync, and reset
                // its idle clock so a concurrent reclaim can't steal it
                // mid-flight.
                if let Err(e) =
                    self.touch_session(arg.session_id, system_context.current_timestamp_ns)
                {
                    return ComputationStatus::Error(e);
                }
                let initial_progress =
                    ExecuteOperationsProgress::ProcessingOperations { operation_index: 0 };
                ComputationStatus::InProgress(initial_progress)
            }
            ExecuteOperationsProgress::ProcessingOperations { operation_index } => {
                // Process one operation per call
                if operation_index >= arg.operations.len() {
                    // All operations in this call processed. Finalize the sync
                    // only when the caller signals this is the last call;
                    // otherwise keep the session open for further operations.
                    if arg.is_final {
                        self.sync_session = None;
                        self.chunks.clear();
                    }
                    self.certify_404_if_required();
                    // Asset ops in this batch may have clobbered tree entries
                    // that redirect rules own (any rule whose source path
                    // collides with an asset's `<$>` slot). Re-cert them so
                    // the batch ends with a consistent rule tree.
                    self.on_redirect_rules_change();

                    self.last_state_update_timestamp_ns = system_context.current_timestamp_ns;
                    return ComputationStatus::Done(());
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
                        let progress = ExecuteOperationsProgress::HashingChunks {
                            operation_index,
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
                            self.on_redirect_rules_change();
                        })
                    }
                };
                if let Err(e) = result {
                    return ComputationStatus::Error(e);
                }

                let progress = ExecuteOperationsProgress::ProcessingOperations {
                    operation_index: operation_index + 1,
                };
                ComputationStatus::InProgress(progress)
            }
            ExecuteOperationsProgress::HashingChunks {
                operation_index,
                set_asset_content_arg,
                content_chunks,
                chunk_index,
                dependent_keys,
                mut hasher,
            } => {
                if chunk_index >= content_chunks.len() {
                    // All chunks hashed, finalize and complete set_asset_content
                    let sha256: [u8; 32] = hasher.finalize().into();
                    let now = system_context.current_timestamp_ns;

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
                    let progress = ExecuteOperationsProgress::ProcessingOperations {
                        operation_index: operation_index + 1,
                    };
                    ComputationStatus::InProgress(progress)
                } else {
                    // Hash one chunk per iteration
                    hasher.update(&content_chunks[chunk_index]);
                    let progress = ExecuteOperationsProgress::HashingChunks {
                        operation_index,
                        set_asset_content_arg,
                        content_chunks,
                        chunk_index: chunk_index + 1,
                        dependent_keys,
                        hasher,
                    };
                    ComputationStatus::InProgress(progress)
                }
            }
        }
    }

    /// Cancels the active sync, if it matches `session_id` and is owned by
    /// `caller`. Lets a client cleanly release the sync lock on abort instead
    /// of waiting for it to go stale. A caller cannot cancel someone else's
    /// sync (a stale one is reclaimed via `start_sync` instead).
    pub fn cancel_sync(
        &mut self,
        arg: CancelSyncArguments,
        caller: Principal,
    ) -> Result<(), String> {
        match &self.sync_session {
            Some(s) if s.id == arg.session_id && s.owner == caller => {
                self.sync_session = None;
                self.chunks.clear();
                Ok(())
            }
            _ => Err("no active sync for this session id".to_string()),
        }
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
