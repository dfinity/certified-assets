//! The `impl State` methods that drive a sync — `start_sync`, `upload_chunks`,
//! `execute_operations` — alongside the small helpers they rely on.
//!
//! This is the `State`-bound half of the sync domain; the pure data types it
//! operates on — [`SyncSession`], [`ComputationStatus`],
//! [`ExecuteOperationsProgress`], and [`SYNC_IDLE_TIMEOUT_NANOS`] — live in the
//! `State`-free data layer at [`crate::sync`]. Other `State` behavior lives in
//! the sibling submodules of [`crate::state`].

use super::State;
use crate::redirect;
use crate::runtime::SystemContext;
use crate::sync::{
    ComputationStatus, ExecuteOperationsProgress, SyncSession, SYNC_IDLE_TIMEOUT_NANOS,
};
use candid::Principal;
use wire_types::{
    ExecuteOperationsArguments, Operation, SessionId, StartSyncResult, UploadChunksArguments,
};

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

        let session_id = self.alloc_session_id();
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

    /// Stages chunks for the active sync. Chunks are appended in arrival order;
    /// each chunk's id is its index in `self.chunks`. The numbering restarts at
    /// 0 every sync (the staging area is cleared on sync start), so the plugin
    /// — which uploads sequentially — reproduces the same ids without the
    /// canister echoing them back. Returns nothing for that reason.
    pub fn upload_chunks(
        &mut self,
        UploadChunksArguments { session_id, chunks }: UploadChunksArguments,
        system_context: &SystemContext,
    ) -> Result<(), String> {
        self.touch_session(session_id, system_context.current_timestamp_ns)?;

        for chunk in chunks {
            self.chunks.push(Some(chunk));
        }

        Ok(())
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
                    // Asset ops in this call may have clobbered tree entries
                    // that redirect rules own (any rule whose source path
                    // collides with an asset's `<$>` slot). Re-cert them so
                    // the call ends with a consistent rule tree.
                    self.on_redirect_rules_change();

                    // Finalize the sync only when the caller signals this is the
                    // last call; otherwise keep the session open for further
                    // operations and don't touch the cached hash yet.
                    if arg.is_final {
                        self.sync_session = None;
                        self.chunks.clear();
                        // Recompute the cached state hash over the now-final
                        // state, staged one asset per step.
                        let hasher = state_hash::StateHasher::begin(self.state_hash_asset_count());
                        return ComputationStatus::InProgress(
                            ExecuteOperationsProgress::HashingState {
                                hasher,
                                resume_after: None,
                            },
                        );
                    }

                    return ComputationStatus::Done(());
                }

                let op = &arg.operations[operation_index];
                let result = match op {
                    Operation::CreateAsset(arg) => self.create_asset(arg.clone()),
                    Operation::SetAssetContent(arg) => {
                        if !self.contains_asset(&arg.key) {
                            return ComputationStatus::Error("asset not found".to_string());
                        }
                        if arg.chunk_ids.is_empty() {
                            return ComputationStatus::Error(
                                "encoding must have at least one chunk".to_string(),
                            );
                        }

                        // A chunk id is a slot index into the staging area.
                        // Reject the whole op up front if any id doesn't point at
                        // a still-present chunk, so a bad id fails cleanly rather
                        // than leaving earlier chunks half-consumed.
                        let staged = self.chunks();
                        if arg
                            .chunk_ids
                            .iter()
                            .any(|&id| !matches!(staged.get(id as usize), Some(Some(_))))
                        {
                            return ComputationStatus::Error("chunk not found".to_string());
                        }

                        // Take each chunk out of the staging area so its bytes are
                        // freed as soon as it's consumed (the slot is left as a
                        // `None` hole, preserving later indices).
                        let content_chunks: Vec<_> = arg
                            .chunk_ids
                            .iter()
                            .map(|&id| self.chunks[id as usize].take().expect("validated above"))
                            .collect();

                        // The client supplied the content hashes; the canister
                        // trusts them, so there's no per-chunk hashing pass to
                        // spread across calls — write the encoding and certify it
                        // in this single step.
                        self.complete_set_asset_content(arg.clone(), content_chunks)
                    }
                    Operation::UnsetAssetContent(arg) => self.unset_asset_content(arg.clone()),
                    Operation::DeleteAsset(arg) => {
                        self.delete_asset(arg.clone());
                        Ok(())
                    }
                    Operation::SetAssetHeaders(arg) => self.set_asset_headers(arg.clone()),
                    Operation::SetRedirectRules(arg) => {
                        // Validate every rule before mutating state so a single
                        // bad rule fails the whole op with no partial update.
                        let mut validation: Result<(), String> = Ok(());
                        for rule in &arg.rules {
                            if let Err(e) = redirect::validate(rule) {
                                validation = Err(e);
                                break;
                            }
                            // A 404/410 custom error page is served as a single
                            // inline body, so its target must be single-chunk
                            // (see `State::build_alias_rule_entry`). Reject up
                            // front when the target already exists and is
                            // multi-chunk. A target that doesn't exist yet is
                            // allowed — the rule stays inert until it does. The
                            // sync-plugin enforces the same cross-check at deploy
                            // time; this guards against other callers.
                            if matches!(rule.status, 404 | 410)
                                && self.target_is_multichunk(&rule.to)
                            {
                                validation = Err(format!(
                                    "redirect rule to '{}' with status {} points to a \
                                     multi-chunk asset; 404/410 error pages must be small \
                                     enough to serve as a single chunk (< ~1.9 MB)",
                                    rule.to, rule.status
                                ));
                                break;
                            }
                        }
                        validation.map(|_| self.set_redirect_rules(arg.rules.clone()))
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
            ExecuteOperationsProgress::HashingState {
                mut hasher,
                resume_after,
            } => {
                // Fold one asset per step, in key order, resuming after the last.
                if let Some((key, asset)) = self.next_manifest_asset(&resume_after) {
                    hasher.write_asset(&asset);
                    return ComputationStatus::InProgress(
                        ExecuteOperationsProgress::HashingState {
                            hasher,
                            resume_after: Some(key),
                        },
                    );
                }
                // Keyspace exhausted: fold the redirect rules, finalize, cache.
                self.fold_redirect_rules(&mut hasher);
                self.cache_state_hash(hasher.finish());
                ComputationStatus::Done(())
            }
        }
    }
}
