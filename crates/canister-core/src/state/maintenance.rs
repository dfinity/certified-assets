//! Maintenance: re-certifying the whole canister outside a sync, after a change
//! to a setting every response depends on — the access-protection toggles and
//! an env refresh.
//!
//! Such a change re-certifies every asset (or every HTML one) and every redirect
//! rule, which for a site of a few thousand pages is far more than one message's
//! instruction limit. So, like a sync, the work is staged: the change marks what
//! it affects stale in the [`Certifier`](crate::cert::Certifier), and
//! [`State::maintenance_step`] re-certifies it one asset or rule per step, which
//! the canister's driver spreads across messages.
//!
//! While the job runs it holds the sync lock as a *finalizing* session, so
//! nothing else mutates the tree under it: `start_sync` reports `Busy`, uploads
//! and commits are refused, and so is a second toggle. Each step touches the
//! session, so it only goes stale — reclaimable by a sync, whose own end-of-call
//! re-certification then finishes the job — if the job died.

use super::State;
use crate::runtime::SystemContext;
use crate::sync::{ComputationStatus, SYNC_IDLE_TIMEOUT_NANOS, SyncSession};
use candid::Principal;
use wire_types::SessionId;

impl State {
    /// Takes the sync lock for a maintenance job, returning its session id.
    /// Refused while a live sync (or another job) holds it; a stale one is
    /// taken over, as `start_sync` would.
    pub(super) fn begin_maintenance(
        &mut self,
        owner: Principal,
        system_context: &SystemContext,
    ) -> Result<SessionId, String> {
        let now = system_context.current_timestamp_ns;
        if let Some(active) = &self.sync_session
            && now.saturating_sub(active.last_activity_ns) < SYNC_IDLE_TIMEOUT_NANOS
        {
            return Err(format!(
                "a sync by {} is in progress; retry once it finishes",
                active.owner
            ));
        }
        // Taking over an abandoned sync: drop its staged chunks, as a reclaiming
        // `start_sync` would. Its cached hash was already invalidated when it
        // started, and anything it left stale is picked up below.
        self.chunks.clear();
        let id = self.alloc_session_id();
        self.sync_session = Some(SyncSession {
            id,
            owner,
            last_activity_ns: now,
            finalizing: true,
        });
        Ok(id)
    }

    /// Advances the maintenance job holding `session_id` by one asset or rule,
    /// releasing the lock once everything stale is certified. Caller publishes
    /// `certified_data` once it is `Done`.
    pub fn maintenance_step(
        &mut self,
        session_id: SessionId,
        system_context: &SystemContext,
    ) -> ComputationStatus<(), (), String> {
        // Staged across messages, so the lock may have been taken over (after
        // the idle timeout) since the last step.
        match &mut self.sync_session {
            Some(s) if s.id == session_id && s.finalizing => {
                s.last_activity_ns = system_context.current_timestamp_ns;
            }
            _ => {
                return ComputationStatus::Error(
                    "the maintenance job was superseded by a sync".to_string(),
                );
            }
        }
        if self.certifier.recertification_step(&self.store) {
            ComputationStatus::InProgress(())
        } else {
            self.sync_session = None;
            ComputationStatus::Done(())
        }
    }
}
