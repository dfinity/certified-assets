//! This module declares canister methods expected by the assets canister client.
mod asset;
mod cert;
mod governance;
mod http;
mod protection;
mod redirect;
mod runtime;
mod state;
mod store;
mod sync;

#[cfg(feature = "canbench-rs")]
mod benches;

use crate::{
    runtime::{CanisterEnv, SystemContext},
    state::State,
    sync::ComputationStatus,
};
use candid::Principal;
use ic_cdk::api::{certified_data_set, data_certificate, msg_caller, time, trap};
use std::cell::RefCell;

pub use governance::ProposedState;
pub use http::{HttpRequest, HttpResponse};
pub use protection::{IssueTokenArgs, ProtectionStatus, TokenInfo};
pub use serde_bytes::ByteBuf;
pub use wire_types::{
    AssetDetails, ChunkId, ExecuteOperationsArguments, RedirectRule, StartSyncResult,
    UploadChunksArguments, Version,
};

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// The semver release version this canister was built with. The sync plugin
/// checks this against its own version and refuses to proceed on a mismatch, and
/// the value also encodes state-upgradability between releases. See
/// [`wire_types::VERSION`].
pub fn version() -> Version {
    wire_types::VERSION
}

/// Adds `principal` to the authorized set. Controller-guarded at the endpoint.
pub fn authorize(principal: Principal) {
    STATE.with_borrow_mut(|s| s.authorize(principal))
}

/// Removes `principal` from the authorized set. Controller-guarded at the endpoint.
pub fn deauthorize(principal: Principal) {
    STATE.with_borrow_mut(|s| s.deauthorize(&principal))
}

/// Renders an `authorize` payload for voters — the `validator_method` of the SNS
/// generic function that wraps it.
///
/// A generic nervous system function cannot be registered without a validator
/// (`validator_method_name` empty is a rejected proposal), so `authorize` is only
/// reachable by proposal because this exists. Reports whether the principal is
/// already authorized, so a no-op proposal is visible before the vote rather
/// than after.
pub fn validate_authorize(principal: Principal) -> Result<String, String> {
    let already = STATE.with_borrow(|s| s.is_authorized(&principal));
    Ok(format!(
        "Authorize {principal} to sync assets to this canister.\n\n\
         Currently authorized: {}.\n\n\
         A syncing principal can prepare a state change, but cannot make one \
         live — only the governance approver can commit.",
        if already {
            "yes, this changes nothing"
        } else {
            "no"
        }
    ))
}

/// Renders a `deauthorize` payload for voters. See [`validate_authorize`].
pub fn validate_deauthorize(principal: Principal) -> Result<String, String> {
    let authorized = STATE.with_borrow(|s| s.is_authorized(&principal));
    Ok(format!(
        "Revoke {principal}'s authorization to sync assets to this canister.\n\n\
         Currently authorized: {}.\n\n\
         Canister controllers and the governance approver keep their access \
         either way; this list holds only the extra principals.",
        if authorized {
            "yes"
        } else {
            "no, this changes nothing"
        }
    ))
}

pub fn list_authorized() -> Vec<Principal> {
    STATE.with_borrow(|s| s.list_authorized())
}

pub fn start_sync() -> StartSyncResult {
    let system_context = SystemContext::new();
    let caller = msg_caller();

    STATE.with_borrow_mut(|s| {
        let result = s.start_sync(caller, &system_context);
        // Capture the env once, at sync start, so every asset (re)certified by
        // the operations that follow already carries the current `ic_env`
        // cookie — no separate re-cert pass once the sync completes. Env vars
        // aren't expected to change mid-sync; `refresh_env` publishes an
        // env-only change without a sync. Only on a real start (not `Busy`).
        if matches!(result, StartSyncResult::Started { .. }) {
            s.capture_env_at_sync_start(&CanisterEnv::load());
            certified_data_set(s.root_hash());
        }
        result
    })
}

pub fn upload_chunks(arg: UploadChunksArguments) -> Vec<ChunkId> {
    let system_context = SystemContext::new();

    STATE.with_borrow_mut(|s| match s.upload_chunks(arg, &system_context) {
        Ok(ids) => ids,
        Err(msg) => trap(&msg),
    })
}

/// Applies a group of sync operations. The call flagged `is_final` finalizes the
/// sync and returns the canonical state hash recomputed over the now-final
/// state; every other call returns `None`. Reporting it here means a client
/// never needs a second `state_hash()` round trip to learn what it just
/// installed — though that value is *canister-reported*, so a third party
/// verifying a deploy still reproduces the hash from source (see
/// `docs/verifying-contents.md`).
pub async fn execute_operations(arg: ExecuteOperationsArguments) -> Option<ByteBuf> {
    let system_context = SystemContext::new();
    let arg_ref = &arg;

    let state_hash = loop_with_message_extension_until_completion(|progress| {
        STATE.with_borrow_mut(|s| s.execute_operations(arg_ref, progress, &system_context))
    })
    .await
    .map_err(|msg| trap(&msg))
    .ok()
    .flatten();

    STATE.with_borrow_mut(|s| certified_data_set(s.root_hash()));

    state_hash.map(|hash| ByteBuf::from(hash.to_vec()))
}

pub fn get_asset_details(start_after: Option<String>) -> Vec<AssetDetails> {
    STATE.with_borrow(|s| s.get_asset_details(start_after))
}

pub fn get_redirect_rules(start_index: u64) -> Vec<RedirectRule> {
    STATE.with_borrow(|s| s.get_redirect_rules(start_index))
}

/// The cached canonical **state hash**: a SHA-256 over the canister's served-
/// content model (every asset's content_type/headers/encoding hashes + the
/// redirect rules — see the `state-hash` crate). Recomputed at the end of every
/// final sync and returned here verbatim.
///
/// `[0; 32]` means "no verifiable hash": before the first sync, and from the
/// moment a sync starts until it finalizes. An abandoned sync therefore leaves
/// zeros rather than the pre-sync hash, which by then describes content the
/// canister no longer serves.
///
/// The endpoint is public and unguarded; the `canister` crate exposes it as an
/// **update** so the reply is consensus-backed and a verifier can trust it
/// against a hash they computed locally from the source build. Returns the
/// cached value with no recomputation, so there is no cycle-DoS vector.
pub fn state_hash() -> ByteBuf {
    STATE.with_borrow(|s| ByteBuf::from(s.cached_state_hash().to_vec()))
}

/// The compression fingerprint of the client that last prepared every asset (see
/// `asset-prep::canary`), or 32 zero bytes if no client has recorded one.
///
/// A syncing client reads this to decide whether the compressed encodings stored
/// here are the ones its own compressors would produce. If they differ — a
/// dependency bump, a different DEFLATE backend, a different target — it must
/// re-prepare every asset instead of trusting an unchanged uncompressed hash to
/// imply unchanged compressed bytes. The canister assigns the bytes no meaning.
pub fn preparation_canary() -> ByteBuf {
    STATE.with_borrow(|s| ByteBuf::from(s.preparation_canary().to_vec()))
}

pub fn http_request(req: HttpRequest) -> HttpResponse {
    if req.certificate_version != Some(2) {
        trap("Only support V2 certification");
    }
    let certificate = data_certificate().unwrap_or_else(|| trap("no data certificate available"));
    // `time()` is readable in a (non-replicated) query; access protection
    // uses it to reject expired tokens. Unlike `root_key`/`env_var_*` (which
    // trap in a query and are snapshotted on the update path), `time` is fine here.
    let now = time();

    STATE.with_borrow(|s| s.http_request(req, &certificate, now))
}

/// Turns access protection on with `login_page` as the exempt login surface.
/// Controller-guarded at the endpoint. Idempotent at the same page; see
/// [`State::enable_protection`].
pub fn enable_protection(login_page: String) {
    STATE.with_borrow_mut(|s| {
        s.enable_protection(login_page);
        certified_data_set(s.root_hash());
    })
}

/// Turns access protection off and drops all tokens. Controller-guarded.
pub fn disable_protection() {
    STATE.with_borrow_mut(|s| {
        s.disable_protection();
        certified_data_set(s.root_hash());
    })
}

/// Issues an access token and returns its plaintext value (shown once). With
/// `args.value` set, mints that exact (typeable) passphrase; otherwise a
/// high-entropy random value via `raw_rand`. Controller-guarded. Async because
/// random tokens need the management canister's randomness — a rare, off-the-
/// hot-path update.
pub async fn issue_token(args: IssueTokenArgs) -> String {
    let value = match args.value {
        Some(v) => v,
        None => {
            let random = ic_cdk_management_canister::raw_rand()
                .await
                .unwrap_or_else(|e| trap(format!("raw_rand failed: {e:?}")));
            hex::encode(random)
        }
    };
    let now = time();
    STATE.with_borrow_mut(|s| {
        if let Err(msg) = s.issue_token(value.clone(), args.label, args.ttl_secs, now) {
            trap(&msg);
        }
        certified_data_set(s.root_hash());
    });
    value
}

/// Revokes the token with the given label (live on the next request).
/// Controller-guarded.
pub fn revoke_token(label: String) {
    STATE.with_borrow_mut(|s| {
        s.revoke_token(&label);
        certified_data_set(s.root_hash());
    })
}

/// Live tokens (label + expiry) for the management UI. Controller-guarded.
pub fn list_tokens() -> Vec<TokenInfo> {
    STATE.with_borrow(|s| s.list_tokens())
}

/// Whether protection is off, healthy, or degraded (login page missing).
pub fn check_protection_status() -> ProtectionStatus {
    STATE.with_borrow(|s| s.check_protection_status())
}

/// Whether the current caller may sync assets: either in the authorized set, or
/// a canister controller. The authorized set holds only the extra (non-controller)
/// principals — controllers are always allowed without being stored.
pub fn can_sync() -> bool {
    let caller = msg_caller();
    is_owner(&caller) || STATE.with_borrow(|s| s.is_authorized(&caller))
}

/// Whether `caller` administers this canister: a controller, or the configured
/// governance approver.
///
/// Under an SNS the two are different principals and both are needed. SNS
/// **root** is the sole controller of a dapp canister, but root only performs
/// canister management — it never relays an arbitrary method call. A proposal
/// that calls a method on this canister is executed by SNS **governance**,
/// calling directly, so governance is the principal that actually arrives here.
/// Treating the approver as an administrator is what lets a DAO manage its own
/// asset canister by proposal — notably `authorize`/`deauthorize`, without which
/// it could never grant or rotate a developer's sync access.
fn is_owner(caller: &Principal) -> bool {
    ic_cdk::api::is_controller(caller) || STATE.with_borrow(|s| s.is_governance_approver(caller))
}

// ───────── Governance mode (by-proposal deploys) ─────────

/// Sets (or clears, with `None`) the governance approver — the principal allowed
/// to commit a prepared state. `Some` puts the canister in by-proposal mode:
/// every sync then prepares instead of publishing. Controller-guarded at the
/// endpoint; refused while a batch is prepared.
pub fn set_governance(approver: Option<Principal>) {
    STATE.with_borrow_mut(|s| {
        if let Err(msg) = s.set_governance_approver(approver) {
            trap(&msg);
        }
    })
}

/// The configured governance approver, or `None` when by-proposal deploys are
/// off. Public: which principal may change this canister's content is exactly
/// the kind of thing an outside verifier should be able to check.
pub fn governance() -> Option<Principal> {
    STATE.with_borrow(|s| s.governance_approver())
}

/// Whether anything is prepared, and if so the hash committing it would produce.
///
/// A query, so treat it as a convenience for operators and voters rather than
/// proof: the binding check is the one `commit_proposed_state` makes on the
/// replicated path. The number to verify against source is still reproduced
/// locally with `state-hash-cli`.
pub fn proposed_state() -> ProposedState {
    STATE.with_borrow(|s| s.proposed_state())
}

/// Commits the prepared state, making it live. The single point at which served
/// content changes.
///
/// `state_hash_hex` is the proposal's payload: the 64-hex-character state hash
/// the committed canister must report, which a voter reproduces from source with
/// `state-hash-cli`. Guarded to the governance approver at the endpoint.
///
/// **Traps on every failure, and never returns an error.** SNS governance
/// discards a target method's reply (`canister_control.rs`: "any reply is
/// considered a success"), so a method that returned `Err` would have its
/// proposal recorded as *executed* while nothing happened. A trap is the only
/// failure this canister can report that governance will actually surface — and
/// it rolls the message back, so a rejected commit leaves the canister exactly
/// as it was.
pub fn commit_proposed_state(state_hash_hex: String) {
    let expected = governance::parse_state_hash(&state_hash_hex).unwrap_or_else(|e| trap(&e));
    STATE.with_borrow_mut(|s| {
        if let Err(msg) = s.commit_proposed_state(expected) {
            trap(&msg);
        }
        certified_data_set(s.root_hash());
    })
}

/// Renders `commit_proposed_state`'s payload for voters — the `validator_method`
/// of the SNS generic function. Read-only.
///
/// Must be an **update** method: an inter-canister call cannot reach a canister's
/// query entry point, so governance could not call a `#[query]` validator at all.
pub fn validate_commit_proposed_state(state_hash_hex: String) -> Result<String, String> {
    let expected = governance::parse_state_hash(&state_hash_hex)?;
    let rendered = hex::encode(expected);
    match STATE.with_borrow(|s| s.proposed_state()) {
        ProposedState::Staged {
            prospective_state_hash,
            changed_assets,
            ..
        } if prospective_state_hash == rendered => Ok(format!(
            "Commit the prepared frontend state.\n\n\
             State hash: {rendered}\n\
             Assets changed by this commit: {changed_assets}\n\n\
             Verify by reproducing the build from source and running \
             `state-hash <dist>`; it must print exactly the state hash above. \
             After execution, `state_hash()` on this canister returns the same value."
        )),
        ProposedState::Staged {
            prospective_state_hash,
            ..
        } => Err(format!(
            "the prepared batch commits to {prospective_state_hash}, not {rendered}"
        )),
        ProposedState::Preparing { .. } => {
            Err("a sync is still preparing; nothing is committable yet".to_string())
        }
        ProposedState::None => Err("no prepared batch to commit".to_string()),
    }
}

/// Discards the prepared state and frees the content it staged.
///
/// The escape hatch when a proposal is rejected or an upload is abandoned:
/// without it a prepared batch blocks every further sync. Guarded like a sync,
/// so the developer who prepared it can clean up without a proposal.
pub fn discard_proposed_state() {
    STATE.with_borrow_mut(|s| s.discard_proposed_state())
}

/// `#[update(guard = ...)]` guard restricting a call to the governance approver.
pub fn guard_is_governance() -> Result<(), String> {
    let caller = msg_caller();
    if STATE.with_borrow(|s| s.is_governance_approver(&caller)) {
        Ok(())
    } else {
        Err("Caller is not the governance approver.".to_string())
    }
}

/// `#[update(guard = ...)]` guard over every asset-sync operation.
pub fn guard_can_sync() -> Result<(), String> {
    if can_sync() {
        Ok(())
    } else {
        Err("Caller is not authorized to sync assets and is not a controller.".to_string())
    }
}

/// `#[update(guard = ...)]` guard restricting a call to this canister's
/// administrators: its controllers, plus the governance approver when one is
/// configured (see [`is_owner`]).
pub fn guard_is_controller() -> Result<(), String> {
    if is_owner(&msg_caller()) {
        Ok(())
    } else {
        Err("Caller is not a controller.".to_string())
    }
}

/// Recaptures the environment snapshot and re-certifies everything it touches:
/// every `text/html` asset (whose effective header set now carries the cookie)
/// and the redirect-rule entries (a 200-rewrite to an HTML asset borrows it).
/// Controller-guarded at the endpoint; icp-cli calls this during deploy once the
/// `PUBLIC_*` env vars are set.
pub fn refresh_env() {
    let env = CanisterEnv::load(); // replicated context — system API is readable
    STATE.with_borrow_mut(|s| {
        s.refresh_env(&env);
        certified_data_set(s.root_hash());
    });
}

/// Rebuilds derived heap state (the certified-response tree) from the durable
/// state already present in stable memory, then re-publishes `certified_data`.
///
/// There is no `pre_upgrade`: settings, asset metadata, and content live in
/// stable memory and survive the upgrade untouched. The authorized set is left
/// as-is; change it after upgrade via `authorize`/`deauthorize`.
///
/// The env cookie is *derived* heap state, wiped by the upgrade, so we recapture
/// it from the live system API and store it **before** the rebuild — otherwise
/// `post_upgrade_rebuild` would re-certify every HTML asset without the cookie
/// and it would silently vanish until the next `refresh_env`.
pub fn post_upgrade() {
    let env = CanisterEnv::load(); // replicated context — system API is readable
    STATE.with_borrow_mut(|s| {
        s.store_env(&env);
        s.post_upgrade_rebuild();
        certified_data_set(s.root_hash());
    });
}

/// Loops calling a state machine function until completion, periodically async-calling
/// self to reset the instruction counter when needed.
async fn loop_with_message_extension_until_completion<F, D, P, E>(mut compute_fn: F) -> Result<D, E>
where
    F: FnMut(P) -> ComputationStatus<D, P, E>,
    P: Default,
{
    const INSTRUCTION_THRESHOLD: u64 = 35_000_000_000; // At the time of writing, 40b instructions are the limit for single message
    let mut progress = P::default();

    loop {
        match compute_fn(progress) {
            ComputationStatus::Done(done) => return Ok(done),
            ComputationStatus::InProgress(p) => {
                progress = p;
                if ic_cdk::api::performance_counter(0) > INSTRUCTION_THRESHOLD {
                    // Reset instruction counter 0 by doing a bogus self-call
                    // (self-calls are most likely to be short-circuited by the scheduler so we don't incur more wait time than necessary)
                    let _ = ic_cdk::call::Call::bounded_wait(
                        ic_cdk::api::canister_self(),
                        "__this-FunctionDoes_not-Exist",
                    )
                    .await;
                }
            }
            ComputationStatus::Error(e) => return Err(e),
        }
    }
}
