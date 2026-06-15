//! This module declares canister methods expected by the assets canister client.
mod asset;
mod certification;
mod http;
mod nested_tree;
mod rc_bytes;
mod redirect;
mod runtime;
mod stable_store;
mod state;
mod sync;
mod url;

#[cfg(test)]
mod tests;

use crate::{
    http::CallbackFunc,
    runtime::{CanisterEnv, SystemContext},
    state::State,
    sync::ComputationStatus,
};
use candid::Principal;
use ic_cdk::api::{canister_self, certified_data_set, data_certificate, msg_caller, trap};
use std::cell::RefCell;

pub use http::{HttpRequest, HttpResponse, StreamingCallbackHttpResponse, StreamingCallbackToken};
pub use wire_types::{
    AssetDetails, ExecuteOperationsArguments, RedirectRule, StartSyncResult, UploadChunksArguments,
};

pub static SUPPORTED_CERTIFICATE_VERSIONS: [u8; 3] = *b"1,2";

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// The bundle tag this canister was built with: the build time as a
/// `YYYYMMDDhhmm` decimal (UTC), or `None` for an unstamped dev build. The sync
/// plugin checks this against its own tag and refuses to proceed on a mismatch.
/// See [`wire_types::BUNDLE_TAG`].
pub fn bundle_tag() -> Option<u64> {
    wire_types::BUNDLE_TAG
}

/// Adds `principal` to the authorized set. Controller-guarded at the endpoint.
pub fn authorize(principal: Principal) {
    with_state_mut(|s| s.authorize(principal))
}

/// Removes `principal` from the authorized set. Controller-guarded at the endpoint.
pub fn deauthorize(principal: Principal) {
    with_state_mut(|s| s.deauthorize(&principal))
}

pub fn list_authorized() -> Vec<Principal> {
    with_state(|s| s.list_authorized())
}

pub fn start_sync() -> StartSyncResult {
    let system_context = SystemContext::new();
    let caller = msg_caller();

    with_state_mut(|s| {
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

pub fn upload_chunks(arg: UploadChunksArguments) {
    let system_context = SystemContext::new();

    with_state_mut(|s| {
        if let Err(msg) = s.upload_chunks(arg, &system_context) {
            trap(&msg);
        }
    })
}

pub async fn execute_operations(arg: ExecuteOperationsArguments) {
    let system_context = SystemContext::new();
    let arg_ref = &arg;

    loop_with_message_extension_until_completion(|progress| {
        with_state_mut(|s| s.execute_operations(arg_ref, progress, &system_context))
    })
    .await
    .map_err(|msg| trap(&msg))
    .ok();

    with_state_mut(|s| certified_data_set(s.root_hash()));
}

pub fn get_asset_details(start_after: Option<String>) -> Vec<AssetDetails> {
    with_state(|s| s.get_asset_details(start_after))
}

pub fn get_redirect_rules(start_index: u64) -> Vec<RedirectRule> {
    with_state(|s| s.get_redirect_rules(start_index))
}

pub fn http_request(req: HttpRequest) -> HttpResponse {
    if req.certificate_version != Some(2) {
        trap("Only support V2 certification");
    }
    let certificate = data_certificate().unwrap_or_else(|| trap("no data certificate available"));

    with_state(|s| {
        s.http_request(
            req,
            &certificate,
            CallbackFunc::new(
                canister_self(),
                "http_request_streaming_callback".to_string(),
            ),
        )
    })
}

pub fn http_request_streaming_callback(
    token: StreamingCallbackToken,
) -> Option<StreamingCallbackHttpResponse> {
    with_state(|s| {
        Some(
            s.http_request_streaming_callback(token)
                .unwrap_or_else(|msg| trap(&msg)),
        )
    })
}

/// Whether the current caller may sync assets: either in the authorized set, or
/// a canister controller. The authorized set holds only the extra (non-controller)
/// principals — controllers are always allowed without being stored.
pub fn can_sync() -> bool {
    let caller = msg_caller();
    with_state(|s| s.is_authorized(&caller)) || ic_cdk::api::is_controller(&caller)
}

/// `#[update(guard = ...)]` guard over every asset-sync operation.
pub fn guard_can_sync() -> Result<(), String> {
    if can_sync() {
        Ok(())
    } else {
        Err("Caller is not authorized to sync assets and is not a controller.".to_string())
    }
}

/// `#[update(guard = ...)]` guard restricting a call to canister controllers.
pub fn guard_is_controller() -> Result<(), String> {
    let caller = msg_caller();
    if ic_cdk::api::is_controller(&caller) {
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
    with_state_mut(|s| {
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
    with_state_mut(|s| {
        s.store_env(&env);
        s.post_upgrade_rebuild();
        certified_data_set(s.root_hash());
    });
}

fn with_state_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| f(&mut s.borrow_mut()))
}

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&State) -> R,
{
    STATE.with(|s| f(&s.borrow()))
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
