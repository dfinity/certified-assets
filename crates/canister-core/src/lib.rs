//! This module declares canister methods expected by the assets canister client.
pub mod asset;
pub mod certification;
pub mod http;
pub mod nested_tree;
pub mod rc_bytes;
pub mod redirect;
pub mod stable;
pub mod state;
pub mod sync;
pub mod system_context;
pub mod types;
mod url;

#[cfg(test)]
mod tests;

pub use crate::stable::StableState;
use crate::{
    http::{
        CallbackFunc, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
        StreamingCallbackToken,
    },
    state::State,
    sync::ComputationStatus,
    system_context::SystemContext,
    types::*,
};
use candid::Principal;
use ic_cdk::api::{canister_self, certified_data_set, data_certificate, msg_caller, trap};
use std::cell::RefCell;

pub static SUPPORTED_CERTIFICATE_VERSIONS: [u8; 3] = *b"1,2";

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// The bundle tag this canister was built with: minutes since the Unix epoch
/// (UTC), or `None` for an unstamped dev build. The sync plugin checks this
/// against its own tag and refuses to proceed on a mismatch. See
/// [`wire_types::BUNDLE_TAG`].
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
    with_state(|s| s.list_authorized().iter().cloned().collect())
}

pub fn start_sync() -> StartSyncResult {
    let system_context = SystemContext::new();
    let caller = msg_caller();

    with_state_mut(|s| s.start_sync(caller, &system_context))
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

pub fn get_redirect_rules(start_index: u64) -> Vec<crate::redirect::RedirectRule> {
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

pub fn pre_upgrade() -> StableState {
    STATE.with(|s| s.take().into())
}

pub fn post_upgrade(stable_state: StableState) {
    // The restored authorized set is left untouched; change it after upgrade
    // through the `authorize`/`deauthorize` endpoints.
    with_state_mut(|s| {
        *s = State::from(stable_state);
        certified_data_set(s.root_hash());
    });
}

pub fn with_state_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| f(&mut s.borrow_mut()))
}

pub fn with_state<F, R>(f: F) -> R
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
