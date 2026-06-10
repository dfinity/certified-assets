mod state;

use candid::Principal;
use canister_core::{
    guard_can_sync, guard_is_controller,
    http::{HttpRequest, HttpResponse, StreamingCallbackHttpResponse, StreamingCallbackToken},
    redirect::RedirectRule,
    types::{
        AssetDetails, CancelSyncArguments, CreateChunksArguments, CreateChunksResponse,
        ExecuteOperationsArguments, StartSyncResult,
    },
};
use ic_cdk::{post_upgrade, pre_upgrade, query, update};

use crate::state::{load_stable_state, save_stable_state};

#[pre_upgrade]
fn pre_upgrade() {
    let stable_state = canister_core::pre_upgrade();
    save_stable_state(&stable_state).expect("failed to serialize stable state");
}

#[post_upgrade]
fn post_upgrade() {
    let stable_state = load_stable_state().expect("failed to deserialize stable state");
    canister_core::post_upgrade(stable_state);
}

#[cfg(target_family = "wasm")]
#[used]
#[unsafe(link_section = "icp:public supported_certificate_versions")]
static CERTIFICATE_VERSIONS: [u8; 3] = canister_core::SUPPORTED_CERTIFICATE_VERSIONS;

// Query methods

#[query]
fn api_version() -> u16 {
    canister_core::api_version()
}

#[query]
fn get_asset_details(start_after: Option<String>) -> Vec<AssetDetails> {
    canister_core::get_asset_details(start_after)
}

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    canister_core::http_request(req)
}

#[query]
fn http_request_streaming_callback(
    token: StreamingCallbackToken,
) -> Option<StreamingCallbackHttpResponse> {
    canister_core::http_request_streaming_callback(token)
}

#[query]
fn get_redirect_rules(start_index: u64) -> Vec<RedirectRule> {
    canister_core::get_redirect_rules(start_index)
}

// Update methods

#[update(guard = "guard_is_controller")]
fn authorize(principal: Principal) {
    canister_core::authorize(principal)
}

#[update(guard = "guard_is_controller")]
fn deauthorize(principal: Principal) {
    canister_core::deauthorize(principal)
}

#[update]
fn list_authorized() -> Vec<Principal> {
    canister_core::list_authorized()
}

// Whether the calling identity may sync assets (authorized or a controller).
// Lets a client check access up front instead of discovering it mid-sync.
#[query]
fn can_sync() -> bool {
    canister_core::can_sync()
}

#[update(guard = "guard_can_sync")]
fn start_sync() -> StartSyncResult {
    canister_core::start_sync()
}

#[update(guard = "guard_can_sync")]
fn create_chunks(arg: CreateChunksArguments) -> CreateChunksResponse {
    canister_core::create_chunks(arg)
}

#[update(guard = "guard_can_sync")]
async fn execute_operations(arg: ExecuteOperationsArguments) {
    canister_core::execute_operations(arg).await
}

#[update(guard = "guard_can_sync")]
fn cancel_sync(arg: CancelSyncArguments) {
    canister_core::cancel_sync(arg)
}

ic_cdk::export_candid!();

#[test]
fn candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    let new_interface = __export_service();

    // crates/canister -> crates -> workspace root, then candid/assets.did
    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../candid/assets.did");

    println!("Exported interface: {new_interface}");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("The assets canister interface is not compatible with the assets.did file");
}
