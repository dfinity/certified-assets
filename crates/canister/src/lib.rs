use candid::Principal;
use canister_core::{
    guard_can_sync, guard_is_controller, AssetDetails, ExecuteOperationsArguments, RedirectRule,
    StartSyncResult, UploadChunksArguments, Version,
    {HttpRequest, HttpResponse, StreamingCallbackHttpResponse, StreamingCallbackToken},
};
use ic_cdk::{post_upgrade, query, update};

#[post_upgrade]
fn post_upgrade() {
    canister_core::post_upgrade();
}

#[cfg(target_family = "wasm")]
#[used]
#[unsafe(link_section = "icp:public supported_certificate_versions")]
static CERTIFICATE_VERSIONS: [u8; 3] = canister_core::SUPPORTED_CERTIFICATE_VERSIONS;

// Query methods

#[query]
fn version() -> Version {
    canister_core::version()
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

// Recaptures the `PUBLIC_*` env vars + IC root key and re-certifies the `ic_env`
// cookie onto every HTML response. Any sync-authorized caller may trigger it
// (same guard as a sync) — only controllers can *change* the env vars, but an
// authorized syncer should be able to re-publish them. The env is also captured
// at the start of every sync, so this is only needed to publish an env-var
// change without a content sync.
#[update(guard = "guard_can_sync")]
fn refresh_env() {
    canister_core::refresh_env()
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
fn upload_chunks(arg: UploadChunksArguments) {
    canister_core::upload_chunks(arg)
}

#[update(guard = "guard_can_sync")]
async fn execute_operations(arg: ExecuteOperationsArguments) {
    canister_core::execute_operations(arg).await
}

ic_cdk::export_candid!();

#[test]
fn candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    let new_interface = __export_service();

    // crates/canister -> crates -> workspace root, then certified-assets.did
    let old_interface = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../certified-assets.did");

    println!("Exported interface: {new_interface}");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("The assets canister interface is not compatible with the certified-assets.did file");
}
