mod state;

use candid::Principal;
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_certified_assets::{
    asset::{AssetDetails, EncodedAsset},
    can_commit, can_prepare,
    certification::AssetKey,
    http::{HttpRequest, HttpResponse, StreamingCallbackHttpResponse, StreamingCallbackToken},
    is_controller, is_manager_or_controller,
    rc_bytes::RcBytes,
    state::CertifiedTree,
    types::{
        AssetCanisterArgs, AssetProperties, CommitBatchArguments, ConfigurationResponse,
        ConfigureArguments, CreateAssetArguments, CreateBatchResponse, CreateChunksArg,
        CreateChunksResponse, DeleteAssetArguments, DeleteBatchArguments, GetArg, GetChunkArg,
        GetChunkResponse, GrantPermissionArguments, ListPermittedArguments, ListRequest,
        RevokePermissionArguments, SetAssetContentArguments, SetAssetPropertiesArguments,
        StateInfo, StoreArg, UnsetAssetContentArguments,
    },
};

use crate::state::{load_stable_state, save_stable_state};

#[init]
fn init(args: Option<AssetCanisterArgs>) {
    ic_certified_assets::init(args);
}

#[pre_upgrade]
fn pre_upgrade() {
    let stable_state = ic_certified_assets::pre_upgrade();
    save_stable_state(&stable_state).expect("failed to serialize stable state");
}

#[post_upgrade]
fn post_upgrade(args: Option<AssetCanisterArgs>) {
    let stable_state = load_stable_state().expect("failed to deserialize stable state");
    ic_certified_assets::post_upgrade(stable_state, args);
}

#[cfg(target_family = "wasm")]
#[used]
#[unsafe(link_section = "icp:public supported_certificate_versions")]
static CERTIFICATE_VERSIONS: [u8; 3] = ic_certified_assets::SUPPORTED_CERTIFICATE_VERSIONS;

// Query methods

#[query]
fn api_version() -> u16 {
    ic_certified_assets::api_version()
}

#[query]
fn retrieve(key: AssetKey) -> RcBytes {
    ic_certified_assets::retrieve(key)
}

#[query]
fn get(arg: GetArg) -> EncodedAsset {
    ic_certified_assets::get(arg)
}

#[query]
fn get_chunk(arg: GetChunkArg) -> GetChunkResponse {
    ic_certified_assets::get_chunk(arg)
}

#[query]
fn list(request: ListRequest) -> Vec<AssetDetails> {
    ic_certified_assets::list(request)
}

#[query]
fn certified_tree() -> CertifiedTree {
    ic_certified_assets::certified_tree()
}

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    ic_certified_assets::http_request(req)
}

#[query]
fn http_request_streaming_callback(
    token: StreamingCallbackToken,
) -> Option<StreamingCallbackHttpResponse> {
    ic_certified_assets::http_request_streaming_callback(token)
}

#[query]
fn get_asset_properties(key: AssetKey) -> AssetProperties {
    ic_certified_assets::get_asset_properties(key)
}

#[query]
fn get_state_info() -> StateInfo {
    ic_certified_assets::get_state_info()
}

// Update methods

#[update(guard = "is_manager_or_controller")]
fn authorize(other: Principal) {
    ic_certified_assets::authorize(other)
}

#[update(guard = "is_manager_or_controller")]
fn grant_permission(arg: GrantPermissionArguments) {
    ic_certified_assets::grant_permission(arg)
}

#[update]
async fn deauthorize(other: Principal) {
    ic_certified_assets::deauthorize(other).await
}

#[update]
async fn revoke_permission(arg: RevokePermissionArguments) {
    ic_certified_assets::revoke_permission(arg).await
}

#[update]
fn list_authorized() -> Vec<Principal> {
    ic_certified_assets::list_authorized()
}

#[update]
fn list_permitted(arg: ListPermittedArguments) -> Vec<Principal> {
    ic_certified_assets::list_permitted(arg)
}

#[update(guard = "is_controller")]
async fn take_ownership() {
    ic_certified_assets::take_ownership().await
}

#[update(guard = "can_commit")]
fn store(arg: StoreArg) {
    ic_certified_assets::store(arg)
}

#[update(guard = "can_prepare")]
fn create_batch() -> CreateBatchResponse {
    ic_certified_assets::create_batch()
}

#[update(guard = "can_prepare")]
fn create_chunks(arg: CreateChunksArg) -> CreateChunksResponse {
    ic_certified_assets::create_chunks(arg)
}

#[update(guard = "can_commit")]
fn create_asset(arg: CreateAssetArguments) {
    ic_certified_assets::create_asset(arg)
}

#[update(guard = "can_commit")]
fn set_asset_content(arg: SetAssetContentArguments) {
    ic_certified_assets::set_asset_content(arg)
}

#[update(guard = "can_commit")]
fn unset_asset_content(arg: UnsetAssetContentArguments) {
    ic_certified_assets::unset_asset_content(arg)
}

#[update(guard = "can_commit")]
fn delete_asset(arg: DeleteAssetArguments) {
    ic_certified_assets::delete_asset(arg)
}

#[update(guard = "can_commit")]
fn clear() {
    ic_certified_assets::clear()
}

#[update(guard = "can_commit")]
async fn commit_batch(arg: CommitBatchArguments) {
    ic_certified_assets::commit_batch(arg).await
}

#[update]
async fn compute_state_hash() -> Option<String> {
    ic_certified_assets::compute_state_hash().await
}

#[update(guard = "can_prepare")]
fn delete_batch(arg: DeleteBatchArguments) {
    ic_certified_assets::delete_batch(arg)
}

#[update(guard = "can_commit")]
fn set_asset_properties(arg: SetAssetPropertiesArguments) {
    ic_certified_assets::set_asset_properties(arg)
}

#[update(guard = "can_prepare")]
fn get_configuration() -> ConfigurationResponse {
    ic_certified_assets::get_configuration()
}

#[update(guard = "can_commit")]
fn configure(arg: ConfigureArguments) {
    ic_certified_assets::configure(arg)
}

ic_cdk::export_candid!();

#[test]
fn candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    let new_interface = __export_service();

    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets.did");

    println!("Exported interface: {new_interface}");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("The assets canister interface is not compatible with the assets.did file");
}
