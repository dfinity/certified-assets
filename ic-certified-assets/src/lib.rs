//! This module declares canister methods expected by the assets canister client.
pub mod asset;
pub mod batch;
pub mod certification;
mod cookies;
pub mod http;
pub mod nested_tree;
pub mod rc_bytes;
pub mod stable;
pub mod state;
pub mod state_hash;
pub mod system_context;
pub mod types;
mod url;

#[cfg(test)]
mod tests;

pub use crate::stable::StableState;
use crate::{
    asset::{AssetDetails, EncodedAsset},
    batch::ComputationStatus,
    certification::AssetKey,
    http::{
        CallbackFunc, HttpRequest, HttpResponse, StreamingCallbackHttpResponse,
        StreamingCallbackToken,
    },
    rc_bytes::RcBytes,
    state::{CertifiedTree, State},
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

pub fn api_version() -> u16 {
    2
}

pub fn authorize(other: Principal) {
    with_state_mut(|s| s.grant_permission(other, &Permission::Commit))
}

pub fn grant_permission(arg: GrantPermissionArguments) {
    with_state_mut(|s| s.grant_permission(arg.to_principal, &arg.permission))
}

pub async fn validate_grant_permission(arg: GrantPermissionArguments) -> Result<String, String> {
    Ok(format!(
        "grant {} permission to principal {}",
        arg.permission, arg.to_principal
    ))
}

pub async fn deauthorize(other: Principal) {
    let check_access_result = if other == msg_caller() {
        // this isn't "ManagePermissions" because these legacy methods only
        // deal with the Commit permission
        has_permission_or_is_controller(&Permission::Commit)
    } else {
        is_controller()
    };
    match check_access_result {
        Err(e) => trap(&e),
        Ok(_) => with_state_mut(|s| s.revoke_permission(other, &Permission::Commit)),
    }
}

pub async fn revoke_permission(arg: RevokePermissionArguments) {
    let check_access_result = if arg.of_principal == msg_caller() {
        has_permission_or_is_controller(&arg.permission)
    } else {
        has_permission_or_is_controller(&Permission::ManagePermissions)
    };
    match check_access_result {
        Err(e) => trap(&e),
        Ok(_) => with_state_mut(|s| s.revoke_permission(arg.of_principal, &arg.permission)),
    }
}

pub async fn validate_revoke_permission(arg: RevokePermissionArguments) -> Result<String, String> {
    Ok(format!(
        "revoke {} permission from principal {}",
        arg.permission, arg.of_principal
    ))
}

pub fn list_authorized() -> Vec<Principal> {
    with_state(|s| {
        s.list_permitted(&Permission::Commit)
            .iter()
            .cloned()
            .collect()
    })
}

pub fn list_permitted(arg: ListPermittedArguments) -> Vec<Principal> {
    with_state(|s| s.list_permitted(&arg.permission).iter().cloned().collect())
}

pub async fn take_ownership() {
    let caller = msg_caller();
    with_state_mut(|s| s.take_ownership(caller))
}

pub async fn validate_take_ownership() -> Result<String, String> {
    Ok("revoke all permissions, then gives the caller Commit permissions".to_string())
}

pub fn retrieve(key: AssetKey) -> RcBytes {
    with_state(|s| match s.retrieve(&key) {
        Ok(bytes) => bytes,
        Err(msg) => trap(&msg),
    })
}

pub fn store(arg: StoreArg) {
    let system_context = SystemContext::new();

    with_state_mut(|s| {
        if let Err(msg) = s.store(arg, &system_context) {
            trap(&msg);
        }
        certified_data_set(s.root_hash());
    });
}

pub fn create_batch() -> CreateBatchResponse {
    let system_context = SystemContext::new();

    with_state_mut(|s| match s.create_batch(&system_context) {
        Ok(batch_id) => CreateBatchResponse { batch_id },
        Err(msg) => trap(&msg),
    })
}

pub fn create_chunks(arg: CreateChunksArg) -> CreateChunksResponse {
    let system_context = SystemContext::new();

    with_state_mut(|s| match s.create_chunks(arg, &system_context) {
        Ok(chunk_ids) => CreateChunksResponse { chunk_ids },
        Err(msg) => trap(&msg),
    })
}

pub fn create_asset(arg: CreateAssetArguments) {
    with_state_mut(|s| {
        if let Err(msg) = s.create_asset(arg) {
            trap(&msg);
        }
        certified_data_set(s.root_hash());
    })
}

pub fn set_asset_content(arg: SetAssetContentArguments) {
    let system_context = SystemContext::new();

    with_state_mut(|s| {
        if let Err(msg) = s.set_asset_content(arg, &system_context) {
            trap(&msg);
        }
        certified_data_set(s.root_hash());
    })
}

pub fn unset_asset_content(arg: UnsetAssetContentArguments) {
    with_state_mut(|s| {
        if let Err(msg) = s.unset_asset_content(arg) {
            trap(&msg);
        }
        certified_data_set(s.root_hash());
    })
}

pub fn delete_asset(arg: DeleteAssetArguments) {
    with_state_mut(|s| {
        s.delete_asset(arg);
        certified_data_set(s.root_hash());
    });
}

pub fn clear() {
    with_state_mut(|s| {
        s.clear();
        certified_data_set(s.root_hash());
    });
}

pub async fn commit_batch(arg: CommitBatchArguments) {
    let system_context = SystemContext::new();
    let arg_ref = &arg;

    loop_with_message_extension_until_completion(|progress| {
        with_state_mut(|s| s.commit_batch(arg_ref, progress, &system_context))
    })
    .await
    .map_err(|msg| trap(&msg))
    .ok();

    with_state_mut(|s| certified_data_set(s.root_hash()));
}

pub async fn compute_state_hash() -> Option<String> {
    loop_with_message_extension_until_completion(|_progress| {
        with_state_mut(|s| s.compute_state_hash())
    })
    .await
    .ok()
}

pub fn get_state_info() -> StateInfo {
    with_state(|s| s.get_state_info())
}

pub fn delete_batch(arg: DeleteBatchArguments) {
    if let Err(msg) = with_state_mut(|s| s.delete_batch(arg)) {
        trap(&msg);
    }
}

pub fn get(arg: GetArg) -> EncodedAsset {
    with_state(|s| match s.get(arg) {
        Ok(asset) => asset,
        Err(msg) => trap(&msg),
    })
}

pub fn get_chunk(arg: GetChunkArg) -> GetChunkResponse {
    with_state(|s| match s.get_chunk(arg) {
        Ok(content) => GetChunkResponse { content },
        Err(msg) => trap(&msg),
    })
}

pub fn list(request: ListRequest) -> Vec<AssetDetails> {
    with_state(|s| s.list_assets(request))
}

pub fn certified_tree() -> CertifiedTree {
    let certificate = data_certificate().unwrap_or_else(|| trap("no data certificate available"));

    with_state(|s| s.certified_tree(&certificate))
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
) -> StreamingCallbackHttpResponse {
    with_state(|s| {
        s.http_request_streaming_callback(token)
            .unwrap_or_else(|msg| trap(&msg))
    })
}

pub fn get_asset_properties(key: AssetKey) -> AssetProperties {
    with_state(|s| s.get_asset_properties(key).unwrap_or_else(|msg| trap(&msg)))
}

pub fn set_asset_properties(arg: SetAssetPropertiesArguments) {
    with_state_mut(|s| {
        if let Err(msg) = s.set_asset_properties(arg) {
            trap(&msg);
        }
    })
}

pub fn get_configuration() -> ConfigurationResponse {
    with_state(|s| s.get_configuration())
}

pub fn configure(arg: ConfigureArguments) {
    with_state_mut(|s| s.configure(arg))
}

pub fn validate_configure(arg: ConfigureArguments) -> Result<String, String> {
    Ok(format!("configure: {arg:?}"))
}

pub fn can(permission: Permission) -> Result<(), String> {
    with_state(|s| {
        s.can(&msg_caller(), &permission)
            .then_some(())
            .ok_or_else(|| format!("Caller does not have {permission} permission"))
    })
}

pub fn can_commit() -> Result<(), String> {
    can(Permission::Commit)
}

pub fn can_prepare() -> Result<(), String> {
    can(Permission::Prepare)
}

pub fn has_permission_or_is_controller(permission: &Permission) -> Result<(), String> {
    let caller = msg_caller();
    let has_permission = with_state(|s| s.has_permission(&caller, permission));
    let is_controller = ic_cdk::api::is_controller(&caller);
    if has_permission || is_controller {
        Ok(())
    } else {
        Err(format!(
            "Caller does not have {permission} permission and is not a controller."
        ))
    }
}

pub fn is_manager_or_controller() -> Result<(), String> {
    has_permission_or_is_controller(&Permission::ManagePermissions)
}

pub fn is_controller() -> Result<(), String> {
    let caller = msg_caller();
    if ic_cdk::api::is_controller(&caller) {
        Ok(())
    } else {
        Err("Caller is not a controller.".to_string())
    }
}

pub fn init(args: Option<AssetCanisterArgs>) {
    with_state_mut(|s| {
        s.clear();
        s.grant_permission(msg_caller(), &Permission::Commit);
    });

    if let Some(upgrade_arg) = args {
        let AssetCanisterArgs::Init(init_args) = upgrade_arg else {
            ic_cdk::trap(
                "Cannot initialize the canister with an Upgrade argument. Please provide an Init argument.",
            )
        };
        with_state_mut(|s| {
            if let Some(set_permissions) = init_args.set_permissions {
                s.set_permissions(set_permissions);
            }
        });
    }
}

pub fn pre_upgrade() -> StableState {
    STATE.with(|s| s.take().into())
}

pub fn post_upgrade(stable_state: StableState, args: Option<AssetCanisterArgs>) {
    let set_permissions = args.and_then(|args| {
        let AssetCanisterArgs::Upgrade(UpgradeArgs { set_permissions }) = args else {ic_cdk::trap("Cannot upgrade the canister with an Init argument. Please provide an Upgrade argument.")};
        set_permissions
    });

    with_state_mut(|s| {
        *s = State::from(stable_state);
        certified_data_set(s.root_hash());
        if let Some(set_permissions) = set_permissions {
            s.set_permissions(set_permissions);
        }
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
