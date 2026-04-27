//! Wrappers around the host's `canister-call` import.
//!
//! Most calls use `direct: true` (bypass proxy). Permission bootstrap calls
//! in proxy mode use `direct: false` so the proxy canister, which is the
//! controller, can authorise them.

use candid::{CandidType, Decode, Encode, Nat, Principal};
use serde::de::DeserializeOwned;

use crate::icp::sync_plugin::types as ty;
use crate::types::{
    AssetDetails, CommitBatchArguments, CreateBatchRequest, CreateBatchResponse,
    CreateChunkRequest, CreateChunkResponse, GrantPermissionArguments, ListAssetsRequest,
    ListPermittedArguments, Permission,
};
use crate::{canister_call, CanisterCallRequest};

fn call<A, R>(method: &str, arg: A, call_type: ty::CallType) -> Result<R, String>
where
    A: CandidType,
    R: CandidType + DeserializeOwned,
{
    let arg_bytes = Encode!(&arg).map_err(|e| format!("encode arg for {method}: {e}"))?;
    let req = CanisterCallRequest {
        method: method.to_string(),
        arg: arg_bytes,
        call_type: Some(call_type),
        direct: true,
    };
    let bytes = canister_call(&req).map_err(|e| format!("{method}: {e}"))?;
    Decode!(&bytes, R).map_err(|e| format!("decode reply from {method}: {e}"))
}

fn call_void<A>(method: &str, arg: A, call_type: ty::CallType) -> Result<(), String>
where
    A: CandidType,
{
    let arg_bytes = Encode!(&arg).map_err(|e| format!("encode arg for {method}: {e}"))?;
    let req = CanisterCallRequest {
        method: method.to_string(),
        arg: arg_bytes,
        call_type: Some(call_type),
        direct: true,
    };
    let bytes = canister_call(&req).map_err(|e| format!("{method}: {e}"))?;
    Decode!(&bytes).map_err(|e| format!("decode reply from {method}: {e}"))
}

pub fn api_version() -> Result<u16, String> {
    call::<(), u16>("api_version", (), ty::CallType::Query)
}

pub fn list_assets() -> Result<Vec<AssetDetails>, String> {
    let mut all: Vec<AssetDetails> = Vec::new();
    let mut start: u64 = 0;
    let mut prev_page_size: Option<usize> = None;

    loop {
        let req = ListAssetsRequest {
            start: Some(Nat::from(start)),
            length: None,
        };
        let entries: Vec<AssetDetails> = call("list", req, ty::CallType::Query)?;

        let n = entries.len();
        if n == 0 {
            break;
        }
        if start > 0 && entries == all {
            break;
        }
        start += n as u64;
        all.extend(entries);
        if let Some(prev) = prev_page_size {
            if n < prev {
                break;
            }
        }
        prev_page_size = Some(n);
    }

    Ok(all)
}

pub fn create_batch() -> Result<Nat, String> {
    let resp: CreateBatchResponse =
        call("create_batch", CreateBatchRequest {}, ty::CallType::Update)?;
    Ok(resp.batch_id)
}

pub fn create_chunk(batch_id: &Nat, content: &[u8]) -> Result<Nat, String> {
    let req = CreateChunkRequest {
        batch_id: batch_id.clone(),
        content,
    };
    let resp: CreateChunkResponse = call("create_chunk", req, ty::CallType::Update)?;
    Ok(resp.chunk_id)
}

pub fn commit_batch(args: CommitBatchArguments) -> Result<(), String> {
    call_void("commit_batch", args, ty::CallType::Update)
}

pub fn list_permitted(permission: Permission) -> Result<Vec<Principal>, String> {
    call::<_, Vec<Principal>>(
        "list_permitted",
        ListPermittedArguments { permission },
        ty::CallType::Update,
    )
}

// Routes through the proxy (direct: false) so the proxy canister — the
// controller — can authorise the call on the assets canister.
pub fn grant_permission_via_proxy(
    to_principal: Principal,
    permission: Permission,
) -> Result<(), String> {
    let arg_bytes = Encode!(&GrantPermissionArguments {
        to_principal,
        permission
    })
    .map_err(|e| format!("encode arg for grant_permission: {e}"))?;
    let req = CanisterCallRequest {
        method: "grant_permission".to_string(),
        arg: arg_bytes,
        call_type: Some(ty::CallType::Update),
        direct: false,
    };
    let bytes = canister_call(&req).map_err(|e| format!("grant_permission: {e}"))?;
    Decode!(&bytes).map_err(|e| format!("decode reply from grant_permission: {e}"))
}
