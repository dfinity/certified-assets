//! Production implementation of `CanisterCall`: drives the host's `canister-call` WIT import.

use assets_sync::canister::{AssetDetails, CanisterCall, CommitBatchArguments, Permission};
use candid::{CandidType, Decode, Encode, Nat, Principal};
use serde::de::DeserializeOwned;

use crate::icp::sync_plugin::types as ty;
use crate::{canister_call, CanisterCallRequest};

pub struct WasiCanister;

// Internal wire types only needed by the production impl.

#[derive(CandidType, Debug)]
struct ListAssetsRequest {
    start: Option<Nat>,
    length: Option<Nat>,
}

#[derive(CandidType, Debug)]
struct CreateBatchRequest {}

#[derive(CandidType, Debug, serde::Deserialize)]
struct CreateBatchResponse {
    batch_id: Nat,
}

#[derive(CandidType, Debug)]
struct CreateChunkRequest<'a> {
    batch_id: Nat,
    content: &'a [u8],
}

#[derive(CandidType, Debug, serde::Deserialize)]
struct CreateChunkResponse {
    chunk_id: Nat,
}

#[derive(CandidType, Debug)]
struct ListPermittedArguments {
    permission: Permission,
}

#[derive(CandidType, Debug)]
struct GrantPermissionArguments {
    to_principal: Principal,
    permission: Permission,
}

fn call<A, R>(method: &str, arg: A, call_type: ty::CallType) -> Result<R, String>
where
    A: CandidType,
    R: CandidType + DeserializeOwned,
{
    let arg_bytes = Encode!(&arg).map_err(|e| format!("encode arg for {method}: {e}"))?;
    let req = CanisterCallRequest {
        method: method.to_string(),
        arg: arg_bytes,
        call_type,
        direct: true,
        cycles: 0,
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
        call_type,
        direct: true,
        cycles: 0,
    };
    let bytes = canister_call(&req).map_err(|e| format!("{method}: {e}"))?;
    Decode!(&bytes).map_err(|e| format!("decode reply from {method}: {e}"))
}

impl CanisterCall for WasiCanister {
    fn api_version(&self) -> Result<u16, String> {
        call::<(), u16>("api_version", (), ty::CallType::Query)
    }

    // Ported from ic-asset. Unlike ic-asset, which must handle older canister versions
    // that ignore `start`, this plugin targets only the canister in this repo, which
    // always honours pagination.
    fn list_assets(&self) -> Result<Vec<AssetDetails>, String> {
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

    fn create_batch(&self) -> Result<Nat, String> {
        let resp: CreateBatchResponse =
            call("create_batch", CreateBatchRequest {}, ty::CallType::Update)?;
        Ok(resp.batch_id)
    }

    fn create_chunk(&self, batch_id: &Nat, content: &[u8]) -> Result<Nat, String> {
        let req = CreateChunkRequest {
            batch_id: batch_id.clone(),
            content,
        };
        let resp: CreateChunkResponse = call("create_chunk", req, ty::CallType::Update)?;
        Ok(resp.chunk_id)
    }

    fn commit_batch(&self, args: CommitBatchArguments) -> Result<(), String> {
        call_void("commit_batch", args, ty::CallType::Update)
    }

    fn list_permitted(&self, permission: Permission) -> Result<Vec<Principal>, String> {
        call::<_, Vec<Principal>>(
            "list_permitted",
            ListPermittedArguments { permission },
            ty::CallType::Update,
        )
    }

    // Routes through the proxy (direct: false) so the proxy canister — the
    // controller — can authorise the call on the assets canister.
    fn grant_permission_via_proxy(
        &self,
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
            call_type: ty::CallType::Update,
            direct: false,
            cycles: 0,
        };
        let bytes = canister_call(&req).map_err(|e| format!("grant_permission: {e}"))?;
        Decode!(&bytes).map_err(|e| format!("decode reply from grant_permission: {e}"))
    }
}
