//! Assets canister API: Candid wire types and call wrappers.
//!
//! Types are ported from `ic-asset` (`src/canisters/frontend/ic-asset/src/canister_api/`).
//! Only the subset needed for the V2 batch-upload flow is included.
//!
//! Calls wrap the host's `canister-call` import. Most calls use `direct: true`
//! (bypass proxy). Permission bootstrap calls in proxy mode use `direct: false`
//! so the proxy canister, which is the controller, can authorise them.

#![allow(dead_code)]

use candid::{CandidType, Nat, Principal};
use serde::Deserialize;
use std::collections::HashMap;

// --- Candid wire types ---

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct AssetEncodingDetails {
    pub content_encoding: String,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
    pub max_age: Option<u64>,
    pub headers: Option<HashMap<String, String>>,
    pub enable_aliasing: Option<bool>,
    pub allow_raw_access: Option<bool>,
}

#[derive(CandidType, Clone, Debug)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<Nat>,
    pub last_chunk: Option<Vec<u8>>,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Clone, Debug)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct DeleteAssetArguments {
    pub key: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct ClearArguments {}

#[derive(CandidType, Clone, Debug)]
pub struct SetAssetPropertiesArguments {
    pub key: String,
    pub max_age: Option<Option<u64>>,
    pub headers: Option<Option<Vec<(String, String)>>>,
    pub allow_raw_access: Option<Option<bool>>,
    pub is_aliased: Option<Option<bool>>,
}

#[derive(CandidType, Clone, Debug)]
pub enum BatchOperationKind {
    Clear(ClearArguments),
    DeleteAsset(DeleteAssetArguments),
    CreateAsset(CreateAssetArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    SetAssetContent(SetAssetContentArguments),
    SetAssetProperties(SetAssetPropertiesArguments),
}

#[derive(CandidType, Debug)]
pub struct CommitBatchArguments {
    pub batch_id: Nat,
    pub operations: Vec<BatchOperationKind>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub enum Permission {
    Commit,
    ManagePermissions,
    Prepare,
}

// --- Canister call trait ---

pub trait CanisterCall {
    fn api_version(&self) -> Result<u16, String>;
    fn list_assets(&self) -> Result<Vec<AssetDetails>, String>;
    fn create_batch(&self) -> Result<Nat, String>;
    fn create_chunk(&self, batch_id: &Nat, content: &[u8]) -> Result<Nat, String>;
    fn commit_batch(&self, args: CommitBatchArguments) -> Result<(), String>;
    fn list_permitted(&self, permission: Permission) -> Result<Vec<Principal>, String>;
    fn grant_permission_via_proxy(
        &self,
        to_principal: Principal,
        permission: Permission,
    ) -> Result<(), String>;
}

/// Production implementation: drives the host's `canister-call` WIT import.
pub struct WasiCanister;

// The WIT import `canister_call` is an extern resolved only in the wasm32-wasip2
// runtime. Guard the entire implementation so the test binary never references it.
#[cfg(not(test))]
mod wasi_impl {
    use super::*;
    use candid::{Decode, Encode};
    use serde::de::DeserializeOwned;

    use crate::icp::sync_plugin::types as ty;
    use crate::{canister_call, CanisterCallRequest};

    // Internal wire types only needed by the production impl.

    #[derive(CandidType, Debug)]
    struct ListAssetsRequest {
        start: Option<Nat>,
        length: Option<Nat>,
    }

    #[derive(CandidType, Debug)]
    struct CreateBatchRequest {}

    #[derive(CandidType, Debug, Deserialize)]
    struct CreateBatchResponse {
        batch_id: Nat,
    }

    #[derive(CandidType, Debug)]
    struct CreateChunkRequest<'a> {
        batch_id: Nat,
        content: &'a [u8],
    }

    #[derive(CandidType, Debug, Deserialize)]
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

    impl super::CanisterCall for super::WasiCanister {
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
}
