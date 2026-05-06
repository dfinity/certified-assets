//! Sync plugin for the certified-assets canister, invoked by `icp deploy`.

// wit_bindgen generates code that triggers clippy warnings, so we allow them here.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    world: "sync-plugin",
    path: "wit/sync-plugin.wit",
});

use assets_sync::canister::{CallType, CanisterCall};
use candid::{CandidType, Decode, Encode};
use serde::de::DeserializeOwned;

use crate::icp::sync_plugin::types as ty;

struct WasiCall;

impl CanisterCall for WasiCall {
    fn call<A, R>(
        &self,
        method: &str,
        arg: A,
        call_type: CallType,
        direct: bool,
    ) -> Result<R, String>
    where
        A: CandidType,
        R: CandidType + DeserializeOwned,
    {
        let arg_bytes = Encode!(&arg).map_err(|e| format!("encode arg for {method}: {e}"))?;
        let req = CanisterCallRequest {
            method: method.to_string(),
            arg: arg_bytes,
            call_type: match call_type {
                CallType::Update => ty::CallType::Update,
                CallType::Query => ty::CallType::Query,
            },
            direct,
            cycles: 0,
        };
        let bytes = canister_call(&req).map_err(|e| format!("{method}: {e}"))?;
        Decode!(&bytes, R).map_err(|e| format!("decode reply from {method}: {e}"))
    }
}

struct Plugin;

impl Guest for Plugin {
    fn exec(input: SyncExecInput) -> Result<Option<String>, String> {
        println!(
            "sync plugin: starting for canister {} (environment: {})",
            input.canister_id, input.environment
        );
        let summary = assets_sync::sync::sync(
            &WasiCall,
            &input.dirs,
            &input.identity_principal,
            input.proxy_canister_id.as_deref(),
        )?;
        Ok(Some(summary))
    }
}

export!(Plugin);
