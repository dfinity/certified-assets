//! Sync plugin for the certified-assets canister, invoked by `icp deploy`.

// wit_bindgen generates code that triggers clippy warnings, so we allow them here.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    world: "sync-plugin",
    path: "wit/sync-plugin.wit",
});
use crate::icp::sync_plugin::types as ty;

use sync_core::{Call, CallType, CanisterCall, Compressors, sync};

struct WasiCall;

impl CanisterCall for WasiCall {
    fn dispatch(&self, call: Call) -> Result<Vec<u8>, String> {
        // Encode/Decode now live in the trait's default `call`; this transport
        // only moves the already-encoded bytes across the host boundary.
        let req = CanisterCallRequest {
            method: call.method.clone(),
            arg: call.arg,
            call_type: match call.call_type {
                CallType::Update => ty::CallType::Update,
                CallType::Query => ty::CallType::Query,
            },
            direct: call.direct,
            cycles: 0,
        };
        canister_call(&req).map_err(|e| format!("{}: {e}", call.method))
    }

    // `dispatch_batch` inherits the sequential default on purpose: keeping the
    // plugin sequential is zero runtime work today. When the icp-cli runtime
    // gains a `canister-call-batch` host import, override `dispatch_batch` here
    // to fan the calls out concurrently — and touch nothing else in this repo.
}

struct Plugin;

impl Guest for Plugin {
    fn exec(input: SyncExecInput) -> Result<(), String> {
        println!(
            "sync plugin: starting for canister {} (environment: {})",
            input.canister_id, input.environment
        );
        // Always the canonical registry — gzip + brotli q11. Cheaper compressors
        // are a deploy-time trade a *platform* makes for builds it knows nobody
        // browses (see `asset-prep::Compressors`); every `icp deploy` serves real
        // visitors, so the plugin never offers the choice — the cost would land on
        // them, not on whoever typed the command. It is also what keeps every
        // `icp deploy` reproducible by the stock `state-hash` verifier.
        let summary = sync(
            &WasiCall,
            &input.dirs,
            &input.identity_principal,
            input.proxy_canister_id.as_deref(),
            &Compressors::canonical(),
        )?;
        eprintln!("{summary}");
        Ok(())
    }
}

export!(Plugin);
