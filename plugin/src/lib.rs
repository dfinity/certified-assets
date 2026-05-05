//! Sync plugin for the certified-assets canister, invoked by `icp deploy`.

// wit_bindgen generates code that triggers clippy warnings, so we allow them here.
#![allow(clippy::too_many_arguments)]
// In test builds the WIT entry point (exec) is cfg-guarded, so the production
// call path appears unused. Suppress the noise; the cdylib build is authoritative.
#![cfg_attr(test, allow(dead_code))]

wit_bindgen::generate!({
    world: "sync-plugin",
    path: "wit/sync-plugin.wit",
});

mod canister;
mod content;
mod scan;
mod sync;

struct Plugin;

// `impl Guest` and `export!` reference WasiCanister, which only implements
// CanisterCall in non-test builds (its impl drives the WIT `canister-call` import).
#[cfg(not(test))]
impl Guest for Plugin {
    fn exec(input: SyncExecInput) -> Result<Option<String>, String> {
        use crate::canister::WasiCanister;
        println!(
            "sync plugin: starting for canister {} (environment: {})",
            input.canister_id, input.environment
        );
        let summary = sync::sync(
            &WasiCanister,
            &input.dirs,
            &input.identity_principal,
            input.proxy_canister_id.as_deref(),
        )?;
        Ok(Some(summary))
    }
}

#[cfg(not(test))]
export!(Plugin);
