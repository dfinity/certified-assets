//! Sync plugin for the certified-assets canister, invoked by `icp deploy`.

// wit_bindgen generates code that triggers clippy warnings, so we allow them here.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    world: "sync-plugin",
    path: "wit/sync-plugin.wit",
});

mod wasi_canister;

struct Plugin;

impl Guest for Plugin {
    fn exec(input: SyncExecInput) -> Result<Option<String>, String> {
        use crate::wasi_canister::WasiCanister;
        println!(
            "sync plugin: starting for canister {} (environment: {})",
            input.canister_id, input.environment
        );
        let summary = assets_sync::sync::sync(
            &WasiCanister,
            &input.dirs,
            &input.identity_principal,
            input.proxy_canister_id.as_deref(),
        )?;
        Ok(Some(summary))
    }
}

export!(Plugin);
