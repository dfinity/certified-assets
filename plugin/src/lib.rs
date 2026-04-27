//! Sync plugin for the certified-assets canister, invoked by `icp deploy`.

// wit_bindgen generates code that triggers clippy warnings, so we allow them here.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    world: "sync-plugin",
    path: "wit/sync-plugin.wit",
});

mod call;
mod content;
mod gather;
mod types;
mod upload;

struct Plugin;

impl Guest for Plugin {
    fn exec(input: SyncExecInput) -> Result<Option<String>, String> {
        println!(
            "sync plugin: starting for canister {} (environment: {})",
            input.canister_id, input.environment
        );
        let summary = upload::run(
            &input.dirs,
            &input.identity_principal,
            input.proxy_canister_id.as_deref(),
        )?;
        Ok(Some(summary))
    }
}

export!(Plugin);
