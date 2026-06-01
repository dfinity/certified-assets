//! Runtime context exposed to state-machine entry points.
//!
//! [`SystemContext`] is a small bundle of values that the state machine needs
//! but should not read from `ic_cdk` directly (so the state machine can stay
//! pure and testable). [`CanisterEnv`] is a snapshot of the canister-scoped
//! environment (root key + public env vars) that gets folded into the
//! per-asset `ic_env` cookie.

use crate::url::url_encode;
use ic_cdk::api::{env_var_count, env_var_name, env_var_value, root_key, time};
use std::cell::{Ref, RefCell};
use std::collections::BTreeMap;

const PUBLIC_ENV_VAR_NAME_PREFIX: &str = "PUBLIC_";

const IC_ROOT_KEY_VALUE_KEY: &str = "ic_root_key";
const COOKIE_VALUES_SEPARATOR: &str = "&";

/// Context that is available only inside canister runtime.
pub struct SystemContext {
    canister_env: RefCell<Option<CanisterEnv>>,
    pub current_timestamp_ns: u64,
}

impl SystemContext {
    pub fn new() -> Self {
        Self {
            // We do not load the canister env here, because it might not be needed.
            // Users should call [Self::get_canister_env] to get the canister env,
            // which takes care of loading the canister env if it is not already loaded.
            canister_env: RefCell::new(None),
            current_timestamp_ns: time(),
        }
    }

    #[cfg(test)]
    pub fn new_with_options(canister_env: Option<CanisterEnv>, current_timestamp_ns: u64) -> Self {
        Self {
            canister_env: RefCell::new(canister_env),
            current_timestamp_ns,
        }
    }

    /// Returns the current canister environment, loading it if it is not already loaded.
    pub fn get_canister_env(&self) -> Ref<'_, CanisterEnv> {
        if self.canister_env.borrow().is_none() {
            let canister_env = CanisterEnv::load();
            self.canister_env.borrow_mut().replace(canister_env);
        }
        Ref::map(self.canister_env.borrow(), |opt| {
            opt.as_ref().expect("CanisterEnv should be initialized")
        })
    }

    pub fn instruction_counter(&self) -> u64 {
        #[cfg(target_arch = "wasm32")]
        {
            ic_cdk::api::performance_counter(0)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // For tests/non-wasm, return 0 or a mock value if needed.
            // Since we don't have a mock setup here yet, 0 is safe as it won't trigger limits.
            0
        }
    }
}

impl Default for SystemContext {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CanisterEnv {
    pub ic_root_key: Vec<u8>,
    /// We can expect a maximum of 20 entries, each with a maximum of 128 characters
    /// for both the key and the value. Total size: 20 * 128 * 2 = 4096 bytes
    ///
    /// Numbers from https://github.com/dfinity/ic/blob/34bd4301f941cdfa1596a0eecf9f58ad6407293c/rs/config/src/execution_environment.rs#L175-L183
    pub icp_public_env_vars: BTreeMap<String, String>,
}

impl CanisterEnv {
    pub fn load() -> Self {
        Self {
            ic_root_key: root_key(),
            icp_public_env_vars: load_icp_public_env_vars(),
        }
    }

    pub fn to_cookie_value(&self) -> String {
        let hex_root_key = hex::encode(&self.ic_root_key);
        let root_key_value = format!("{IC_ROOT_KEY_VALUE_KEY}={hex_root_key}");

        let mut values = vec![root_key_value];

        let icp_public_env_vars = self
            .icp_public_env_vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>();
        values.extend(icp_public_env_vars);

        let cookie_value = values.join(COOKIE_VALUES_SEPARATOR);

        url_encode(&cookie_value)
    }
}

fn load_icp_public_env_vars() -> BTreeMap<String, String> {
    let mut public_env_vars = BTreeMap::new();
    let env_var_count = env_var_count();

    for i in 0..env_var_count {
        let name = env_var_name(i);
        if name.starts_with(PUBLIC_ENV_VAR_NAME_PREFIX) {
            let value = env_var_value(&name);
            public_env_vars.insert(name, value);
        }
    }
    public_env_vars
}
