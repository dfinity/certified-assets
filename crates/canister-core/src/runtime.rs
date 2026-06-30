//! Runtime context exposed to state-machine entry points.
//!
//! [`SystemContext`] and [`CanisterEnv`] are bundles of values that the state
//! machine needs but should not read from `ic_cdk` directly (so the state
//! machine can stay pure and testable): the entry layer reads them from the
//! system API in a replicated context and passes them in by argument.

use ic_cdk::api::time;
use std::collections::BTreeMap;

/// Env vars with this prefix (and only these) are exposed to the frontend via
/// the `ic_env` cookie. The prefix is the security boundary between
/// frontend-safe and canister-only configuration.
const PUBLIC_ENV_VAR_PREFIX: &str = "PUBLIC_";

/// Env var holding the cookie-gate secret: the value the `IC_AUTH_TOKEN` cookie
/// must carry for a request to reach a gated asset (see
/// [`crate::state::State`]'s auth-gate handling). It is deliberately **not**
/// `PUBLIC_`-prefixed, so it never leaks into the `ic_env` cookie. An unset or
/// empty value means the gate is off.
const AUTH_TOKEN_ENV_VAR: &str = "IC_AUTH_TOKEN";

/// Context that is available only inside canister runtime.
pub struct SystemContext {
    pub current_timestamp_ns: u64,
}

impl SystemContext {
    pub fn new() -> Self {
        Self {
            current_timestamp_ns: time(),
        }
    }

    #[cfg(any(test, feature = "canbench-rs"))]
    pub fn new_with_options(current_timestamp_ns: u64) -> Self {
        Self {
            current_timestamp_ns,
        }
    }
}

impl Default for SystemContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time snapshot of the canister's environment, read from the system
/// API in a *replicated* context (`post_upgrade`, or an update call such as a
/// sync). The `http_request` query must never read these directly —
/// `root_key()` traps in non-replicated mode and `env_var_*` is likewise
/// replicated-only — so they are captured here and the rendered cookie is read
/// from heap state when serving.
///
/// Like [`SystemContext`], the state machine takes `&CanisterEnv` by argument so
/// tests can inject a mock without the system API.
pub struct CanisterEnv {
    /// DER-encoded IC root key (133 bytes on a real network).
    pub root_key: Vec<u8>,
    /// `PUBLIC_`-prefixed env vars only, sorted by name (BTreeMap order).
    pub public_vars: BTreeMap<String, String>,
    /// The cookie-gate secret from `IC_AUTH_TOKEN`, if set to a non-empty value.
    /// `None` means the gate is off. Kept separate from `public_vars` so it is
    /// never rendered into the (frontend-visible) `ic_env` cookie.
    pub auth_token: Option<String>,
}

impl CanisterEnv {
    /// Loads the snapshot from the system API. MUST run in a replicated context:
    /// `root_key()` traps in the `http_request` query.
    pub fn load() -> Self {
        use ic_cdk::api::{env_var_count, env_var_name, env_var_value, root_key};
        let all_vars = (0..env_var_count()).map(|i| {
            let name = env_var_name(i);
            let value = env_var_value(&name);
            (name, value)
        });
        Self::from_raw(root_key(), all_vars)
    }

    /// Builds a snapshot from a root key and the *full* env-var set, keeping only
    /// the `PUBLIC_`-prefixed (frontend-safe) vars plus the private
    /// `IC_AUTH_TOKEN` gate secret. Split out from [`Self::load`] so the
    /// filtering is unit-testable without the system API.
    pub fn from_raw(
        root_key: Vec<u8>,
        all_vars: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        let mut public_vars = BTreeMap::new();
        let mut auth_token = None;
        for (name, value) in all_vars {
            if name == AUTH_TOKEN_ENV_VAR {
                // An empty secret is treated as "gate off".
                if !value.is_empty() {
                    auth_token = Some(value);
                }
            } else if name.starts_with(PUBLIC_ENV_VAR_PREFIX) {
                public_vars.insert(name, value);
            }
        }
        Self {
            root_key,
            public_vars,
            auth_token,
        }
    }

    /// The rendered `Set-Cookie: ic_env=…` value for this snapshot; see
    /// [`crate::asset::render_env_cookie`].
    pub fn render_cookie(&self) -> String {
        crate::asset::render_env_cookie(&self.root_key, &self.public_vars)
    }
}
