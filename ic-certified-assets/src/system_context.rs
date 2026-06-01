//! Runtime context exposed to state-machine entry points.
//!
//! [`SystemContext`] is a small bundle of values that the state machine needs
//! but should not read from `ic_cdk` directly (so the state machine can stay
//! pure and testable).

use ic_cdk::api::time;

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

    #[cfg(test)]
    pub fn new_with_options(current_timestamp_ns: u64) -> Self {
        Self {
            current_timestamp_ns,
        }
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
