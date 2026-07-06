//! Redirect rules: replacing the rule list, rebuilding their certified-tree
//! entries (plus the built-in 404 fallback), and the paginated
//! `get_redirect_rules` query. The certified-entry rebuild is delegated to the
//! [`Certifier`]; callers refresh `certified_data` afterwards.
//!
//! [`Certifier`]: crate::cert::Certifier

use super::{State, PAGE_SIZE};
use wire_types::RedirectRule;

impl State {
    // ---- queries ----

    /// Serves the `get_redirect_rules` endpoint: one page of rules in match
    /// order. Rules live in a `Vec` whose order is semantic (first match wins)
    /// and where no element has a unique key, so the cursor is a positional
    /// `start_index`. `start_index` is the number of rules already seen; at most
    /// `PAGE_SIZE` rules are returned, and an empty result means there is nothing
    /// at or after `start_index`.
    pub fn get_redirect_rules(&self, start_index: u64) -> Vec<RedirectRule> {
        let start = start_index as usize;
        self.store
            .redirect_rules()
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take(PAGE_SIZE)
            .cloned()
            .collect()
    }

    // ---- mutations ----

    /// Rebuilds the certified-tree entries for the redirect rules and the
    /// built-in 404 fallback (and, under protection, the rule/root unauthenticated
    /// siblings). Called whenever the rule list changes (in `execute_operations`),
    /// after asset ops that could clobber a rule's tree slot, and on upgrade.
    /// Delegates to the [`Certifier`]; the caller refreshes `certified_data`
    /// afterwards.
    ///
    /// [`Certifier`]: crate::cert::Certifier
    pub fn on_redirect_rules_change(&mut self) {
        self.certifier.on_redirect_rules_change(&self.store);
    }

    /// Replaces the redirect rules and rebuilds their certified entries.
    pub fn set_redirect_rules(&mut self, rules: Vec<RedirectRule>) {
        self.store.set_redirect_rules(rules);
        self.on_redirect_rules_change();
    }
}
