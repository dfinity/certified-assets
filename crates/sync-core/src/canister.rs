//! Assets canister API: client-side call wrappers.
//!
//! The Candid wire types live in the [`wire_types`] crate, shared with the
//! canister, and are re-exported here so the rest of `sync-core` can keep
//! referring to them via `crate::canister::*`. This module adds the call
//! wrappers and the [`CanisterCall`] transport trait.

#![allow(dead_code)]

use candid::{CandidType, Principal};
use serde::de::DeserializeOwned;
use serde_bytes::ByteBuf;
use std::collections::HashMap;

pub use wire_types::{
    AssetDetails, AssetEncodingDetails, CreateAssetArguments,
    DeleteAssetArguments, ExecuteOperationsArguments, Operation, RedirectRule, RulePattern,
    SetAssetContentArguments, SetAssetHeadersArguments, SetRedirectRulesArguments, StartSyncResult,
    UnsetAssetContentArguments, UploadChunksArguments,
};

#[derive(Debug, Clone, Copy)]
pub enum CallType {
    Update,
    Query,
}

pub trait CanisterCall {
    fn call<A, R>(
        &self,
        method: &str,
        arg: A,
        call_type: CallType,
        direct: bool,
    ) -> Result<R, String>
    where
        A: CandidType,
        R: CandidType + DeserializeOwned;
}

pub fn bundle_tag(c: &impl CanisterCall) -> Result<Option<u64>, String> {
    c.call("bundle_tag", (), CallType::Query, true)
}

// Fetch the complete asset list by paging through `get_asset_details`, returned
// as a map keyed by asset key — the shape the sync diff consumes. Building the
// map directly avoids materializing an intermediate Vec of every asset and a
// second pass to index it. Keys never collide: the canister returns assets
// ordered by key and `start_after` is exclusive, so each page begins strictly
// after the last.
//
// The canister owns the page size; we just follow its cursor, passing the last
// key we saw as `start_after`. We never need to know the page size: a page
// shorter than the previous full page is the last one (stop without the extra
// empty round-trip), and an empty page also ends the walk.
pub fn list_all_assets(c: &impl CanisterCall) -> Result<HashMap<String, AssetDetails>, String> {
    let mut all: HashMap<String, AssetDetails> = HashMap::new();
    let mut start_after: Option<String> = None;
    let mut prev_page_size: Option<usize> = None;
    loop {
        let entries: Vec<AssetDetails> =
            c.call("get_asset_details", &start_after, CallType::Query, true)?;
        let n = entries.len();
        let Some(last) = entries.last() else {
            break;
        };
        start_after = Some(last.key.clone());
        for d in entries {
            all.insert(d.key.clone(), d);
        }
        if let Some(prev) = prev_page_size {
            if n < prev {
                break;
            }
        }
        prev_page_size = Some(n);
    }
    Ok(all)
}

/// Begins a sync, returning its session id. A `Busy` result (another non-stale
/// sync is in progress) is surfaced as an error with the holder's principal and
/// idle time so the caller can decide whether to wait.
pub fn start_sync(c: &impl CanisterCall) -> Result<u64, String> {
    let resp: StartSyncResult = c.call("start_sync", (), CallType::Update, true)?;
    match resp {
        StartSyncResult::Started { session_id } => Ok(session_id),
        StartSyncResult::Busy {
            owner,
            idle_for_secs,
        } => Err(format!(
            "a sync is already in progress on this canister (started by {owner}, \
             idle for {idle_for_secs}s); retry once it completes, or after it goes stale"
        )),
    }
}

/// Stage content chunks under the sync. Takes ownership of the chunk bytes:
/// Candid copies them into the request buffer on encode regardless, so moving
/// them in (rather than borrowing) costs nothing and lets the caller hand off
/// its buffers directly.
///
/// Returns nothing: the canister numbers staged chunks 0, 1, 2, … per sync in
/// arrival order, and the caller reproduces the same ids locally rather than
/// receiving them over the wire (see `pack_and_upload_chunks`).
pub fn upload_chunks(
    c: &impl CanisterCall,
    session_id: u64,
    chunks: Vec<ByteBuf>,
) -> Result<(), String> {
    let req = UploadChunksArguments { session_id, chunks };
    c.call("upload_chunks", req, CallType::Update, true)
}

pub fn execute_operations(
    c: &impl CanisterCall,
    args: ExecuteOperationsArguments,
) -> Result<(), String> {
    c.call("execute_operations", args, CallType::Update, true)
}

// Fetch the complete redirect-rule list by paging through `get_redirect_rules`,
// preserving order — the diff matches rules positionally and the canister
// applies them first-match-wins, so order is significant (unlike the asset map).
// The cursor is a positional `start_index` (the count seen so far) rather than a
// value cursor like the asset walk uses: rules have no unique key, so only a
// position can name "where we left off".
//
// As with `list_all_assets`, the canister owns the page size; a page shorter
// than the previous full page is the last one (stop without the extra empty
// round-trip), and an empty page also ends the walk.
pub fn list_all_redirect_rules(c: &impl CanisterCall) -> Result<Vec<RedirectRule>, String> {
    let mut all: Vec<RedirectRule> = Vec::new();
    let mut start_index: u64 = 0;
    let mut prev_page_size: Option<usize> = None;
    loop {
        let page: Vec<RedirectRule> =
            c.call("get_redirect_rules", start_index, CallType::Query, true)?;
        let n = page.len();
        if n == 0 {
            break;
        }
        start_index += n as u64;
        all.extend(page);
        if let Some(prev) = prev_page_size {
            if n < prev {
                break;
            }
        }
        prev_page_size = Some(n);
    }
    Ok(all)
}

// Whether the signing identity may sync assets (authorized or a controller).
// Called directly (not via proxy) so it reflects the identity's own access.
pub fn can_sync(c: &impl CanisterCall) -> Result<bool, String> {
    c.call("can_sync", (), CallType::Query, true)
}

// Routes through the proxy (direct: false) so the proxy canister — the
// controller — can authorise the call on the assets canister.
pub fn authorize_via_proxy(c: &impl CanisterCall, principal: Principal) -> Result<(), String> {
    c.call("authorize", principal, CallType::Update, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::CandidType;
    use serde::de::DeserializeOwned;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct PagedMock {
        pages: RefCell<VecDeque<Vec<AssetDetails>>>,
    }

    impl PagedMock {
        fn new(pages: Vec<Vec<AssetDetails>>) -> Self {
            Self {
                pages: RefCell::new(VecDeque::from(pages)),
            }
        }
    }

    impl CanisterCall for PagedMock {
        fn call<A, R>(&self, method: &str, _arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "get_asset_details");
            let page = self.pages.borrow_mut().pop_front().unwrap_or_default();
            let bytes = candid::encode_one(page).map_err(|e| e.to_string())?;
            candid::decode_one(&bytes).map_err(|e| e.to_string())
        }
    }

    // Pages of assets with globally unique keys, mirroring the canister's
    // ordered-by-key, exclusive-cursor pagination (no key repeats across pages).
    fn mk_assets(start: usize, n: usize) -> Vec<AssetDetails> {
        (start..start + n)
            .map(|i| AssetDetails {
                key: format!("/asset-{i}"),
                encodings: vec![],
                content_type: "text/plain".to_string(),
                headers: vec![],
            })
            .collect()
    }

    #[test]
    fn list_all_assets_empty_canister_returns_empty() {
        let result = list_all_assets(&PagedMock::new(vec![])).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_all_assets_single_partial_page_returns_all() {
        // 5 assets — one partial page, then the implicit empty page terminates the loop.
        let result = list_all_assets(&PagedMock::new(vec![mk_assets(0, 5)])).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn list_all_assets_partial_last_page_terminates_early() {
        // 100 + 50: the 50-item page is smaller than the 100-item page, so the loop
        // breaks without making a third request.
        let mock = PagedMock::new(vec![mk_assets(0, 100), mk_assets(100, 50)]);
        let result = list_all_assets(&mock).unwrap();
        assert_eq!(result.len(), 150);
        assert!(
            mock.pages.borrow().is_empty(),
            "no third request should be made"
        );
    }

    #[test]
    fn list_all_assets_full_pages_then_empty_returns_all() {
        // 100 + 100 + 0: two full pages followed by an empty page.
        let result = list_all_assets(&PagedMock::new(vec![
            mk_assets(0, 100),
            mk_assets(100, 100),
            vec![],
        ]))
        .unwrap();
        assert_eq!(result.len(), 200);
    }

    #[test]
    fn list_all_assets_multiple_full_pages_then_partial() {
        // 100 + 100 + 73: terminates on the smaller page.
        let result = list_all_assets(&PagedMock::new(vec![
            mk_assets(0, 100),
            mk_assets(100, 100),
            mk_assets(200, 73),
        ]))
        .unwrap();
        assert_eq!(result.len(), 273);
    }

    struct RulePagedMock {
        pages: RefCell<VecDeque<Vec<RedirectRule>>>,
    }

    impl RulePagedMock {
        fn new(pages: Vec<Vec<RedirectRule>>) -> Self {
            Self {
                pages: RefCell::new(VecDeque::from(pages)),
            }
        }
    }

    impl CanisterCall for RulePagedMock {
        fn call<A, R>(&self, method: &str, _arg: A, _: CallType, _: bool) -> Result<R, String>
        where
            A: CandidType,
            R: CandidType + DeserializeOwned,
        {
            assert_eq!(method, "get_redirect_rules");
            let page = self.pages.borrow_mut().pop_front().unwrap_or_default();
            let bytes = candid::encode_one(page).map_err(|e| e.to_string())?;
            candid::decode_one(&bytes).map_err(|e| e.to_string())
        }
    }

    // Rules whose `to` encodes a global index, so a reassembled walk can be
    // checked for both completeness and order.
    fn mk_rules(start: usize, n: usize) -> Vec<RedirectRule> {
        (start..start + n)
            .map(|i| RedirectRule {
                from: RulePattern::Exact(format!("/from-{i}")),
                to: format!("/to-{i}"),
                status: 301,
                headers: vec![],
            })
            .collect()
    }

    #[test]
    fn list_all_redirect_rules_empty_canister_returns_empty() {
        let result = list_all_redirect_rules(&RulePagedMock::new(vec![])).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_all_redirect_rules_single_partial_page_returns_all() {
        let result = list_all_redirect_rules(&RulePagedMock::new(vec![mk_rules(0, 5)])).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn list_all_redirect_rules_partial_last_page_terminates_early() {
        // 100 + 50: the smaller second page ends the walk with no third request.
        let mock = RulePagedMock::new(vec![mk_rules(0, 100), mk_rules(100, 50)]);
        let result = list_all_redirect_rules(&mock).unwrap();
        assert_eq!(result.len(), 150);
        assert!(
            mock.pages.borrow().is_empty(),
            "no third request should be made"
        );
    }

    #[test]
    fn list_all_redirect_rules_full_pages_then_empty_preserve_order() {
        // 100 + 100 + 0: order must survive across pages. Unlike the asset walk
        // (which dedupes into a map), rules are matched positionally, so the
        // concatenation order is the contract.
        let result = list_all_redirect_rules(&RulePagedMock::new(vec![
            mk_rules(0, 100),
            mk_rules(100, 100),
            vec![],
        ]))
        .unwrap();
        assert_eq!(result.len(), 200);
        assert!(result
            .iter()
            .enumerate()
            .all(|(i, r)| r.to == format!("/to-{i}")));
    }
}
