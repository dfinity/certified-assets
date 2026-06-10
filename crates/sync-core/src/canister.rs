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
    AssetDetails, AssetEncodingDetails, BatchOperationKind, CancelSyncArguments,
    CreateAssetArguments, CreateChunksArguments, CreateChunksResponse, DeleteAssetArguments,
    ExecuteOperationsArguments, RedirectRule, RulePattern, SetAssetContentArguments,
    SetAssetPropertiesArguments, SetRedirectRulesArguments, StartSyncResult,
    UnsetAssetContentArguments,
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

pub fn api_version(c: &impl CanisterCall) -> Result<u16, String> {
    c.call("api_version", (), CallType::Query, true)
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
pub fn create_chunks(
    c: &impl CanisterCall,
    session_id: u64,
    content: Vec<ByteBuf>,
) -> Result<Vec<u64>, String> {
    let req = CreateChunksArguments {
        session_id,
        content,
    };
    let resp: CreateChunksResponse = c.call("create_chunks", req, CallType::Update, true)?;
    Ok(resp.chunk_ids)
}

pub fn execute_operations(
    c: &impl CanisterCall,
    args: ExecuteOperationsArguments,
) -> Result<(), String> {
    c.call("execute_operations", args, CallType::Update, true)
}

/// Abandons the active sync, releasing the lock. Best-effort cleanup on an
/// aborted sync; a sync left uncancelled is reclaimed once it goes stale.
pub fn cancel_sync(c: &impl CanisterCall, session_id: u64) -> Result<(), String> {
    c.call(
        "cancel_sync",
        CancelSyncArguments { session_id },
        CallType::Update,
        true,
    )
}

pub fn get_redirect_rules(c: &impl CanisterCall) -> Result<Vec<RedirectRule>, String> {
    c.call("get_redirect_rules", (), CallType::Query, true)
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
                headers: None,
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
}
