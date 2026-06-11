use std::collections::{BTreeSet, HashMap};

use candid::Principal;
use serde::{Deserialize, Serialize};

use crate::{certification::CertificateExpression, rc_bytes::RcBytes, redirect::RedirectRule};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StableState {
    pub(crate) authorized: BTreeSet<Principal>,
    pub(crate) stable_assets: HashMap<String, StableAsset>,

    pub(crate) next_session_id: u64,

    /// Optional so a `StableState` serialized before this field existed still
    /// deserializes cleanly (yields `None`, which we treat as "no rules").
    #[serde(default)]
    pub(crate) redirect_rules: Option<Vec<RedirectRule>>,
}

impl From<crate::state::State> for StableState {
    fn from(state: crate::state::State) -> Self {
        Self {
            authorized: state.authorized,
            stable_assets: state
                .assets
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            next_session_id: state.next_session_id,
            redirect_rules: Some(state.redirect_rules),
        }
    }
}

/// Same as [crate::asset::Asset] but serde-serializable.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StableAsset {
    pub content_type: String,
    pub encodings: HashMap<String, StableAssetEncoding>,
    pub headers: Vec<(String, String)>,
}

impl From<crate::asset::Asset> for StableAsset {
    fn from(asset: crate::asset::Asset) -> Self {
        Self {
            content_type: asset.content_type,
            encodings: asset
                .encodings
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            headers: asset.headers,
        }
    }
}

impl From<StableAsset> for crate::asset::Asset {
    fn from(stable_asset: StableAsset) -> Self {
        Self {
            content_type: stable_asset.content_type,
            encodings: stable_asset
                .encodings
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            headers: stable_asset.headers,
        }
    }
}

/// Same as [crate::asset::AssetEncoding] but serde-serializable
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct StableAssetEncoding {
    pub content_chunks: Vec<RcBytes>,
    pub certified: bool,
    pub sha256: [u8; 32],
    pub certificate_expression: Option<CertificateExpression>,
    pub response_hashes: Option<HashMap<u16, [u8; 32]>>,
}

impl From<crate::asset::AssetEncoding> for StableAssetEncoding {
    fn from(asset_encoding: crate::asset::AssetEncoding) -> Self {
        Self {
            content_chunks: asset_encoding.content_chunks,
            certified: asset_encoding.certified,
            sha256: asset_encoding.sha256,
            certificate_expression: asset_encoding.certificate_expression,
            response_hashes: asset_encoding.response_hashes,
        }
    }
}

impl From<StableAssetEncoding> for crate::asset::AssetEncoding {
    fn from(stable_asset_encoding: StableAssetEncoding) -> Self {
        Self {
            content_chunks: stable_asset_encoding.content_chunks,
            certified: stable_asset_encoding.certified,
            sha256: stable_asset_encoding.sha256,
            certificate_expression: stable_asset_encoding.certificate_expression,
            response_hashes: stable_asset_encoding.response_hashes,
        }
    }
}
