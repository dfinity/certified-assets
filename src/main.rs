use ic_cdk::api::{caller, time, trap};
use ic_cdk::export::candid::{CandidType, Deserialize, Func, Principal};
use ic_cdk_macros::{query, update};
use serde_bytes::ByteBuf;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

thread_local! {
    static STATE: State = State::default();
}

#[derive(Default)]
struct State {
    assets: RefCell<HashMap<Key, Asset>>,

    chunks: RefCell<HashMap<ChunkId, Chunk>>,
    next_chunk_id: Cell<ChunkId>,

    batches: RefCell<HashMap<BatchId, Batch>>,
    next_batch_id: Cell<BatchId>,

    authorized: RefCell<Vec<Principal>>,
}

#[derive(Default)]
struct AssetEncoding {
    modified: Timestamp,
    content: Vec<ByteBuf>,
    total_length: usize,
    sha256: Option<[u8; 32]>,
}

#[derive(Default)]
struct Asset {
    content_type: String,
    encodings: HashMap<String, AssetEncoding>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct EncodedAsset {
    content: ByteBuf,
    content_type: String,
    content_encoding: String,
    total_length: usize,
    sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct AssetDetails {
    key: String,
    content_type: String,
    encodings: Vec<AssetEncodingDetails>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct AssetEncodingDetails {
    modified: Timestamp,
    content_encoding: String,
    sha256: Option<[u8; 32]>,
    length: usize,
}

struct Chunk {
    content: ByteBuf,
}

struct Batch {}

type Timestamp = u64;
type BatchId = u64;
type ChunkId = u64;
type Key = String;

// IDL Types

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CreateAssetArguments {
    key: Key,
    content_type: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct SetAssetContentArguments {
    key: Key,
    content_encoding: String,
    chunk_ids: Vec<ChunkId>,
    sha256: Option<ByteBuf>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct UnsetAssetContentArguments {
    key: Key,
    content_encoding: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct DeleteAssetArguments {
    key: Key,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct ClearArguments {}

#[derive(Clone, Debug, CandidType, Deserialize)]
enum BatchOperation {
    CreateAsset(CreateAssetArguments),
    SetAssetContent(SetAssetContentArguments),
    UnsetAssetContent(UnsetAssetContentArguments),
    DeleteAsset(DeleteAssetArguments),
    Clear(ClearArguments),
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct StoreArg {
    key: Key,
    content_type: String,
    content_encoding: String,
    content: ByteBuf,
    sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetArg {
    key: Key,
    accept_encodings: Vec<String>,
}

// HTTP interface

type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct HttpResponse {
    status_code: u16,
    headers: Vec<HeaderField>,
    body: ByteBuf,
    streaming_strategy: Option<StreamingStrategy>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct Token {}

#[derive(Clone, Debug, CandidType, Deserialize)]
enum StreamingStrategy {
    Callback { callback: Func, token: Token },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct StreamingCallbackHttpResponse {
    body: ByteBuf,
    token: Option<Token>,
}

#[update]
fn autorize(other: Principal) {
    let caller = caller();
    STATE.with(|s| {
        let caller_autorized = s.authorized.borrow().iter().any(|p| *p == caller);
        if caller_autorized {
            s.authorized.borrow_mut().push(other);
        }
    })
}

#[update]
fn store(arg: StoreArg) {
    trap_if_unauthorized();

    STATE.with(move |s| {
        let mut assets = s.assets.borrow_mut();
        let asset = assets.entry(arg.key).or_default();
        asset.content_type = arg.content_type;

        let encoding = asset.encodings.entry(arg.content_encoding).or_default();
        encoding.total_length = arg.content.len();
        encoding.content = vec![arg.content];
        encoding.modified = time() as u64;
    });
}

#[update]
fn clear() {
    trap_if_unauthorized();

    STATE.with(|s| {
        s.assets.borrow_mut().clear();
        s.batches.borrow_mut().clear();
        s.chunks.borrow_mut().clear();
        s.next_batch_id.set(0);
        s.next_chunk_id.set(0);
    })
}

#[query]
fn get(arg: GetArg) -> EncodedAsset {
    STATE.with(|s| {
        let assets = s.assets.borrow();
        let asset = assets.get(&arg.key).unwrap_or_else(|| {
            trap("asset not found");
        });

        for enc in arg.accept_encodings.iter() {
            if let Some(asset_enc) = asset.encodings.get(enc) {
                return EncodedAsset {
                    content: asset_enc.content[0].clone(),
                    content_type: asset.content_type.clone(),
                    content_encoding: enc.clone(),
                    total_length: asset_enc.total_length,
                    sha256: asset_enc.sha256,
                };
            }
        }
        trap("no such encoding");
    })
}

#[query]
fn list() -> Vec<AssetDetails> {
    STATE.with(|s| {
        s.assets
            .borrow()
            .iter()
            .map(|(key, asset)| {
                let mut encodings: Vec<_> = asset
                    .encodings
                    .iter()
                    .map(|(enc_name, enc)| AssetEncodingDetails {
                        modified: enc.modified,
                        content_encoding: enc_name.clone(),
                        sha256: enc.sha256,
                        length: enc.total_length,
                    })
                    .collect();
                encodings.sort_by(|l, r| l.content_encoding.cmp(&r.content_encoding));

                AssetDetails {
                    key: key.clone(),
                    content_type: asset.content_type.clone(),
                    encodings,
                }
            })
            .collect::<Vec<_>>()
    })
}

#[query]
fn http_request(_req: HttpRequest) -> HttpResponse {
    todo!()
}

fn trap_if_unauthorized() {
    let caller = caller();
    STATE.with(|s| {
        if s.authorized.borrow().iter().all(|p| *p != caller) {
            trap("caller is not authorized");
        }
    })
}

fn main() {}
