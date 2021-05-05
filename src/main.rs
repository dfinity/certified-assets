use ic_cdk::api::{caller, time, trap};
use ic_cdk::export::candid::{CandidType, Deserialize, Func, Nat, Principal};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;

const BATCH_EXPIRY_NANOS: u64 = 300_000_000_000;

thread_local! {
    static STATE: State = State::default();
}

#[derive(Default)]
struct State {
    assets: RefCell<HashMap<Key, Asset>>,

    chunks: RefCell<HashMap<ChunkId, Chunk>>,
    next_chunk_id: RefCell<ChunkId>,

    batches: RefCell<HashMap<BatchId, Batch>>,
    next_batch_id: RefCell<BatchId>,

    authorized: RefCell<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct StableState {
    authorized: Vec<Principal>,
    stable_assets: HashMap<String, Asset>,
}

#[derive(Default, Clone, Debug, CandidType, Deserialize)]
struct AssetEncoding {
    modified: Timestamp,
    content_chunks: Vec<ByteBuf>,
    total_length: usize,
    certified: bool,
    sha256: Option<[u8; 32]>,
}

#[derive(Default, Clone, Debug, CandidType, Deserialize)]
struct Asset {
    content_type: String,
    encodings: HashMap<String, AssetEncoding>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct EncodedAsset {
    content: ByteBuf,
    content_type: String,
    content_encoding: String,
    total_length: Nat,
    sha256: Option<ByteBuf>,
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
    length: Nat,
}

struct Chunk {
    batch_id: BatchId,
    content: ByteBuf,
}

struct Batch {
    expires_at: Timestamp,
}

type Timestamp = u64;
type BatchId = Nat;
type ChunkId = Nat;
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
struct CommitBatchArguments {
    batch_id: BatchId,
    operations: Vec<BatchOperation>,
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

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetChunkArg {
    key: Key,
    content_encoding: String,
    index: Nat,
    sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct GetChunkResponse {
    content: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CreateBatchResponse {
    batch_id: BatchId,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CreateChunkArg {
    batch_id: BatchId,
    content: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct CreateChunkResponse {
    chunk_id: ChunkId,
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

#[query]
fn retrieve(key: Key) -> ByteBuf {
    STATE.with(|s| {
        let assets = s.assets.borrow();
        let asset = assets.get(&key).unwrap_or_else(|| trap("asset not found"));
        let id_enc = asset
            .encodings
            .get("identity")
            .unwrap_or_else(|| trap("no identity encoding"));
        if id_enc.content_chunks.len() > 1 {
            trap("Asset is too large. Uset get() and get_chunk() instead.");
        }
        id_enc.content_chunks[0].clone()
    })
}

#[update]
fn store(arg: StoreArg) {
    trap_if_unauthorized();

    STATE.with(move |s| {
        let mut assets = s.assets.borrow_mut();
        let asset = assets.entry(arg.key.clone()).or_default();
        asset.content_type = arg.content_type;

        let to_certify =
            arg.content_encoding == "identity" || !asset.encodings.contains_key("identity");

        if to_certify {
            for (_, enc) in asset.encodings.iter_mut() {
                enc.certified = false;
            }
            certify_asset(arg.key, &arg.content);
        }

        let encoding = asset.encodings.entry(arg.content_encoding).or_default();
        encoding.total_length = arg.content.len();
        encoding.content_chunks = vec![arg.content];
        encoding.modified = time() as u64;
        encoding.certified = to_certify;
    });
}

#[update]
fn create_batch() -> CreateBatchResponse {
    trap_if_unauthorized();

    STATE.with(|s| {
        let batch_id = s.next_batch_id.borrow().clone();
        *s.next_batch_id.borrow_mut() += 1;

        let now = time() as u64;

        let mut batches = s.batches.borrow_mut();
        batches.insert(
            batch_id.clone(),
            Batch {
                expires_at: now + BATCH_EXPIRY_NANOS,
            },
        );
        s.chunks.borrow_mut().retain(|_, c| {
            batches
                .get(&c.batch_id)
                .map(|b| b.expires_at > now)
                .unwrap_or(false)
        });
        batches.retain(|_, b| b.expires_at > now);

        CreateBatchResponse { batch_id }
    })
}

#[update]
fn create_chunk(arg: CreateChunkArg) -> CreateChunkResponse {
    trap_if_unauthorized();

    STATE.with(|s| {
        let mut batches = s.batches.borrow_mut();
        let now = time() as u64;
        let mut batch = batches
            .get_mut(&arg.batch_id)
            .unwrap_or_else(|| trap("batch not found"));
        batch.expires_at = now + BATCH_EXPIRY_NANOS;

        let chunk_id = s.next_chunk_id.borrow().clone();
        *s.next_chunk_id.borrow_mut() += 1;

        s.chunks.borrow_mut().insert(
            chunk_id.clone(),
            Chunk {
                batch_id: arg.batch_id,
                content: arg.content,
            },
        );

        CreateChunkResponse { chunk_id }
    })
}

#[update]
fn create_asset(arg: CreateAssetArguments) {
    trap_if_unauthorized();
    do_create_asset(arg);
}

#[update]
fn set_asset_content(arg: SetAssetContentArguments) {
    trap_if_unauthorized();
    do_set_asset_content(arg);
}

#[update]
fn unset_asset_content(arg: UnsetAssetContentArguments) {
    trap_if_unauthorized();
    do_unset_asset_content(arg);
}

#[update]
fn delete_content(arg: DeleteAssetArguments) {
    trap_if_unauthorized();
    do_delete_asset(arg);
}

#[update]
fn clear() {
    trap_if_unauthorized();
    do_clear();
}

#[update]
fn commit_batch(arg: CommitBatchArguments) {
    trap_if_unauthorized();
    let batch_id = arg.batch_id;
    for op in arg.operations {
        match op {
            BatchOperation::CreateAsset(arg) => do_create_asset(arg),
            BatchOperation::SetAssetContent(arg) => do_set_asset_content(arg),
            BatchOperation::UnsetAssetContent(arg) => do_unset_asset_content(arg),
            BatchOperation::DeleteAsset(arg) => do_delete_asset(arg),
            BatchOperation::Clear(_) => do_clear(),
        }
    }
    STATE.with(|s| {
        s.batches.borrow_mut().remove(&batch_id);
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
                    content: asset_enc.content_chunks[0].clone(),
                    content_type: asset.content_type.clone(),
                    content_encoding: enc.clone(),
                    total_length: Nat::from(asset_enc.total_length as u64),
                    sha256: asset_enc.sha256.map(|digest| ByteBuf::from(digest)),
                };
            }
        }
        trap("no such encoding");
    })
}

#[query]
fn get_chunk(arg: GetChunkArg) -> GetChunkResponse {
    STATE.with(|s| {
        let assets = s.assets.borrow();
        let asset = assets
            .get(&arg.key)
            .unwrap_or_else(|| trap("asset not found"));

        let enc = asset
            .encodings
            .get(&arg.content_encoding)
            .unwrap_or_else(|| trap("no such encoding"));

        if let (Some(l), Some(r)) = (arg.sha256, enc.sha256) {
            if l != r {
                trap("sha256 mismatch")
            }
        }
        if arg.index >= enc.content_chunks.len() {
            trap("chunk index out of bounds");
        }
        let index: usize = arg.index.to_string().parse().unwrap();

        GetChunkResponse {
            content: enc.content_chunks[index].clone(),
        }
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
                        length: Nat::from(enc.total_length),
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
fn http_request(req: HttpRequest) -> HttpResponse {
    let mut encodings = vec![];
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("Accept-Encoding") {
            for v in value.split(',') {
                encodings.push(v.trim().to_string());
            }
        }
    }
    encodings.push("identity".to_string());

    STATE.with(|s| {
        let assets = s.assets.borrow();
        let mut headers = vec![];
        // TODO: urldecode
        let parts: Vec<_> = req.url.split('?').collect();

        if let Some(asset) = assets.get(parts[0]).or_else(|| assets.get("/index.html")) {
            for enc_name in encodings.iter() {
                if let Some(enc) = asset.encodings.get(enc_name) {
                    headers.push(("Content-Type".to_string(), asset.content_type.to_string()));
                    if enc_name != "identity" {
                        headers.push(("Content-Encoding".to_string(), enc_name.to_string()));
                    }

                    return HttpResponse {
                        status_code: 200,
                        headers,
                        body: enc.content_chunks[0].clone(),
                        streaming_strategy: None,
                    };
                }
            }
        }
        HttpResponse {
            status_code: 404,
            headers,
            body: ByteBuf::from("not found"),
            streaming_strategy: None,
        }
    })
}

fn do_create_asset(arg: CreateAssetArguments) {
    STATE.with(|s| {
        let mut assets = s.assets.borrow_mut();
        if let Some(asset) = assets.get(&arg.key) {
            if asset.content_type != arg.content_type {
                trap("create_asset: content type mismatch");
            }
        } else {
            assets.insert(
                arg.key,
                Asset {
                    content_type: arg.content_type,
                    encodings: HashMap::new(),
                },
            );
        }
    })
}

fn do_set_asset_content(arg: SetAssetContentArguments) {
    STATE.with(|s| {
        if arg.chunk_ids.is_empty() {
            trap(&format!(
                "({}): must have at least one chunk",
                arg.content_encoding
            ));
        }

        let mut assets = s.assets.borrow_mut();
        let asset = assets
            .get_mut(&arg.key)
            .unwrap_or_else(|| trap("asset not found"));
        let now = time() as u64;

        let mut chunks = s.chunks.borrow_mut();

        let mut content_chunks = vec![];
        for chunk_id in arg.chunk_ids.iter() {
            let chunk = chunks
                .remove(chunk_id)
                .unwrap_or_else(|| trap(&format!("chunk {} not found", chunk_id)));
            content_chunks.push(chunk.content);
        }

        let total_length: usize = content_chunks.iter().map(|c| c.len()).sum();
        let enc = AssetEncoding {
            modified: now,
            content_chunks,
            certified: false,
            total_length,
            sha256: arg.sha256.map(|b| {
                b.to_vec()
                    .try_into()
                    .unwrap_or_else(|_| trap("invalid hash length"))
            }),
        };
        asset.encodings.insert(arg.content_encoding, enc);
    })
}

fn do_unset_asset_content(arg: UnsetAssetContentArguments) {
    STATE.with(|s| {
        let mut assets = s.assets.borrow_mut();
        let asset = assets
            .get_mut(&arg.key)
            .unwrap_or_else(|| trap("asset not found"));
        asset.encodings.remove(&arg.content_encoding);
    })
}

fn do_delete_asset(arg: DeleteAssetArguments) {
    STATE.with(|s| {
        let mut assets = s.assets.borrow_mut();
        assets.remove(&arg.key);
    })
}

fn do_clear() {
    STATE.with(|s| {
        s.assets.borrow_mut().clear();
        s.batches.borrow_mut().clear();
        s.chunks.borrow_mut().clear();
        *s.next_batch_id.borrow_mut() = Nat::from(1);
        *s.next_chunk_id.borrow_mut() = Nat::from(1);
    })
}

fn trap_if_unauthorized() {
    let caller = caller();
    STATE.with(|s| {
        if s.authorized.borrow().iter().all(|p| *p != caller) {
            trap("caller is not authorized");
        }
    })
}

fn certify_asset(_key: Key, _contents: &[u8]) {}

#[init]
fn init() {
    do_clear();
    STATE.with(|s| s.authorized.borrow_mut().push(caller()));
}

#[pre_upgrade]
fn pre_upgrade() {
    let stable_state = STATE.with(|s| StableState {
        authorized: s.authorized.take(),
        stable_assets: s.assets.take(),
    });
    ic_cdk::storage::stable_save((stable_state,))
        .unwrap_or_else(|e| trap(&format!("failed to save stable state: {}", e)));
}

#[post_upgrade]
fn post_upgrade() {
    do_clear();
    let (stable_state,): (StableState,) = ic_cdk::storage::stable_restore()
        .unwrap_or_else(|e| trap(&format!("failed to restore stable state: {}", e)));
    STATE.with(|s| {
        s.authorized.replace(stable_state.authorized);
        s.assets.replace(stable_state.stable_assets);
    });
}

fn main() {}
