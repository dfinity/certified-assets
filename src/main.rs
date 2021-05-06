use ic_cdk::api::{caller, data_certificate, set_certified_data, time, trap};
use ic_cdk::export::candid::{CandidType, Deserialize, Func, Nat, Principal};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_certified_map::{AsHashTree, Hash, HashTree, RbTree};
use num_traits::ToPrimitive;
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::Digest;
use std::cell::RefCell;
use std::collections::HashMap;

/// The amount of time a batch is kept alive. Modifying the batch
/// delays the expiry further.
const BATCH_EXPIRY_NANOS: u64 = 300_000_000_000;

/// The order in which we pick encodings for certification.
const ENCODING_CERTIFICATION_ORDER: &[&str] = &["identity", "gzip", "compress", "deflate", "br"];

/// The file to serve if the requested file wasn't found.
const INDEX_FILE: &str = "/index.html";

thread_local! {
    static STATE: State = State::default();
    static ASSET_HASHES: RefCell<AssetHashes> = RefCell::new(RbTree::new());
}

type AssetHashes = RbTree<Key, Hash>;

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
    sha256: [u8; 32],
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
    sha256: Option<ByteBuf>,
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
    sha256: Option<ByteBuf>,
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
    sha256: Option<ByteBuf>,
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
struct Token {
    key: String,
    content_encoding: String,
    index: Nat,
    // We don't care about the sha, we just want to be backward compatible.
    sha256: Option<ByteBuf>,
}

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
fn authorize(other: Principal) {
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
            trap("Asset too large. Use get() and get_chunk() instead.");
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

        let hash = hash_bytes(&arg.content);
        if let Some(provided_hash) = arg.sha256 {
            if &hash != provided_hash.as_ref() {
                trap("sha256 mismatch");
            }
        }

        let encoding = asset.encodings.entry(arg.content_encoding).or_default();
        encoding.total_length = arg.content.len();
        encoding.content_chunks = vec![arg.content];
        encoding.modified = time() as u64;
        encoding.sha256 = hash;

        on_asset_change(&arg.key, asset);
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
                    sha256: Some(ByteBuf::from(asset_enc.sha256)),
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

        if let Some(expected_hash) = arg.sha256 {
            if expected_hash != enc.sha256 {
                trap("sha256 mismatch")
            }
        }
        if arg.index >= enc.content_chunks.len() {
            trap("chunk index out of bounds");
        }
        let index: usize = arg.index.0.to_usize().unwrap();

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
                        sha256: Some(ByteBuf::from(enc.sha256)),
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

fn create_strategy(
    _asset: &Asset,
    enc_name: &str,
    enc: &AssetEncoding,
    key: &str,
    chunk_index: usize,
) -> Option<StreamingStrategy> {
    if chunk_index + 1 >= enc.content_chunks.len() {
        None
    } else {
        Some(StreamingStrategy::Callback {
            callback: ic_cdk::export::candid::Func {
                method: "http_request_streaming_callback".to_string(),
                principal: ic_cdk::id(),
            },
            token: Token {
                key: key.to_string(),
                content_encoding: enc_name.to_string(),
                index: Nat::from(chunk_index + 1),
                sha256: Some(ByteBuf::from(enc.sha256)),
            },
        })
    }
}

fn build_200(
    asset: &Asset,
    enc_name: &str,
    enc: &AssetEncoding,
    key: &str,
    chunk_index: usize,
    certificate_header: HeaderField,
) -> HttpResponse {
    let mut headers = vec![("Content-Type".to_string(), asset.content_type.to_string())];
    if enc_name != "identity" {
        headers.push(("Content-Encoding".to_string(), enc_name.to_string()));
    }
    headers.push(certificate_header);

    let streaming_strategy = create_strategy(asset, enc_name, enc, key, chunk_index);

    HttpResponse {
        status_code: 200,
        headers,
        body: enc.content_chunks[chunk_index].clone(),
        streaming_strategy,
    }
}

fn build_404(certificate_header: HeaderField) -> HttpResponse {
    HttpResponse {
        status_code: 404,
        headers: vec![certificate_header],
        body: ByteBuf::from("not found"),
        streaming_strategy: None,
    }
}

fn build_http_response(path: &str, encodings: Vec<String>, index: usize) -> HttpResponse {
    STATE.with(|s| {
        let assets = s.assets.borrow();

        let index_redirect_certificate = ASSET_HASHES.with(|t| {
            let tree = t.borrow();
            if tree.get(path.as_bytes()).is_none() && tree.get(INDEX_FILE.as_bytes()).is_some() {
                let absence_proof = tree.witness(path.as_bytes());
                let index_proof = tree.witness(INDEX_FILE.as_bytes());
                let combined_proof = merge_hash_trees(absence_proof, index_proof);
                Some(witness_to_header(combined_proof))
            } else {
                None
            }
        });

        if let Some(certificate_header) = index_redirect_certificate {
            if let Some(asset) = assets.get(INDEX_FILE) {
                for (enc_name, enc) in asset.encodings.iter() {
                    if enc.certified {
                        return build_200(
                            asset,
                            enc_name,
                            enc,
                            INDEX_FILE,
                            index,
                            certificate_header,
                        );
                    }
                }
            }
        }

        let certificate_header =
            ASSET_HASHES.with(|t| witness_to_header(t.borrow().witness(path.as_bytes())));

        if let Some(asset) = assets.get(path) {
            for enc_name in encodings.iter() {
                if let Some(enc) = asset.encodings.get(enc_name) {
                    if enc.certified {
                        return build_200(asset, enc_name, enc, path, index, certificate_header);
                    }
                }
            }
        }

        build_404(certificate_header)
    })
}

/// An iterator-like structure that decode a URL.
struct UrlDecode<'a> {
    bytes: std::slice::Iter<'a, u8>,
}

fn convert_percent(iter: &mut std::slice::Iter<u8>) -> Option<u8> {
    let mut cloned_iter = iter.clone();
    let result = match cloned_iter.next()? {
        b'%' => b'%',
        h => {
            let h = char::from(*h).to_digit(16)?;
            let l = char::from(*cloned_iter.next()?).to_digit(16)?;
            h as u8 * 0x10 + l as u8
        }
    };
    // Update this if we make it this far, otherwise "reset" the iterator.
    *iter = cloned_iter;
    Some(result)
}

impl<'a> Iterator for UrlDecode<'a> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.bytes.next()?;
        match b {
            b'%' => Some(char::from(convert_percent(&mut self.bytes).expect(
                "error decoding url: % must be followed by '%' or two hex digits",
            ))),
            b'+' => Some(' '),
            x => Some(char::from(*x)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let bytes = self.bytes.len();
        (bytes / 3, Some(bytes))
    }
}

fn url_decode(url: &str) -> String {
    UrlDecode {
        bytes: url.as_bytes().into_iter(),
    }
    .collect()
}

#[test]
fn check_url_decode() {
    assert_eq!(url_decode("/%"), "/%");
    assert_eq!(url_decode("/%%"), "/%");
    assert_eq!(url_decode("/%20a"), "/ a");
    assert_eq!(url_decode("/%%+a%20+%@"), "/% a  %@");
    assert_eq!(url_decode("/has%percent.txt"), "/has%percent.txt");
    assert_eq!(url_decode("/%e6"), "/æ");
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

    let path = match req.url.find('?') {
        Some(i) => &req.url[..i],
        None => &req.url[..],
    };

    build_http_response(&url_decode(&path), encodings, 0)
}

#[query]
fn http_request_streaming_callback(
    Token {
        key,
        content_encoding,
        index,
        ..
    }: Token,
) -> HttpResponse {
    build_http_response(
        &key,
        vec![content_encoding],
        index.0.to_usize().unwrap_or(usize::MAX),
    )
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
        let mut hasher = sha2::Sha256::new();
        for chunk_id in arg.chunk_ids.iter() {
            let chunk = chunks
                .remove(chunk_id)
                .unwrap_or_else(|| trap(&format!("chunk {} not found", chunk_id)));
            hasher.update(&chunk.content);
            content_chunks.push(chunk.content);
        }

        let sha256 = hasher.finalize().into();

        if let Some(expected_hash) = arg.sha256 {
            if expected_hash != sha256 {
                trap("sha256 mismatch");
            }
        }

        let total_length: usize = content_chunks.iter().map(|c| c.len()).sum();
        let enc = AssetEncoding {
            modified: now,
            content_chunks,
            certified: false,
            total_length,
            sha256,
        };
        asset.encodings.insert(arg.content_encoding, enc);

        on_asset_change(&arg.key, asset);
    })
}

fn do_unset_asset_content(arg: UnsetAssetContentArguments) {
    STATE.with(|s| {
        let mut assets = s.assets.borrow_mut();
        let asset = assets
            .get_mut(&arg.key)
            .unwrap_or_else(|| trap("asset not found"));

        if asset.encodings.remove(&arg.content_encoding).is_some() {
            on_asset_change(&arg.key, asset);
        }
    })
}

fn do_delete_asset(arg: DeleteAssetArguments) {
    STATE.with(|s| {
        let mut assets = s.assets.borrow_mut();
        assets.remove(&arg.key);
    });
    delete_asset_hash(&arg.key);
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

fn on_asset_change(key: &str, asset: &mut Asset) {
    // If the most preferred encoding is present and certified,
    // there is nothing to do.
    for enc_name in ENCODING_CERTIFICATION_ORDER.iter() {
        if let Some(enc) = asset.encodings.get(*enc_name) {
            if enc.certified {
                return;
            }
        }
    }

    if asset.encodings.is_empty() {
        delete_asset_hash(key);
        return;
    }

    // An encoding with a higher priority was added, let's certify it
    // instead.

    for enc in asset.encodings.values_mut() {
        enc.certified = false;
    }

    for enc_name in ENCODING_CERTIFICATION_ORDER.iter() {
        if let Some(enc) = asset.encodings.get_mut(*enc_name) {
            certify_asset(key.to_string(), &enc.sha256);
            enc.certified = true;
            return;
        }
    }

    // No known encodings found. Just pick the first one. The exact
    // order is hard to predict because we use a hash map. Should
    // almost never happen anyway.
    if let Some(enc) = asset.encodings.values_mut().next() {
        certify_asset(key.to_string(), &enc.sha256);
        enc.certified = true;
    }
}

fn certify_asset(key: Key, content_hash: &Hash) {
    ASSET_HASHES.with(|t| {
        let mut tree = t.borrow_mut();
        tree.insert(key, *content_hash);
        set_root_hash(&*tree);
    });
}

fn delete_asset_hash(key: &str) {
    ASSET_HASHES.with(|t| {
        let mut tree = t.borrow_mut();
        tree.delete(key.as_bytes());
        set_root_hash(&*tree);
    });
}

fn set_root_hash(tree: &AssetHashes) {
    use ic_certified_map::labeled_hash;
    let full_tree_hash = labeled_hash(b"http_assets", &tree.root_hash());
    set_certified_data(&full_tree_hash);
}

fn witness_to_header<'a>(witness: HashTree<'a>) -> HeaderField {
    use ic_certified_map::labeled;

    let hash_tree = labeled(b"http_assets", witness);
    let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
    serializer.self_describe().unwrap();
    hash_tree.serialize(&mut serializer).unwrap();

    let certificate = data_certificate().unwrap_or_else(|| trap("no data certificate available"));

    (
        "IC-Certificate".to_string(),
        format!(
            "certificate=:{}:, tree=:{}:",
            base64::encode(&certificate),
            base64::encode(&serializer.into_inner())
        ),
    )
}

fn merge_hash_trees<'a>(lhs: HashTree<'a>, rhs: HashTree<'a>) -> HashTree<'a> {
    use HashTree::{Fork, Labeled, Pruned};

    match (lhs, rhs) {
        (Pruned(_), r) => r,
        (l, Pruned(_)) => l,
        (Fork(l), Fork(r)) => Fork(Box::new((
            merge_hash_trees(l.0, r.0),
            merge_hash_trees(l.1, r.1),
        ))),
        (Labeled(l_label, l), Labeled(_, r)) => {
            Labeled(l_label, Box::new(merge_hash_trees(*l, *r)))
        }
        (other, _) => other,
    }
}

fn hash_bytes(bytes: &[u8]) -> Hash {
    let mut hash = sha2::Sha256::new();
    hash.update(bytes);
    hash.finalize().into()
}

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

        for (asset_name, asset) in s.assets.borrow_mut().iter_mut() {
            for enc in asset.encodings.values_mut() {
                enc.certified = false;
            }
            on_asset_change(asset_name, asset);
        }
    });
}

fn main() {}
