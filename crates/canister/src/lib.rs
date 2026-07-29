use candid::Principal;
use canister_core::{
    AssetDetails, ByteBuf, ChunkId, ExecuteOperationsArguments, HttpRequest, HttpResponse,
    IssueTokenArgs, ProtectionStatus, RedirectRule, StartSyncResult, TokenInfo,
    UploadChunksArguments, Version, guard_can_sync, guard_is_controller,
};
use ic_cdk::{post_upgrade, query, update};

#[post_upgrade]
fn post_upgrade() {
    canister_core::post_upgrade();
}

#[cfg(target_family = "wasm")]
#[used]
#[unsafe(link_section = "icp:public supported_certificate_versions")]
static CERTIFICATE_VERSIONS: [u8; 1] = *b"2"; // The canister supports v2 certificates, but not v1.

// Query methods

#[query]
fn version() -> Version {
    canister_core::version()
}

#[query]
fn get_asset_details(start_after: Option<String>) -> Vec<AssetDetails> {
    canister_core::get_asset_details(start_after)
}

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    canister_core::http_request(req)
}

#[query]
fn get_redirect_rules(start_index: u64) -> Vec<RedirectRule> {
    canister_core::get_redirect_rules(start_index)
}

// Update methods

#[update(guard = "guard_is_controller")]
fn authorize(principal: Principal) {
    canister_core::authorize(principal)
}

#[update(guard = "guard_is_controller")]
fn deauthorize(principal: Principal) {
    canister_core::deauthorize(principal)
}

// Recaptures the `PUBLIC_*` env vars + IC root key and re-certifies the `ic_env`
// cookie onto every HTML response. Any sync-authorized caller may trigger it
// (same guard as a sync) — only controllers can *change* the env vars, but an
// authorized syncer should be able to re-publish them. The env is also captured
// at the start of every sync, so this is only needed to publish an env-var
// change without a content sync.
#[update(guard = "guard_can_sync")]
fn refresh_env() {
    canister_core::refresh_env()
}

#[update]
fn list_authorized() -> Vec<Principal> {
    canister_core::list_authorized()
}

// The canister's canonical state hash: a SHA-256 over its served-content model
// (every asset's content_type/headers/encoding hashes + the redirect rules; see
// `state-hash`). Recomputed at the end of every final sync. Public and
// unguarded; an **update** (not a query) so the reply is consensus-backed and a
// third party can trust it against a hash they computed locally from the source
// build. Returns the cached value with no recomputation.
#[update]
fn state_hash() -> ByteBuf {
    canister_core::state_hash()
}

// Whether the calling identity may sync assets (authorized or a controller).
// Lets a client check access up front instead of discovering it mid-sync.
#[query]
fn can_sync() -> bool {
    canister_core::can_sync()
}

#[update(guard = "guard_can_sync")]
fn start_sync() -> StartSyncResult {
    canister_core::start_sync()
}

#[update(guard = "guard_can_sync")]
fn upload_chunks(arg: UploadChunksArguments) -> Vec<ChunkId> {
    canister_core::upload_chunks(arg)
}

// Returns the canonical state hash on the call flagged `is_final` (`None`
// otherwise), so a finishing sync learns what it installed without a second
// round trip. Canister-reported: a self-consistency read, not verification.
#[update(guard = "guard_can_sync")]
async fn execute_operations(arg: ExecuteOperationsArguments) -> Option<ByteBuf> {
    canister_core::execute_operations(arg).await
}

// ───────── Access protection ─────────
// Controller-only configuration for the "private app" gate. None of these touch
// the serving hot path; all serving (including login validation) stays in the
// `http_request` query.

#[update(guard = "guard_is_controller")]
fn enable_protection(login_page: String) {
    canister_core::enable_protection(login_page)
}

#[update(guard = "guard_is_controller")]
fn disable_protection() {
    canister_core::disable_protection()
}

#[update(guard = "guard_is_controller")]
async fn issue_token(args: IssueTokenArgs) -> String {
    canister_core::issue_token(args).await
}

#[update(guard = "guard_is_controller")]
fn revoke_token(label: String) {
    canister_core::revoke_token(label)
}

#[query(guard = "guard_is_controller")]
fn list_tokens() -> Vec<TokenInfo> {
    canister_core::list_tokens()
}

#[query(guard = "guard_is_controller")]
fn check_protection_status() -> ProtectionStatus {
    canister_core::check_protection_status()
}

ic_cdk::export_candid!();

#[test]
fn candid_interface_compatibility() {
    use candid_parser::utils::{CandidSource, service_equal};
    use std::path::PathBuf;

    let new_interface = __export_service();

    // crates/canister -> crates -> workspace root, then certified-assets.did
    let old_interface = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../certified-assets.did");

    println!("Exported interface: {new_interface}");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("The assets canister interface is not compatible with the certified-assets.did file");
}
