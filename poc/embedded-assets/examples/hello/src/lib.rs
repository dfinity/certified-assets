//! A canister whose whole site is baked into its Wasm at compile time.

use embedded_certified_assets::{HttpRequest, HttpResponse};

embedded_certified_assets::include_assets!();

#[ic_cdk::init]
fn init() {
    embedded_certified_assets::init(&ASSETS);
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    embedded_certified_assets::init(&ASSETS);
}

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse<'static> {
    embedded_certified_assets::http_request(req)
}

ic_cdk::export_candid!();
