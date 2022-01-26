use ic_cdk_macros::{init, post_upgrade, pre_upgrade};

#[init]
fn init() {
    certified_assets_lib::init();
}

#[pre_upgrade]
fn pre_upgrade() {
    ic_cdk::storage::stable_save((certified_assets_lib::pre_upgrade(),))
        .expect("failed to save stable state");
}

#[post_upgrade]
fn post_upgrade() {
    let (stable_state,): (certified_assets_lib::StableState,) =
        ic_cdk::storage::stable_restore().expect("failed to restore stable state");
    certified_assets_lib::post_upgrade(stable_state);
}
