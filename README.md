# Certified Assets Canister

This is the re-implementation of the DFX assets canister in Rust with support for asset certification.

## Certified Assets Library

Certified assets can also be served from any Rust canister by including the certified-assets-lib crate:

```
[dependencies]
certified-assets-lib = { git = "https://github.com/dfinity/certified-assets", branch = "main"}
```

The assets are over upgrades by including the corresponding functions in the `init/pre_upgrade/upgrade`
hooks which can be mixed with the other state from the canister:

```
#[derive(Clone, Debug, CandidType, Deserialize)]
struct StableState {
  my_state: MyState,
  assets: crate::assets::StableState,
}

#[init]
fn init() {
  crate::assets::init();
}

>>#[pre_upgrade]
fn pre_upgrade() {
  let stable_state = STATE.with(|s| StableState {
    my_state: s.my_state,
    assets: crate::assets::pre_upgrade(),
  });
  ic_cdk::storage::stable_save((stable_state,)).expect("failed to save stable state");
}

>>#[post_upgrade]
fn post_upgrade() {
  let (stable_state,): (StableState,) =
    ic_cdk::storage::stable_restore().expect("failed to restore stable state");
  crate::assets::post_upgrade(stable_state.assets);
  STATE.with(|s| {
      s.my_state = stable_state.my_state;
  };
}
```
