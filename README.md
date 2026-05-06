# Certified Assets

Two Wasm modules, each backed by a library crate:

```
         ┌────────────────────┐   ┌────────────────────┐
         │     canister/      │   │      plugin/       │
         │  deployed to ICP   │   │  loaded by icp-cli │
         └─────────┬──────────┘   └─────────┬──────────┘
                   │ wraps                  │ wraps
         ┌─────────▼──────────┐   ┌─────────▼──────────┐
         │  ic-certified-     │   │   assets-sync/     │
         │    assets/         │   │                    │
         └────────────────────┘   └────────────────────┘
```

## [`canister/`](canister/)

The ICP assets canister — a deployable WebAssembly canister that serves certified static assets over HTTP. It wraps `ic-certified-assets` and exposes the canister interface.

### [`ic-certified-assets/`](ic-certified-assets/)

The core business logic library. Handles asset storage, certification (response verification), streaming, and access control. `canister` depends on this crate; it can also be embedded in other canisters.

## [`plugin/`](plugin/)

A thin `icp-cli` sync plugin. Delegates all sync logic to `assets-sync`.

### [`assets-sync/`](assets-sync/)

Platform-agnostic library implementing the asset sync logic: directory scanning, MIME detection, content encoding, canister diffing, and the `CanisterCall` trait that abstracts the transport layer.
