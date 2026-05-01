# Certified Assets

This workspace contains three crates:

## [`canister/`](canister/)

The ICP assets canister — a deployable WebAssembly canister that serves certified static assets over HTTP. It wraps `ic-certified-assets` and exposes the canister interface.

## [`ic-certified-assets/`](ic-certified-assets/)

The core business logic library. Handles asset storage, certification (response verification), streaming, and access control. `canister` depends on this crate; it can also be embedded in other canisters.

## [`plugin/`](plugin/)

An `icp-cli` sync plugin. After a deploy, it uploads assets from a local directory to the assets canister using the canister's batch upload API.
