# Certified Assets

An ICP assets canister and `icp-cli` sync plugin for serving certified static assets.

## Candid interface

[`assets.did`](assets.did) is the canister's public interface and the single
source of truth for its Candid types. The `candid_interface_compatibility` test
in [`crates/canister/src/lib.rs`](crates/canister/src/lib.rs) checks the
Rust-exported service against this file (via `service_equal`), so the two stay in
lockstep.

The HTTP types (`HeaderField`, `HttpRequest`, `HttpResponse`, `StreamingToken`,
`StreamingStrategy`, `StreamingCallbackHttpResponse`) come from the official
[IC HTTP Gateway specification](https://docs.internetcomputer.org/references/http-gateway-protocol-spec/),
kept as published except for `StreamingToken`: the spec defines it as an opaque
placeholder each canister fills in with its own concrete type, and `assets.did`
fills it in with the assets canister's concrete token. The file is self-contained
(no `import`) so it can be attached to the canister wasm as Candid metadata.
