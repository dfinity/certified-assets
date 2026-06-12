# Certified Assets

An ICP assets canister and `icp-cli` sync plugin for serving certified static assets.

## Building the wasm

```sh
make wasm        # build both modules into dist/
make canister    # canister wasm only
make plugin      # sync-plugin wasm only
make release ASSETS_BUNDLE_TAG=$(( $(date -u +%s) / 60 ))  # publishable build
```

Artifacts land in `dist/` under stable names (`dist/canister.wasm`,
`dist/plugin.wasm`). The [`Makefile`](Makefile) is the single source of truth
for the build recipe — which target triple and profile each module uses — and
is reused by the e2e tests and the release workflow so they all ship the same
artifacts. The canister is built with the size-optimized `canister-release`
profile (see [`Cargo.toml`](Cargo.toml)).

`make wasm` is what the tests and manual builds use; it needs no extra tooling.
`make release` produces the publishable artifacts under separate `*-release`
names (so it never clobbers the plain `dist/canister.wasm`/`dist/plugin.wasm`):

- `dist/canister-release.wasm` — [`assets.did`](assets.did) attached as
  `candid:service` metadata via [`ic-wasm`](https://crates.io/crates/ic-wasm)
  (`cargo install ic-wasm`), and `dist/canister-release.wasm.gz`, its gzipped form.
- `dist/plugin-release.wasm` — copied as-is for now; it'll be gzipped once the
  icp-cli sync plugin can load a gzipped wasi module.

`ASSETS_BUNDLE_TAG` is the optional release identity stamped into **both**
modules so a deployed canister and its sync plugin only pair with their exact
counterpart. The release workflow computes it once and passes the same value to
the build; left unset (e2e and manual builds) the artifacts are unstamped.

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
