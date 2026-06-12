# Certified Assets

An ICP assets canister and `icp-cli` sync plugin for serving certified static assets.

## Building the wasm

```sh
make wasm        # build both modules into dist/
make canister    # canister wasm only
make plugin      # sync-plugin wasm only
make release     # publishable build (see Releasing for ASSETS_BUNDLE_TAG)
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

- `dist/canister-release.wasm` — [`certified-assets.did`](certified-assets.did)
  attached as `candid:service` metadata via [`ic-wasm`](https://crates.io/crates/ic-wasm)
  (`cargo install ic-wasm`), and `dist/canister-release.wasm.gz`, its gzipped form.
- `dist/plugin-release.wasm` — copied as-is for now; it'll be gzipped once the
  icp-cli sync plugin can load a gzipped wasi module.
- `dist/certified-assets.did` — the candid interface, for integrators.
- `dist/<file>.sha256` — a SHA-256 checksum beside each published file, so a
  downloaded artifact can be verified on its own (`shasum -a 256 -c <file>.sha256`).

`ASSETS_BUNDLE_TAG` is the optional release identity stamped into **both**
modules so a deployed canister and its sync plugin only pair with their exact
counterpart. It's the build time as a 12-digit `YYYYMMDDhhmm` (UTC) integer —
e.g. `202606121430` for 2026-06-12 14:30 — and is left unset for e2e and manual
builds, which are then unstamped. See Releasing for where its value comes from.

## Releasing

A release is a git tag whose name **is** the bundle tag: the released commit's
committer time as `YYYYMMDDhhmm` in UTC. Deriving it from the commit — not from
when you happen to tag — means re-tagging the same commit always yields the same
value, and the tag equals the exact integer the `bundle_tag` query returns at
runtime, so a plugin/canister mismatch maps straight back to a release.

```sh
make tag                 # create the tag for HEAD (prints the push command)
git push origin <tag>    # triggers .github/workflows/release.yml
```

The workflow re-derives the tag from the commit and rejects a mismatch, then runs
`make release ASSETS_BUNDLE_TAG=<tag>` and publishes `dist/canister-release.wasm.gz`
and `dist/plugin-release.wasm` to a GitHub release. Crate versions stay `0.0.0`;
the bundle tag is the only release identifier.

## Candid interface

[`certified-assets.did`](certified-assets.did) is the canister's public interface
and the single source of truth for its Candid types. The `candid_interface_compatibility` test
in [`crates/canister/src/lib.rs`](crates/canister/src/lib.rs) checks the
Rust-exported service against this file (via `service_equal`), so the two stay in
lockstep.

The HTTP types (`HeaderField`, `HttpRequest`, `HttpResponse`, `StreamingToken`,
`StreamingStrategy`, `StreamingCallbackHttpResponse`) come from the official
[IC HTTP Gateway specification](https://docs.internetcomputer.org/references/http-gateway-protocol-spec/),
kept as published except for `StreamingToken`: the spec defines it as an opaque
placeholder each canister fills in with its own concrete type, and
`certified-assets.did` fills it in with the assets canister's concrete token. The file is self-contained
(no `import`) so it can be attached to the canister wasm as Candid metadata.
