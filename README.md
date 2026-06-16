# Certified Assets

An ICP assets canister and `icp-cli` sync plugin for serving certified static assets.

## Building the wasm

```sh
make wasm        # build both modules into dist/
make canister    # canister wasm only
make plugin      # sync-plugin wasm only
make release     # publishable build (canister + plugin + candid + checksums)
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

The release identity stamped into **both** modules is the single workspace
semver from [`Cargo.toml`](Cargo.toml), read at build time from
`CARGO_PKG_VERSION` — so every build (dev or release) knows its own version and
a deployed canister only pairs with the sync plugin that reports the identical
version. See Releasing for what the number means and how to bump it.

## Releasing

Every crate shares one semver, and that version doubles as the canister↔plugin
release identity: the canister returns it from the `version` query and the
plugin refuses to sync unless it matches its own exactly (they're a locked
pair). The version *value* also says whether moving the canister between two
releases keeps its state — following Cargo's 0.x rule while `major` is `0`:

| Change | Bump | Canister switch |
| --- | --- | --- |
| **Non-breaking** | patch (`0.1.0 → 0.1.1`) | in-place `upgrade`; `post_upgrade` recovers all state |
| **Breaking** | minor (`0.1.x → 0.2.0`) | `reinstall`; state is wiped, a fresh sync re-uploads everything |

(From `1.0.0` on, a major bump is the breaking one.) Choosing breaking vs
non-breaking is a deliberate call — the axis is canister *state* upgradability —
so bump it by hand:

```sh
# 1. edit version in [workspace.package] in Cargo.toml, commit
make tag                 # tags HEAD `v<version>` from Cargo.toml (prints the push command)
git push origin v<version>   # triggers .github/workflows/release.yml
```

The workflow re-reads the version from `Cargo.toml`, rejects a tag that doesn't
match, then runs `make release` and publishes `dist/canister-release.wasm.gz`
and `dist/plugin-release.wasm` to a GitHub release named for the version.

## Recipe

Most users don't reference the canister/plugin wasm directly — they use the
**recipe** published to [`dfinity/icp-cli-recipes`](https://github.com/dfinity/icp-cli-recipes),
which `icp-cli` expands into a canister build + sync config:

```yaml
canisters:
  - name: frontend
    recipe:
      type: "@dfinity/certified-assets@v1.0.0"
      configuration:
        dir: dist           # required: the single asset directory
        build: [npm run build]   # optional: commands run before sync
        # metadata: [...]    # optional: name/value pairs injected via ic-wasm
```

The recipe (`recipe.hbs`) is generated from one source —
[`crates/recipe-gen/src/recipe.hbs.in`](crates/recipe-gen/src/recipe.hbs.in) —
in two variants that differ only in how the wasm is pinned:

```sh
make recipe-local        # pins wasm by local path -> dist/recipe.local.hbs (for manual testing)
make recipe-release      # pins wasm by release URL + sha256 -> dist/recipe.hbs (for publishing)
```

The e2e tests exercise the local variant through the real `icp` CLI
([`crates/e2e/tests/recipe.rs`](crates/e2e/tests/recipe.rs)), and `recipe-gen`'s
unit tests assert every config field renders to valid icp-cli YAML.

To publish a new recipe version after a `v<version>` release exists:

```sh
scripts/publish-recipe.sh v<version>          # generates + commits on a branch in ../icp-cli-recipes; prints the PR command
scripts/publish-recipe.sh v<version> --push   # also pushes and opens the PR
```

The script downloads the release's `.sha256` assets to pin the exact published
wasm, branches off a fresh `origin/main` in your icp-cli-recipes clone, and
writes `recipes/certified-assets/{recipe.hbs,README.md}`. After the PR merges,
tag `certified-assets-v<version>` in icp-cli-recipes to cut the recipe release.

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
