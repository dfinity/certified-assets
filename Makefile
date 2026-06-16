# Build the canister and sync-plugin wasm modules.
#
# Single source of truth for how the wasm artifacts are compiled — which crate,
# target triple, and profile each uses. Reused by:
#   - crates/e2e/build.rs (the tests build their wasm through `make wasm`)
#   - the release workflow (`make release ASSETS_BUNDLE_TAG=…`)
#   - developers building the wasm by hand
#
# Built artifacts are copied to dist/ under stable, profile-independent names so
# consumers never have to encode the target triple or profile in a path:
#   dist/canister.wasm
#   dist/plugin.wasm

DIST := dist

# The canister ships size-optimized (canister-release: lto + opt-level=z); the
# plugin uses the standard release profile. See Cargo.toml.
CANISTER_TARGET  := wasm32-unknown-unknown
CANISTER_PROFILE := canister-release
PLUGIN_TARGET    := wasm32-wasip2
PLUGIN_PROFILE   := release

CANISTER_OUT := target/$(CANISTER_TARGET)/$(CANISTER_PROFILE)/canister.wasm
PLUGIN_OUT   := target/$(PLUGIN_TARGET)/$(PLUGIN_PROFILE)/sync_plugin.wasm

# Candid interface attached to the published canister wasm as `candid:service`.
CANDID := certified-assets.did

# The release identity compiled into both modules is the single workspace semver
# in Cargo.toml, which the crates read at build time via `CARGO_PKG_VERSION` — no
# env var to plumb here. See crates/wire-types/src/version.rs and the `tag`
# target.

.PHONY: wasm canister plugin release recipe-local recipe-release tag clean

# Build both wasm modules into dist/. Used by the tests and for manual builds;
# needs no extra tooling.
wasm: canister plugin

# Recipes are phony on purpose: cargo already does incremental freshness
# tracking, so we always invoke it (cheap when nothing changed) and let it decide
# whether a rebuild is needed, then copy the result into dist/.
canister:
	cargo build -p canister --target $(CANISTER_TARGET) --profile $(CANISTER_PROFILE)
	@mkdir -p $(DIST)
	cp $(CANISTER_OUT) $(DIST)/canister.wasm

plugin:
	cargo build -p sync-plugin --target $(PLUGIN_TARGET) --profile $(PLUGIN_PROFILE)
	@mkdir -p $(DIST)
	cp $(PLUGIN_OUT) $(DIST)/plugin.wasm

# Publishable artifacts. Written under *-release names so the post-processing
# never clobbers the plain dist/canister.wasm / dist/plugin.wasm the tests build.
# This is the complete set the release workflow uploads:
#
#   dist/canister-release.wasm     — candid interface attached as metadata
#   dist/canister-release.wasm.gz  — the above, gzipped (the canister the IC installs)
#   dist/plugin-release.wasm       — copied as-is; icp-cli can't load a gzipped
#                                    wasi module yet, so gzip it here once it can
#   dist/certified-assets.did      — the candid interface, for integrators
#   dist/<file>.sha256             — a SHA-256 checksum beside each artifact above,
#                                    so a downloaded file verifies on its own
#
# The canister attach requires ic-wasm (`cargo install ic-wasm`); the plain
# `wasm` target does not. `shasum -a 256` is used for the checksums so it runs
# the same on macOS and Linux.
release: wasm
	ic-wasm $(DIST)/canister.wasm -o $(DIST)/canister-release.wasm metadata candid:service -f $(CANDID) -v public
	gzip -n9c $(DIST)/canister-release.wasm > $(DIST)/canister-release.wasm.gz
	cp $(DIST)/plugin.wasm $(DIST)/plugin-release.wasm
	cp $(CANDID) $(DIST)/$(CANDID)
	cd $(DIST) && for f in canister-release.wasm.gz plugin-release.wasm $(CANDID); do \
	  shasum -a 256 "$$f" > "$$f.sha256"; \
	done

# The icp-cli recipe (`recipe.hbs`) is the product most users consume; both
# variants are generated from one source by the recipe-gen crate.
#
# recipe-local: pins the canister/plugin wasm by local file path — for sanity
# checks outside the e2e harness. (The e2e tests generate their own local recipe
# in-process via the recipe-gen library.)
recipe-local: wasm
	cargo run -p recipe-gen -- local \
	  --canister $(DIST)/canister.wasm \
	  --plugin $(DIST)/plugin.wasm \
	  -o $(DIST)/recipe.local.hbs
	@echo "Wrote $(DIST)/recipe.local.hbs"

# recipe-release: pins the canister/plugin wasm by versioned GitHub release URL +
# sha256. Depends on `release` so the *-release.wasm*.sha256 files exist, and
# reads the version from Cargo.toml the same way `tag` does so the URLs match the
# tag the release workflow publishes. This is the recipe published to
# icp-cli-recipes (see scripts/publish-recipe.sh).
recipe-release: release
	@version=$$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/'); \
	cargo run -p recipe-gen -- release \
	  --version "v$$version" \
	  --shas-from $(DIST) \
	  -o $(DIST)/recipe.hbs; \
	echo "Wrote $(DIST)/recipe.hbs for v$$version"

# Create the release tag for HEAD from the workspace version in Cargo.toml: the
# tag is `v<major>.<minor>.<patch>` (e.g. v0.1.0). Bump the version in
# [workspace.package] and commit first, then run this and push the tag
# (`git push origin v<version>`) to trigger the release workflow, which re-reads
# the version from Cargo.toml and rejects a mismatch. Reading the single `^version`
# line keeps this deterministic and free of extra tooling.
tag:
	@version=$$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/'); \
	git tag -a "v$$version" -m "Release v$$version"; \
	echo "Created tag v$$version — push it with: git push origin v$$version"

clean:
	rm -rf $(DIST)
