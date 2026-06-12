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
CANDID := assets.did

# Optional release identity compiled into both modules. The release workflow
# computes it once — `ASSETS_BUNDLE_TAG=$$(( $$(date -u +%s) / 60 ))` — and passes
# it here, so the plugin only syncs against its exact counterpart. Left unset for
# e2e and manual builds, which become unstamped (None) dev builds. wire-types
# reads it via option_env!, so leaving it unset also keeps those builds out of
# the recompile-on-tag-change path.
TAG_ENV := $(if $(ASSETS_BUNDLE_TAG),ASSETS_BUNDLE_TAG=$(ASSETS_BUNDLE_TAG),)

.PHONY: wasm canister plugin release tag clean

# Build both wasm modules into dist/. Used by the tests and for manual builds;
# needs no extra tooling.
wasm: canister plugin

# Recipes are phony on purpose: cargo already does incremental freshness
# tracking, so we always invoke it (cheap when nothing changed) and let it decide
# whether a rebuild is needed, then copy the result into dist/.
canister:
	$(TAG_ENV) cargo build -p canister --target $(CANISTER_TARGET) --profile $(CANISTER_PROFILE)
	@mkdir -p $(DIST)
	cp $(CANISTER_OUT) $(DIST)/canister.wasm

plugin:
	$(TAG_ENV) cargo build -p sync-plugin --target $(PLUGIN_TARGET) --profile $(PLUGIN_PROFILE)
	@mkdir -p $(DIST)
	cp $(PLUGIN_OUT) $(DIST)/plugin.wasm

# Publishable artifacts. Written under *-release names so the post-processing
# never clobbers the plain dist/canister.wasm / dist/plugin.wasm the tests build:
#
#   dist/canister-release.wasm     — candid interface attached as metadata
#   dist/canister-release.wasm.gz  — the above, gzipped (the canister the IC installs)
#   dist/plugin-release.wasm       — copied as-is; icp-cli can't load a gzipped
#                                    wasi module yet, so gzip it here once it can
#
# The canister attach requires ic-wasm (`cargo install ic-wasm`); the plain
# `wasm` target does not.
release: wasm
	ic-wasm $(DIST)/canister.wasm -o $(DIST)/canister-release.wasm metadata candid:service -f $(CANDID) -v public
	gzip -n9c $(DIST)/canister-release.wasm > $(DIST)/canister-release.wasm.gz
	cp $(DIST)/plugin.wasm $(DIST)/plugin-release.wasm

# Create the release tag for HEAD. The tag's name IS the bundle tag — HEAD's
# committer time in minutes since the Unix epoch (UTC) — so it depends only on
# the commit, not on when you run this: re-tagging the same commit yields the
# same value. Push it (`git push origin <tag>`) to trigger the release workflow,
# which re-derives this value from the commit and rejects a mismatch.
tag:
	@tag=$$(( $$(git log -1 --format=%ct) / 60 )); \
	git tag -a "$$tag" -m "Release $$tag"; \
	echo "Created tag $$tag — push it with: git push origin $$tag"

clean:
	rm -rf $(DIST)
