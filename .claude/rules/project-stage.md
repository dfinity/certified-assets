# Project stage

This project is **launching**. `v0.3.0` is the first release whose recipe
(`@dfinity/static-site`) is published to the public `icp-cli-recipes` registry, so
from this version on we should expect **real production canisters** in the wild.
The old "no production instances, break anything" stance no longer applies.

The compatibility contract is the one the release machinery already encodes — see
[`crates/wire-types/src/version.rs`](../../crates/wire-types/src/version.rs) and the
"Releasing" section of the [README](../../README.md):

- **Within a release series, stable state must survive an upgrade.** The canister and
  plugin ship as a version-locked pair, and while `major == 0` a *patch* bump
  (`0.3.0 → 0.3.1`) is a non-breaking, in-place `upgrade`: `post_upgrade` must recover
  state written by any earlier build in the same series. Don't land a stable-state
  shape change that a patch release couldn't deserialize.
- **Breaking changes are allowed, but are a deliberate, disruptive event.** A *series*
  bump (pre-1.0, a minor: `0.3.x → 0.4.0`) reinstalls the canister and wipes its state;
  a fresh sync re-uploads every asset. That is the sanctioned mechanism for changing
  stable-state shapes, dropping legacy fields, and deleting migration code — fine to
  do, but not free: it discards any canister state not re-derived from the local
  project (e.g. access-protection tokens). Prefer a patch when a change can be made
  compatibly; reach for a series bump consciously.
- **The recipe config is a public interface.** The `canister.yaml` `configuration`
  fields (`dir`, `build`, `presync`, `metadata`) live in users' committed project
  files. Renaming or removing one breaks those projects — treat the recipe schema like
  any other released API.

Two things do **not** change:

- **The canister and sync-plugin in this repo are still the only pair that must
  interoperate**, and they're version-locked, so there is no cross-version wire-protocol
  compatibility to maintain — a deployed canister only ever talks to the plugin that
  reports the identical version.
- **No compatibility with the "old" assets canister.** The canister code was seeded by
  trimming down a working implementation from the SDK repo, purely as a development
  shortcut. We do **not** aim to interoperate with or upgrade from that old
  implementation. Anything that only exists to support it can be removed.
