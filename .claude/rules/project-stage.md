# Project stage

This is a fast-evolving, pre-launch project. There are **no production instances**, so:

- **No backward compatibility constraints.** Don't preserve compatibility with existing deployed canisters, previously serialized stable state, or older on-disk formats — there are none to protect. Feel free to change stable-state shapes, drop legacy fields, and remove migration/fallback code paths.
- **No compatibility with the "old" assets canister.** The canister code was seeded by trimming down a working implementation from the SDK repo, purely as a development shortcut. We do **not** aim to interoperate with or upgrade from that old implementation. Anything that only exists to support it can be removed.

The only contract that matters is that the **canister and sync-plugin in this repo work well together**.
