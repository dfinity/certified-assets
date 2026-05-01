# Example

A minimal project that deploys a certified-assets canister with a static frontend using the sync plugin.

## Prerequisites

`icp` must be a build of [icp-cli](https://github.com/dfinity/icp-cli) that includes sync plugin support (not yet available in a released version).

You also need [`ic-wasm`](https://github.com/dfinity/ic-wasm) on your `PATH` for the canister build step.

## Running manually

```sh
# Start a local replica
icp network start -d

# Build and deploy the canister, then sync assets via the plugin
icp deploy

# Open the printed frontend canister URL in a browser and verify the page renders correctly

# Stop the replica when done
icp network stop
```

## Proxy deployment path

To exercise the proxy mode — canister created and owned by the proxy identity, assets uploaded via your user identity with direct calls — replace `icp deploy` with:

```sh
icp deploy --proxy txyno-ch777-77776-aaaaq-cai
```

The plugin will ensure your signing identity has `Commit` permission (routing a `grant_permission` call through the proxy if needed) before uploading assets directly.
