## Build and run the example

The [`example/`](example/) directory contains a minimal `icp.yaml` that builds the [`canister/`](canister/) and uses the [`plugin/`](plugin/) to sync assets from `example/dist/` after deploy.

Prerequisites:
- The Rust targets `wasm32-unknown-unknown` and `wasm32-wasip2` (declared in [`rust-toolchain.toml`](rust-toolchain.toml)).
- [`ic-wasm`](https://github.com/dfinity/ic-wasm) on `PATH`.
- A local build of `icp-cli` from the `lwshang/sync_plugin` branch (the runtime side of the sync plugin system is not yet released).

Steps from the project root:

```sh
# 1. Build the sync plugin. (The canister is built automatically by `icp deploy`
#    via icp.yaml, but the plugin path in icp.yaml points at a prebuilt artifact.)
cargo build -p plugin --target wasm32-wasip2 --release

# 2. Deploy from the example directory.
cd example
icp deploy
```

`icp deploy` runs the build steps declared in [`example/icp.yaml`](example/icp.yaml) (which builds and installs the canister), then invokes the plugin to upload everything in `example/dist/` to the canister.
