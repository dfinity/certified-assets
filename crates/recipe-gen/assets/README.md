# Certified Assets Recipe

Deploy a static frontend to the [`dfinity/certified-assets`](https://github.com/dfinity/certified-assets) canister, with response certification and asset synchronization handled for you.

Each released version of this recipe pins a **matched pair** of the certified-assets canister wasm and its sync plugin. The two must share the same version, so — unlike a generic pre-built recipe — there is no user-selectable canister `version`; choose it via the recipe version in the `type` field instead.

## Usage

Reference this recipe in an `icp.yaml` (or `canister.yaml`) file:

```yaml
canisters:
  - name: frontend
    recipe:
      type: "@dfinity/certified-assets@<version>"
      configuration:
        dir: dist
```

> Replace `<version>` with a release version (e.g. `v1.0.0`). See [available versions](https://github.com/dfinity/icp-cli-recipes/releases?q=certified-assets&expanded=true).

## Configuration Parameters

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| dir | string | Yes | The single directory of built assets to synchronize to the canister | - |
| build | array | No | Shell commands run before sync to produce the asset directory (e.g. `npm run build`) | [] |
| metadata | array | No | Name/value pairs injected into the canister wasm via `ic-wasm` | [] |

> The sync plugin owns the canister's full URL space and accepts **exactly one** asset directory, so `dir` is a single string rather than a list.

## Prerequisites

- The asset directory must already exist or be produced by the `build` commands.
- Internet connection to download the pinned canister and plugin wasm.
- `ic-wasm` (bundled with icp-cli) — only required when using the `metadata` option.

> **Note:** If you followed the [icp-cli installation guide](https://github.com/dfinity/icp-cli#installation), `ic-wasm` is already installed.

## Examples

### Basic

```yaml
canisters:
  - name: website
    recipe:
      type: "@dfinity/certified-assets@<version>"
      configuration:
        dir: build
```

### With a build step and metadata

```yaml
canisters:
  - name: spa-frontend
    recipe:
      type: "@dfinity/certified-assets@<version>"
      configuration:
        build:
          - npm ci
          - npm run build
        dir: dist
        metadata:
          - name: "frontend:framework"
            value: "react"
```

## Build Process

When this recipe runs:

1. (If `build` is set) runs your build commands to produce the asset directory.
2. Downloads the pinned certified-assets canister wasm (verified against its `sha256`).
3. (If `metadata` is set) injects each name/value pair into the wasm with `ic-wasm`.
4. Installs the canister, then runs the pinned sync plugin to upload and certify the assets in `dir`.

## Asset Synchronization

The sync plugin diffs your local directory against the canister and uploads only what changed. It serves:

- **Static files** — HTML, CSS, JS, images, fonts, etc., with response certification.
- **Content encoding** — gzip/Brotli negotiation per request.
- **Redirects & headers** — driven by `_redirects` / `_headers` files in the asset directory.
- **404 handling** — a certified fallback plus your own `/404.html` if present.

## Common Issues

**Version mismatch between plugin and canister** — re-deploy with the same recipe version so the canister and plugin are the matched pair this recipe pins.

**Assets directory not found** — ensure the directory in `dir` exists or is produced by your `build` commands.

**`ic-wasm` not found** — only the `metadata` option needs it; install it or drop the `metadata` config.

## Related Recipes

- [Pre-built Recipe](../prebuilt/README.md) — for arbitrary pre-compiled wasm.
- [Rust Recipe](../rust/README.md) — for backend Rust canisters.
- [Motoko Recipe](../motoko/README.md) — for backend Motoko canisters.

## Release History

See the [release history](https://github.com/dfinity/icp-cli-recipes/releases?q=certified-assets&expanded=true) for changelogs and version updates.
