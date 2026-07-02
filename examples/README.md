# Examples

Runnable `certified-assets` projects, each a self-contained site with its own
`icp.yaml` and a `README.md` explaining what it demonstrates. Every example is
also an end-to-end test: CI deploys it to a local replica and drives it through
the HTTP gateway (see [`crates/e2e/`](../crates/e2e/)), so these stay working.

| Example | Demonstrates |
|---|---|
| [static-site](static-site/) | The smallest project — an HTML page + stylesheet, synced and served. **Start here.** |
| [custom-headers](custom-headers/) | Per-file, subtree, and global HTTP headers via a `_headers` file. |
| [redirects](redirects/) | Redirects, custom error pages, and rewrites via a `_redirects` file. |
| [clean-urls](clean-urls/) | Extensionless routing (`/foo` → `foo.html`), auto-synthesised with no config. |
| [catch-all-404](catch-all-404/) | A `/*` catch-all serving a custom 404 page for every unknown URL. |
| [access-protection](access-protection/) | Turning a public site into a private one gated behind an access token. |

## Running any example

Each example's `icp.yaml` references the canister and sync-plugin wasms at
`../../dist/`. Build them once from the repo root, then deploy the example in
place:

```sh
make wasm                     # builds dist/canister.wasm + dist/plugin.wasm
cd examples/<name>
icp network start -d
icp deploy                    # note the frontend URL it prints
```

Stop the local replica when you're done with `icp network stop`. See each
example's own README for what to try and the prerequisites.
