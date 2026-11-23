# Embedded certified assets (PoC)

Bake a static site into the canister Wasm at compile time and serve it with
IC response certification (v2). No sync step: install the module and the site is
already live. Changing the site means rebuilding and upgrading the canister.

This is a standalone Cargo workspace. It is **not** a member of the repo-root
workspace. It reuses `asset-prep` and `wire-types` from `../../crates` as
build-time path dependencies and does not modify them.

## Using it

```rust
// build.rs
fn main() {
    embedded_certified_assets_build::embed("dist").expect("embedding dist/");
}
```

```rust
// src/lib.rs
use embedded_certified_assets::{HttpRequest, HttpResponse};

embedded_certified_assets::include_assets!(); // defines `static ASSETS`

#[ic_cdk::init]
fn init() { embedded_certified_assets::init(&ASSETS); }

#[ic_cdk::post_upgrade]
fn post_upgrade() { embedded_certified_assets::init(&ASSETS); }

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse<'static> {
    embedded_certified_assets::http_request(req)
}
```

See [`examples/hello`](examples/hello) for a full example (`cd examples/hello && icp network start -d && icp deploy`).

## How it works

| Stage | Where | What |
|---|---|---|
| Prepare | `build.rs` (`embedded-certified-assets-build`) | `asset-prep::prepare_project` with `Compressors::canonical()`: scanning, MIME types, gzip/brotli, `_headers`, `_redirects`, html-handling, 404 convention. Same as the synced canister. |
| Resolve routes | `build.rs` | Turns assets and rules into a table of certified locations (exact paths and wildcard prefixes), each with one fixed response. See below. |
| Hash | `build.rs` | Builds every (route, encoding) response with its final headers and computes its v2 response hash. |
| Generate | `build.rs` | Writes `$OUT_DIR/embedded_certified_assets.rs`: `static ASSETS` made of `&'static` data, with bodies pulled in by `include_bytes!` from content-addressed files. |
| Certify | `init` / `post_upgrade` (`embedded-certified-assets`) | Inserts the precomputed leaves into an `HttpCertificationTree` (`response_only_prehashed`) and calls `certified_data_set(root)`. Asset bytes are never hashed at runtime, so init cost does not grow with site size. |
| Serve | `http_request` query | Exact path, otherwise the longest wildcard prefix. Picks an encoding (br > gzip > identity, `q=0` respected) and adds the witness as the `IC-Certificate` header. |

**Route resolution.** The synced canister checks `_redirects` rules in
declaration order at request time. The gateway's v2 verification instead
requires "exact match, otherwise the most specific wildcard". Rule responses do
not depend on the request path (there is no `:splat`), so the build script can
work out the declaration-order winner for each certified location ahead of
time. The resulting table agrees with both. Assets always win at their own
path. Rules whose target asset is missing are inert. A plain-text 404 at the `/`
wildcard is the last resort if nothing else covers it, although asset-prep's
404 convention normally covers it already.

All response headers are certified, using one response-only CEL expression.

## Verified

- `cargo test -p hello` serves every route kind through `Router` and checks
  each response with `ic-response-verification` against a test certificate.
  This covers assets, html-handling 200s and 307s, an exact 301, a subtree 200
  rewrite (wildcard), the custom 404 page (wildcard), percent-decoding, and all
  three encodings. A tampered body is shown to be rejected.
- Deployed with `icp deploy` to a local network and fetched through its
  verifying HTTP gateway: all route kinds work, and an edit + redeploy
  (`post_upgrade`) serves the new content.

## Not in scope (PoC)

- **Bodies over ~1.9 MB** (one query response). The build fails with a clear
  error. Supporting them would need chunked 206 responses, as the synced
  canister does.
- ETag/304, range requests, access protection, governance, `state_hash`, and
  the `ic_env` cookie.
- Size budget. Everything lives in the Wasm data segment and heap. All
  encodings are embedded, so a compressible site costs roughly identity +
  gzip + br. Dropping gzip (every browser accepts br) would be a cheap win.
