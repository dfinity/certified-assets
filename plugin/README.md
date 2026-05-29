# icp-cli sync plugin

This crate is the sync plugin invoked by `icp-cli` for assets canister syncing.

## What

`icp-cli` added a new plugin system for canister syncing (operations that always run after canister module installation/upgrade).

This crate is an implementation of it that is supposed to be used with the [`assets canister`](../canister/) only.

It is a WASM component module that only access the functionalities exposed by the icp-cli plugin runtime.

It exports an `exec()` function which executes operations similar to the `sync()` function of the public `ic-asset` crate:
- Read access to one or more directories (assets to be uploaded)
- Sync them to a deployed assets canister

## How

The runtime side of the plugin system lives in [`github.com/dfinity/icp-cli`](https://github.com/dfinity/icp-cli):
- The runtime crate: `crates/icp-sync-plugin`
- An example: `examples/icp-sync-plugin`

All sync logic (directory scanning, MIME detection, content encoding, canister diffing, and per-endpoint call wrappers) lives in the [`assets-sync`](../assets-sync/) library crate. This plugin crate is a thin WASI/WIT wrapper: it implements the `CanisterCall` trait (`WasiCall`) on top of the host's `canister-call` import, then delegates to `assets_sync::sync::sync()`.

The protocol-level pieces (Candid types, batch/chunk upload flow, content encoding) were ported from the `ic-asset` crate in [`github.com/dfinity/sdk`](https://github.com/dfinity/sdk) (`src/canisters/frontend/ic-asset`). The transport layer was rewritten on top of the host's `canister-call` import.

## Build

```sh
cargo build -p plugin --target wasm32-wasip2 --release
```

The output WASM lands at `../target/wasm32-wasip2/release/plugin.wasm` — the path that [`../example/icp.yaml`](../example/icp.yaml) references.

## Scope

The current implementation supports the V2 protocol of the assets canister (transactional batch API):
- The manifest's `dirs:` setting must list **exactly one** directory. The plugin rejects the sync before any canister call if zero or multiple entries are given — the assets canister owns the URL space below `/`, and a single tree keeps key collisions and `_redirects` precedence unambiguous.
- Walks that directory; dotfiles are skipped.
- Detects the MIME type of each file and computes encodings: `gzip` for all `text/*`, `*/javascript`, and `*/html` types (only if the compressed output is smaller), `identity` for everything.
- Diffs against `list_assets()`: skips encodings already in place (matched by sha256), unsets encodings that are stale, and deletes assets that have been removed or whose `content_type` changed.
- Reads `_redirects` at the root of the input directory and replaces the canister's ruleset in the same batch (see "Redirects" below).
- Reads `_headers` at the root of the input directory, resolves per-asset header lists, and routes them through `CreateAssetArguments.headers` and `SetAssetProperties` (see "Headers" below).
- Opens a transaction (`create_batch`), uploads each content chunk via `create_chunks` (one chunk per call, 1.9 MB max), then commits all operations atomically with a single `commit_batch` call.
- In normal mode all canister calls use `direct: true`. In proxy mode (when a `proxy_canister_id` is provided by the host) the plugin first ensures the signing identity has `Commit` permission, routing a `grant_permission` call through the proxy (which is the canister's controller) if needed, then proceeds with direct calls.

The plugin calls `api_version` first and aborts if the canister advertises anything below 2.

## Redirects

The plugin reads a Netlify-style `_redirects` file at the root of the input directory (`dirs:` must list exactly one). The file itself is **not** uploaded as an asset — it's consumed by the plugin and lowered into canister-side rules. Each non-empty, non-comment line:

```
<from>  <to>  <status>
```

- `<from>` — absolute path. A trailing `/*` makes the rule match every URL whose path starts with the prefix (subtree). Anywhere else, `*` is an error.
- `<to>` — absolute path for `200` rewrites and `4xx` custom error pages. For `3xx` rules it may also be a fully-qualified URL (sent in the `Location` header).
- `<status>` — required integer, one of `{200, 301, 302, 307, 308, 404, 410}`. Unlike Netlify, there is no default; the explicit number keeps the intent (rewrite vs. redirect vs. error) unambiguous.
- Lines starting with `#` and blank lines are ignored. Inline `# comments` at the end of a rule line are stripped before parsing.

### Examples

```text
# 3xx — issue a Location-header redirect
/old-page        /new-page              301
/external        https://example.com/   302

# 200 — rewrite: serve the target asset's body at the source URL
/about           /about.html            200
/blog/*          /blog/index.html       200

# 4xx — custom error page (serves the target asset's body with the override status)
/missing         /404.html              404
/gone            /tombstone.html        410
```

A real asset at the rule's `from` path always wins — a file at `/about.html` is served at `/about.html` regardless of any rule. For 200 rewrites and 4xx error pages, the target asset's existing `Content-Type` and certified headers are inherited verbatim; the rule itself can't override them.

Rule order is significant: the plugin sends rules in declaration order, and the canister returns the first match. Replacing the file is a full replace-all operation — if you remove `_redirects` between deploys, the plugin emits an empty `SetRedirectRules` op so the canister clears its ruleset.

### Default HTML handling (auto-synthesised)

Ahead of the user's `_redirects`, the plugin auto-synthesises Cloudflare's [`auto-trailing-slash`](https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/#automatic-trailing-slashes-default) rule set for every `.html` asset in the project. Synthesised rules are prepended **before** the user's rules, so the html-handling defaults claim the exact paths they cover (`/foo`, `/foo/`, `/foo/index`, `/foo/index.html`, `/bar/`, `/bar`, etc.) and user rules apply to whatever paths are left. The most common use of `_redirects` after this — a SPA-style `/* /404.html 404` catch-all — works as expected: it fires only for paths no HTML asset claims.

This ordering is also a correctness requirement: the IC HTTP gateway's response verifier rejects a wildcard expression path response (`["http_expr", "<*>"]`) when a potential exact expression path (`["http_expr", <segments>, "<$>"]`) exists in the certified tree. Putting synth first ensures the canister always returns the Exact-path response for paths the html-handling defaults certify, which keeps the verifier happy. A user rule placed at the same `from` as a synthesised rule (e.g. `/foo /foo.html 200` when `/foo.html` already exists) is therefore dead — the synth rule wins. To override html-handling for a particular page, remove its `.html` source and serve it under a non-HTML key.

Given two assets `/foo.html` and `/bar/index.html`, the synthesised rules behave per Cloudflare's table:

| Request           | Effective response                           |
|-------------------|----------------------------------------------|
| `/foo`            | `200`, body of `/foo.html`                   |
| `/foo.html`       | `200`, body of `/foo.html` (see note)        |
| `/foo/`           | `307` → `/foo`                               |
| `/foo/index`      | `307` → `/foo`                               |
| `/foo/index.html` | `307` → `/foo`                               |
| `/bar/`           | `200`, body of `/bar/index.html`             |
| `/bar`            | `307` → `/bar/`                              |
| `/bar.html`       | `307` → `/bar` (client chains to `/bar/`)    |
| `/bar/index`      | `307` → `/bar` (client chains to `/bar/`)    |
| `/bar/index.html` | `200`, body of `/bar/index.html` (see note)  |

**Note on the two inert rows.** Cloudflare emits `307` for both `/foo.html → /foo` and `/bar/index.html → /bar/` (URL canonicalisation). The asset canister matches direct asset lookups before rules, so the asset at those keys wins and the synthesised 307 is shadowed. Requests to the literal `.html` URL still 200-serve the asset rather than redirecting. The synthesised rules are kept in the rule list so the table activates automatically if that precedence ever changes; users who care about strict canonicalisation can omit the `.html` source by other means (e.g. excluding it from the input directory).

### Migration from built-in aliasing

Earlier versions of this canister implicitly served `/foo.html` at `/foo` and `/foo/index.html` at both `/foo/` and `/foo`. Equivalent routing is now produced by auto-synthesis (above) for every `.html` asset, so most projects need no migration — the `_redirects` file is optional.

The one pre-existing pattern that is **not** covered by auto-synthesis is the SPA fallback (subtree → single HTML), since it requires a wildcard match across paths that don't correspond to an asset. Declare it explicitly:

```text
# SPA fallback (formerly served implicitly when no other asset matched)
/*               /index.html            200
```

The canister's built-in aliasing (and the `is_aliased` field on `set_asset_properties`) have been retired in favour of `_redirects` + plugin-side synthesis. The plugin no longer reads any project-side config file — only `_redirects` at the root of the input directory is consulted. The canister will drop the `is_aliased` field in a follow-up cleanup.

### Unsupported syntax

- `:splat` and `:placeholder` substitution in `<to>` — deferred (see the design plan's tier-3 follow-up).
- Netlify's `!` force suffix on status codes — files always win over rules at the same path; remove the conflicting asset instead.
- Country/role conditions and query-string matching — out of scope.
- Inline headers as a fourth field — headers are configured in a separate `_headers` file (see "Headers" below).

Parse errors abort the sync with the offending file path and 1-based line number, before any canister call is issued.

## Headers

The plugin reads a Netlify-style `_headers` file at the root of the input directory (`dirs:` must list exactly one). The file itself is **not** uploaded as an asset — it's consumed by the plugin and lowered into per-asset header lists. Each non-indented `<pattern>` line opens a block; subsequent indented lines (1+ spaces or tabs) are `Header-Name: value` entries belonging to the block. Blank lines close the block:

```text
/_astro/*
  Cache-Control: public, max-age=31536000, immutable
  X-Content-Type-Options: nosniff

/*
  X-Frame-Options: DENY
  X-Robots-Tag: noindex

/api
  Cache-Control: no-store
```

- `<pattern>` — absolute path. A trailing `/*` makes it a subtree match (`/*` alone matches every key). Anywhere else, `*` is an error.
- Header lines must follow a `<pattern>` block; an indented line at the top of the file or after a blank-line boundary is an error.
- Lines starting with `#` and blank lines are ignored. Inline `# comments` at the end of a line are stripped before parsing.

### Precedence

When multiple rules match the same key, **all** matching rules apply — there is no "more specific overrides" rule, and exact vs subtree patterns are not ranked. Same-name values across matching rules are concatenated with `, ` per [RFC 7230 §3.2.2](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.2):

```text
/*
  X-Robots-Tag: noindex

/admin/*
  X-Robots-Tag: nofollow
```

`/admin/page` sees `X-Robots-Tag: noindex, nofollow`. Semantically conflicting concatenations (`Cache-Control: public, no-store`) are the user's responsibility to avoid.

`Set-Cookie` is the one exception per [RFC 6265 §3](https://datatracker.ietf.org/doc/html/rfc6265#section-3) — multiple `Set-Cookie` lines, whether from a single rule or across rules, stay as separate header entries instead of being comma-folded.

The plugin stable-sorts the resolved list by lowercased header name before sending so wire order is a deterministic function of header content. `Set-Cookie` entries get grouped together but preserve declaration order within the group ([RFC 6265 §5.3](https://datatracker.ietf.org/doc/html/rfc6265#section-5.3) makes the *last* same-name cookie win, so the group order is load-bearing).

### What gets touched

- **New assets**: the resolved header list is passed in `CreateAssetArguments.headers`.
- **Existing assets**: drift is detected byte-for-byte against canister-stored headers; mismatches emit a `SetAssetProperties` op with the new list. A `_headers`-only edit propagates without re-uploading content.
- **3xx redirects** (rules in `_redirects` with status 301/302/307/308) synthesize their own response, so they don't inherit asset headers. The plugin populates `RedirectRule.headers` for these from any `_headers` rule whose pattern matches the redirect's `from`. 200 / 4xx rules borrow headers from the target asset, so no plumbing is needed there.

### `Content-Type` overrides

`Content-Type` is recognised inside a `_headers` block, but it routes to the asset's stored media type instead of the appended response headers. This is the only way to override the `mime_guess::from_path` default (or to add a `charset` parameter) — the canister always derives a single, certified `Content-Type` for every asset, and an appended header would produce a duplicate on the wire.

```text
/*.md
  Content-Type: text/markdown; charset=utf-8
  Cache-Control: public, max-age=300
```

The plugin extracts `Content-Type` and feeds it into `CreateAssetArguments.content_type`; other headers in the block continue to flow through `headers` as usual. `Content-Type` is single-valued, so when multiple blocks match the same asset the first matching `Content-Type` wins (other matching rules still contribute their non-`Content-Type` headers). Editing a `Content-Type` and redeploying triggers delete-then-recreate on the canister to keep the certified type in sync.

Validation:

- The value must parse as a MIME type via the `mime` crate.
- A duplicate `Content-Type:` line within the same block is rejected.
- Empty value is rejected.

### Validation and unsupported syntax

Header names and values are validated via the `http` crate's `HeaderName` / `HeaderValue` (rejects CR/LF, so no header injection). Rejected with a 1-based line number:

- Mid-path wildcards in `<pattern>` (e.g. `/foo/*/bar`) — not supported.
- `:splat` / `:placeholder` substitution in header values — deferred.
- Patterns like `/*.html` or `/blog/:slug` — deferred (see the design plan's tier-3 follow-up).
- Missing colon, blank header name, or value containing CR/LF.
- A `<pattern>` block with no header lines under it (likely a typo).

Parsing aborts at the first bad line so users fix issues one at a time.

## TODO

- [x] **Asset properties update** — emit `SetAssetProperties` ops for assets whose canister-side properties drifted from the plugin's defaults. `get_asset_properties` is called after `list_assets` to collect the current `AssetProperties` for every canister asset, and `update_properties` resets any non-default `max_age`, `headers`, or `allow_raw_access`. (`is_aliased` is no longer carried; the canister will drop it in a follow-up cleanup PR.)

- [x] **Header representation: `Map` → `Vec<(name, value)>`** — `Option<BTreeMap<String, String>>` / `Option<HashMap<String, String>>` were replaced with a list of pairs across `ic-certified-assets` (`Asset`, `AssetProperties`, `CreateAssetArguments`, `SetAssetPropertiesArguments`, `build_headers`, `evidence::hash_headers`) and `assets-sync` (`canister::AssetProperties`, `update_properties`). Candid wire type `vec record { text; text }` is already a list, so this was a Rust-only change. Lets users carry multiple `Set-Cookie` values. Evidence hashing stable-sorts by lowercased name only so same-name groups preserve declaration order.

- [ ] **`commit_batch` chunking** — split operations across multiple `commit_batch` calls to stay within the ~2 MB ICP ingress message limit, matching `ic-asset` behaviour.
  - Replace the single `commit_batch` call in `sync()` with a `commit_in_stages` helper modelled on `ic-asset/src/sync.rs::commit_in_stages`.
  - Implement `create_commit_batches(ops)` that splits the operation list using two limits: 500 ops per batch (cert-tree work) and 1.5 MB of accumulated header data per batch (header maps dominate ingress size). Header size is the sum of key+value lengths across all `CreateAsset` and `SetAssetProperties` operations in the batch.
  - Each intermediate batch is committed with `batch_id = 0`; after all operation batches are committed, a final call with the real `batch_id` and an empty operations list closes the batch.

- [ ] **Multi-chunk upload via `create_chunks`** — send multiple small chunks per canister call instead of one, reducing round-trips for projects with many small files.
  - Add a `create_chunks` wrapper in `canister.rs` that calls the canister's `create_chunks` method (takes `batch_id` and `Vec<Vec<u8>>`, returns `Vec<Nat>` chunk IDs).
  - In `sync()`, replace the single-chunk loop with a batching uploader: accumulate chunks up to `MAX_CHUNK_SIZE` (1.9 MB) of total payload per call, then flush via `create_chunks`. The last chunk of each file can be sent inline as `last_chunk` in `SetAssetContentArguments` rather than as a separate chunk ID, saving one round-trip per file.
