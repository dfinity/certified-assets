# Overview

**Certified Assets** deploys a static site — a built frontend, docs, or any folder of
files — to a canister on the [Internet Computer](https://internetcomputer.org) that
serves it over HTTP with **response certification**. You point it at your build
directory; it uploads your files, certifies them, and serves them.

Certification is what makes this different from a plain web host: every response the
canister returns carries a cryptographic proof, and the IC's HTTP gateway verifies
that proof before handing the response to the browser. Visitors get content the
canister has provably committed to — no boundary node or gateway can tamper with it
in transit.

You configure it through [`icp-cli`](https://github.com/dfinity/icp-cli) using a
**recipe**, which bundles a matched pair of the canister and its sync plugin. Most
sites need nothing more than this page.

## Get started

### 1. Reference the recipe in your `icp.yaml`

```yaml
canisters:
  - name: frontend
    recipe:
      type: "@dfinity/certified-assets@<version>"
      configuration:
        dir: dist          # the directory of files to serve
```

Replace `<version>` with a released version (e.g. `v1.0.0`); see the
[available versions](https://github.com/dfinity/icp-cli-recipes/releases?q=certified-assets&expanded=true).
Pick the version here — because the recipe pins a matched canister + plugin pair,
there is no separate canister version to choose.

### 2. Deploy

```sh
icp deploy
```

This installs the canister, then runs the sync plugin to upload and certify every
file in `dir`. Re-running `icp deploy` syncs again: the plugin diffs your directory
against the canister and uploads only what changed.

That's it — your site is live and certified.

## Configuration

The recipe takes three configuration fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dir` | string | **Yes** | The single directory of built files to serve. The canister owns its whole URL space, so this is one directory, not a list. |
| `build` | array | No | Shell commands run *before* sync to produce `dir` (e.g. `npm run build`). |
| `metadata` | array | No | `name`/`value` pairs baked into the canister wasm via `ic-wasm`. |

A fuller example with a build step and metadata:

```yaml
canisters:
  - name: frontend
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

> `metadata` is the only field that needs `ic-wasm`. It ships with `icp-cli`, so if
> you installed the CLI you already have it.

## What you get automatically

You don't have to configure any of these — they're on by default:

- **Response certification** — every response is certified and gateway-verified.
- **[Clean URLs](routing.md)** — `/about` serves `/about.html`, `/blog/` serves
  `/blog/index.html`, with redirects that keep one canonical URL per page.
- **[Compression](how-it-works.md#content-encoding)** — text, JS, JSON, SVG, and
  wasm are stored gzip- and Brotli-compressed and negotiated per request via
  `Accept-Encoding`.
- **[ETag / `304 Not Modified`](how-it-works.md#etag-and-conditional-requests)** —
  each asset gets a content-hash ETag, so unchanged files aren't re-downloaded.
- **[A default `404` page](routing.md#not-found-handling)** — a built-in, certified
  fallback you can replace by adding your own `/404.html`.

## Customize further

When you need finer control, each topic has its own page:

- **[Routing & clean URLs](routing.md)** — how request paths map to files, trailing
  slashes, and 404 handling.
- **[Redirects & rewrites](redirects.md)** — the `_redirects` file: send `/old` to
  `/new`, serve one file at another path, set custom error pages.
- **[Custom headers](headers.md)** — the `_headers` file: cache-control, a Content
  Security Policy, and other security headers.
- **[Site files & conventions](site-files.md)** — what gets uploaded, the special
  `_redirects`/`_headers` files, excluded files, and custom domains.
- **[Access protection](access-protection.md)** — put a login screen in front of a
  private/preview app with revocable, expiring access tokens.
- **[Verifying contents](verifying-contents.md)** — the canister's state hash:
  prove to a third party that it serves exactly a known build, from source.

Curious how it works underneath? See [Under the hood](how-it-works.md).
