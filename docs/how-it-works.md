# Under the hood

You don't need any of this to use certified-assets — the [overview](overview.md) is
enough to ship a site. But the pieces below explain *why* it behaves the way it does,
and they're the features that set it apart from an ordinary static host. (For the
code-level layout, contributors should read [`ARCHITECTURE.md`](../ARCHITECTURE.md).)

## Response certification

This is the headline feature. When the sync plugin uploads your files, it also builds
a **certification tree** — a hash structure the canister commits to as part of its
public state. For every path, the canister can produce a proof that "this exact
response is what I committed to serve here."

When a browser requests your site, the request goes through the Internet Computer's
**[HTTP gateway](https://docs.internetcomputer.org/references/http-gateway-protocol-spec/)**,
which calls the canister, receives the response *and its certificate*, and verifies
the certificate before passing anything to the browser. A boundary node or gateway
can't alter, inject, or swap your content without the proof failing. A plain web host
asks you to trust the server; here the response is cryptographically tied to the
canister's certified state.

This is also why [redirects](redirects.md#what-isnt-supported-dynamic-rules) and
[headers](headers.md#reserved-headers) are constrained to what can be enumerated and
certified ahead of time.

## Serving large assets

A single canister response has a bounded message size, so a large file can't be
returned in one shot. The canister splits it into chunks and serves each chunk as a
certified **`206 Partial Content`** response carrying a `Content-Range`. For an
ordinary request the **[HTTP gateway](https://docs.internetcomputer.org/references/http-gateway-protocol-spec/)**
fetches the chunks and reassembles them into the full `200` the browser sees; a client
that sends a `Range` header gets back the chunk covering the bytes it asked for. Either
way every chunk is certified, so a large file is exactly as tamper-proof as a small one
— and it's all transparent to the client.

## The sync plugin and its sandbox

The thing that uploads your files is a WebAssembly **sync plugin** that `icp-cli`
loads and runs in a sandboxed [WASI](https://wasi.dev) runtime. The plugin can only
touch the directories the CLI explicitly grants it — your asset directory — and has
no ambient access to the rest of your machine. The canister and the plugin are shipped
as a version-locked pair (the [recipe](overview.md) pins both), so the upload format
and the serving logic always agree.

## Content encoding

Text-like assets — HTML, CSS, JavaScript, JSON, SVG, WebAssembly, and similar — are
stored in three forms: uncompressed (identity), gzip, and Brotli. A compressed copy is
only kept if it's actually smaller than the original. Already-compressed formats
(images, video, `woff2` fonts, archives) are stored as-is.

At request time the canister reads the browser's `Accept-Encoding` header and serves
the best encoding both sides support, setting `Content-Encoding` accordingly. You get
smaller transfers for free, with no build-step configuration.

Compressing is the slowest part of a deploy, so a sync does it only where it has to.
It first reads each file and hashes it uncompressed, then asks the canister what it
already holds; any asset whose uncompressed hash, content type and encoding set
already match is left alone, and only the rest are compressed and uploaded. Editing
one file in a large site therefore costs one file's worth of compression, and
re-deploying an unchanged site costs none at all. (Header and redirect changes are
still detected for every asset — those don't depend on content.)

Reusing what's already stored assumes the compressors still behave the same way, and
that isn't something a version number can promise — compressed output isn't part of
a library's published interface. So each sync also records a small fingerprint of how
its compressors actually behaved. If a later deploy's fingerprint differs — a
dependency update, a different backend, or a deploy that simply used different
compressors — it stops trusting the shortcut and re-prepares every asset, restoring
the canister to exactly what the new build produces.

Every `icp deploy` uses the same compressors: gzip at its default level and Brotli at
quality 11, the settings the `state-hash` verifier reproduces. A platform building on
these crates supplies its own — it can tune Brotli down for short-lived preview
canisters, drop gzip, or store nothing but the uncompressed copy for deploys nobody
browses. That is a trade only the deploying platform can make: it keeps the saved
seconds while the larger transfers go to whoever visits the site. Changing them needs
no cleanup — the fingerprint above catches it, and the next sync re-prepares the
canister to match — but a canister prepared with anything other than the standard
settings won't match what `state-hash` computes.

## ETag and conditional requests

Every asset is served with an `ETag` — a strong validator derived from the SHA-256
hash of its content. On a repeat visit the browser sends that value back in an
`If-None-Match` header; if it still matches, the canister returns a certified
`304 Not Modified` with an empty body instead of resending the file. Both the `200`
and the `304` are certified, so conditional requests save bandwidth without weakening
the integrity guarantee.

## State that survives upgrades

The canister keeps your assets and rules in **stable memory** using
[`ic-stable-structures`](https://crates.io/crates/ic-stable-structures), so its state
lives directly in the structure the IC preserves across canister upgrades — there's no
serialize-everything-on-upgrade / deserialize-on-boot step that could fail or grow
unbounded as a site gets large.

This ties into how releases are versioned: a **patch** release can be applied as an
in-place upgrade that keeps all state, while a **breaking** release reinstalls and a
fresh sync re-uploads everything. See [Releasing](../README.md#releasing) for the
details.
