---
title: "Under the hood"
description: "How the canister certifies responses, serves large assets, negotiates encodings, and persists state across upgrades"
sidebar:
  order: 8
---

You don't need any of this to use certified-assets; the [overview](overview.md) is
enough to ship a site. But the pieces below explain *why* it behaves the way it does,
and they're the features that set it apart from an ordinary static host. (For the
code-level layout, contributors should read [`ARCHITECTURE.md`](https://github.com/dfinity/certified-assets/blob/main/ARCHITECTURE.md).)

## Response certification

This is the headline feature. When the sync plugin uploads your files, it also builds
a **certification tree**, a hash structure the canister commits to as part of its
public state. For every path, the canister can produce a proof that "this exact
response is what I committed to serve here."

Serving happens in a **query**, which is answered by a single replica rather than by
consensus. Certification is what makes that answer trustworthy: the proof chains the
response back to state the canister committed *through* consensus, so no single replica
can invent a response that verifies.

The canister certifies **every** response it serves, and there is no way to turn that
off. It accepts only version 2 of the certification protocol, and everything it returns
carries a full certification expression; it never uses the gateway protocol's
`no_certification` escape hatch. Whatever you request, the proof comes with it.

This is also why [redirects](redirects.md#what-isnt-supported-dynamic-rules) and
[headers](headers.md#reserved-headers) are constrained to what can be enumerated and
certified ahead of time.

### Who verifies the certificate

A proof only helps if somebody checks it, and in a browser that somebody is the
**[HTTP gateway](https://docs.internetcomputer.org/references/http-gateway-protocol-spec/)**.
Three parties are involved:

- The **canister** certifies every response, as above.
- The **gateway** calls the canister, verifies the certificate, and forwards the
  response. Its promise to the client is "I checked this proof against the canister's
  certified state."
- The **client** picks a gateway by pointing at its URL. A browser can't verify an IC
  certificate on its own, so it delegates that check. **Choosing the gateway is the
  whole trust decision.**

Go through a gateway that verifies, and nothing between it and the canister can alter,
inject, or swap your content without the proof failing. A plain web host asks you to
trust the server; here the response is cryptographically tied to the canister's
certified state.

### The `raw` hosts skip verification

Alongside their verifying hostname, gateways have long answered on a second one that
forwards the response **without** checking the proof: `<canister-id>.raw.icp0.io`
serves the same site as `<canister-id>.icp0.io`, unverified.

That dates from certification v1, when a canister had no way to tell the gateway "this
response is dynamic, don't try to verify it." A non-verifying hostname was the only
escape hatch available to canisters serving content they couldn't certify ahead of
time. Version 2 replaced it with something better: a canister now says so per response,
in band, through the `no_certification` expression mentioned above. The `raw` hostnames
outlived the problem they solved, and survive mainly as a debugging aid.

This canister never needed the escape hatch. It is v2-only and certifies everything, so
it behaves identically on both hostnames: it attaches the certificate either way, and on
`raw` the gateway simply discards it. Nothing about the canister's guarantee weakens
there, but the client has chosen a party that doesn't check, so it gets no better
assurance than from an ordinary web host.

**The canister can't reliably refuse `raw` requests.** Its only clue is the `Host`
header, which the client supplies and nothing authenticates. Matching it against `raw`
would hardcode a hostname convention that no protocol defines: which hostnames verify
and which don't is a property of how a particular gateway is deployed, not something
the gateway protocol states. With gateways independently operated, self-hosted, and
behind custom domains, such a check is wrong in both directions, since a non-verifying
gateway can answer on any hostname and a verifying one can be named anything at all.

So the guidance is client-side: **link to a gateway that verifies, and treat a `raw`
URL as a debugging tool rather than a way to serve or visit a site.** A `raw` link is
copy-pasteable and gets shared, and nothing in the response tells a visitor it arrived
unverified.

If you'd rather not trust a gateway at all, check the proof yourself: call the canister
through an
[agent](https://docs.internetcomputer.org/guides/canister-calls/calling-from-clients/)
and verify the certificate in your own code, or use the
[state hash](verifying-contents.md), whose `state_hash` call is an update and therefore
consensus-backed.

## Serving large assets

A single canister response has a bounded message size, so a large file can't be
returned in one shot. The canister splits it into chunks and serves each chunk as a
certified **`206 Partial Content`** response carrying a `Content-Range`. For an
ordinary request the **[HTTP gateway](https://docs.internetcomputer.org/references/http-gateway-protocol-spec/)**
fetches the chunks and reassembles them into the full `200` the browser sees; a client
that sends a `Range` header gets back the chunk covering the bytes it asked for. Either
way every chunk is certified, so a large file is exactly as tamper-proof as a small
one, and it's all transparent to the client.

## The sync plugin and its sandbox

The thing that uploads your files is a WebAssembly **sync plugin** that `icp-cli`
loads and runs in a sandboxed [WASI](https://wasi.dev) runtime. The plugin can only
touch the directories the CLI explicitly grants it (your asset directory) and has
no ambient access to the rest of your machine. The canister and the plugin are shipped
as a version-locked pair (the [recipe](overview.md) pins both), so the upload format
and the serving logic always agree.

## Content encoding

Text-like assets (HTML, CSS, JavaScript, JSON, SVG, WebAssembly, and similar) are
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
still detected for every asset; those don't depend on content.)

Reusing what's already stored assumes the compressors still behave the same way, and
that isn't something a version number can promise: compressed output isn't part of
a library's published interface. So each sync also records a small fingerprint of how
its compressors actually behaved. If a later deploy's fingerprint differs (a
dependency update, a different backend, or a deploy that simply used different
compressors), it stops trusting the shortcut and re-prepares every asset, restoring
the canister to exactly what the new build produces.

Every `icp deploy` uses the same compressors: gzip at its default level and Brotli at
quality 11, the settings the `state-hash` verifier reproduces. A platform building on
these crates supplies its own: it can tune Brotli down for short-lived preview
canisters, drop gzip, or store nothing but the uncompressed copy for deploys nobody
browses. That is a trade only the deploying platform can make: it keeps the saved
seconds while the larger transfers go to whoever visits the site. Changing them needs
no cleanup (the fingerprint above catches it, and the next sync re-prepares the
canister to match), but a canister prepared with anything other than the standard
settings won't match what `state-hash` computes.

## ETag and conditional requests

Every asset is served with an `ETag`, a strong validator derived from the SHA-256
hash of its content. On a repeat visit the browser sends that value back in an
`If-None-Match` header; if it still matches, the canister returns a certified
`304 Not Modified` with an empty body instead of resending the file. Both the `200`
and the `304` are certified, so conditional requests save bandwidth without weakening
the integrity guarantee.

## State that survives upgrades

The canister keeps your assets and rules in **stable memory** using
[`ic-stable-structures`](https://crates.io/crates/ic-stable-structures), so its state
lives directly in the structure the IC preserves across canister upgrades. There is
no serialize-everything-on-upgrade / deserialize-on-boot step that could fail or grow
unbounded as a site gets large.

This ties into how releases are versioned: a **patch** release can be applied as an
in-place upgrade that keeps all state, while a **breaking** release reinstalls and a
fresh sync re-uploads everything. See
[Releasing](https://github.com/dfinity/certified-assets/blob/main/README.md#releasing) for the details.
