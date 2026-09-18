---
title: "Verifying contents"
description: "Prove a canister serves exactly a known build by reproducing its state hash from source"
sidebar:
  order: 7
---

Certification proves that what the canister **serves** matches what it has
**committed to**. But who decides what it committed to? On its own, an asset
canister could commit to (and certify) anything. The **state hash** closes that
gap: it lets a third party verify the canister serves *exactly a known frontend
build* (the reproducible-build story, but for frontend assets instead of wasm).

The trust root is the **source code**, never the operator's word. A verifier
reproduces the build from public source, computes the hash locally, and compares
it to the canister's. An operator who just hands you a number proves nothing;
that number is only a deploy self-consistency check.

## What the hash covers

`state_hash` is a 32-byte SHA-256 over the canister's **served-content model**:

- every asset, by key → its `content_type`, response headers, and per-encoding
  content hashes (the whole-encoding SHA-256, length, chunk count, and per-chunk
  hashes for large multi-chunk assets);
- the redirect rules, in match order.

These are exactly the hashes the canister already stores and certifies. To match the
hash while serving forged content, an attacker would need the certified hashes to
equal the real build's, and a verifying gateway forces served bytes to those hashes.
So a matching hash means matching served content, for any visitor whose gateway checks
the proof (see
[who verifies the certificate](how-it-works.md#who-verifies-the-certificate)).

**Not covered:** asset content bytes are folded in as their certified hashes, never
re-hashed. Two things a visitor receives are outside the model:

- **The `ic_env` cookie.** Every `text/html` response carries a certified
  `set-cookie: ic_env` holding the canister's `PUBLIC_*` environment variables and
  the IC root key. It is added when the response is certified rather than stored
  with the asset, so it is not part of the hash, and `refresh_env` republishes it
  without moving the hash. A frontend that reads a backend's canister id from it is
  configured by state the hash does not cover: a controller can point it at a
  different canister while the build stays byte-identical.
- **Access protection.** Who may *sync* (controllers, authorized principals) has no
  bearing on what is served. The access-protection gate does: with it on, an
  unauthenticated request for your content gets a certified `307` to the login
  page (HTML) or a `401` (anything else) instead of the asset, and `cache-control`
  is replaced with `no-store`. A matching hash says the canister holds your build,
  not that a visitor can reach it.

## How to verify

You need the canister's id, its public source (the repo and the build steps that
produce the served directory), and a Rust toolchain to build the verifier.

1. **Reproduce the build.** Check out the source at the version whose deployment
   you are checking, and run the build to produce the site directory (`dist/`),
   exactly as the deploy does.

2. **Build the verifier at the canister's release.** Ask the canister which
   release it runs, and build `state-hash` from that tag. It is not published as a
   binary or to crates.io, which is the point: the verifier should come from the
   same source you are trusting, not from someone's download.

   ```sh
   icp canister call <canister-id> version '()' -n ic --query
   # (record { major = 0 : nat32; minor = 3 : nat32; patch = 3 : nat32 })

   cargo install --git https://github.com/dfinity/certified-assets \
     --tag v0.3.3 --locked state-hash-cli
   ```

   The release has to match the one that deployed the canister, for the reasons in
   [the frozen contract](#the-frozen-contract). `--locked` is part of that match,
   not a precaution: the committed `Cargo.lock` is what pins the compressor builds
   whose output bytes the hash covers, and `cargo install` re-resolves dependencies
   without it. A verifier on the right tag with a newer `brotli` patch computes a
   different hash.

3. **Compute the hash locally** with the `state-hash` tool, pointed at that
   directory (include any `_headers` / `_redirects` files, as deployed):

   ```sh
   state-hash ./dist
   # 8150a65e854b9bbb…  (64 hex chars, and nothing else)
   ```

   This is the hash of the preparation `icp deploy` produces. A platform building
   on these crates supplies its own compressors (see
   [how it works](how-it-works.md)), perhaps a lower Brotli quality to make
   short-lived preview deploys cheaper, or none at all, and its canisters won't
   match this value. Verifying those is between that platform and its users; the
   tool deliberately doesn't guess at which settings someone else might have used.

4. **Read the canister's hash.** `state_hash` is a public, unguarded method, and
   an *update* call, so the reply is consensus-backed and trustworthy:

   ```sh
   icp canister call <canister-id> state_hash '()' -n ic
   # (blob "\81\50\a6\5e…")
   ```

   Pass the argument explicitly: with none, `icp canister call` opens an
   interactive prompt instead of sending an empty one. Target the canister by
   **principal** with `-n <network>`; `-e <environment>` resolves a canister *name*
   out of a local project, which a third-party verifier does not have.

   To compare the two values directly, take the reply as raw bytes; the hash is
   its last 32:

   ```sh
   icp canister call <canister-id> state_hash '()' -n ic -o hex | tail -c 65
   # 8150a65e854b9bbb…
   ```

   32 zero bytes is not a hash: it means the canister has none to report, either
   because it has never completed a sync or because one is in progress right
   now. A sync drops the cached hash as soon as it starts, since from that point
   the canister may serve content the old hash no longer describes, and only a
   sync that runs to completion caches a new one. Read it again once the deploy
   finishes. A canister that keeps reporting zeros was left mid-sync, and there
   is nothing to verify it against.

5. **Compare.** If the canister's hash equals the one you computed, it serves
   exactly the build you reproduced from source. If it doesn't, either the served
   content, headers, or redirects do not match that source, or it was deployed
   with compressors this tool doesn't know about (see step 3).

   A match needs no further checking of *how* the canister was synced. The hash
   covers every stored encoding by its own hash, so matching it means the canister
   holds exactly the bytes this tool prepared, which is what "prepared with the
   standard compressors" means. There is no separate step, and nothing to take on
   the operator's word.

The deploy also prints a hash in the `icp deploy` / sync result (`canister reports
state hash <hex>`). That value comes back from the canister on the call that
finalizes the sync, so it tells the operator what the canister now holds; it is
*not* a locally-derived cross-check, and not third-party verification. Only the
`state-hash` tool above, run against source you reproduced, is that.

## The frozen contract

The hash is bound to how content is prepared, so a verifier must use a
`state-hash` build **matching the version that deployed the canister**. The
parameters baked into the hash:

- **Compression.** Gzip at `flate2`'s default level; brotli at quality 11,
  window 22, **as produced by the exact compressor builds this version links**.
  RFC 7932 and RFC 1951 specify *decoders*, so those settings don't determine the
  bytes: a different encoder, or a different version of the same one, may emit
  a different valid stream. That is why the verifier reuses this project's
  preparation code rather than reimplementing it, and why a matching version
  matters more here than for anything else in this list. These are the settings
  `sync-plugin` injects, so they are the settings behind every `icp deploy`; a
  program embedding `sync-agent` supplies its own compressors and owns its own
  verification story.
- **Chunk boundary.** `MAX_CHUNK_SIZE` (1,900,000 bytes). Per-chunk hashes for
  large assets depend on where chunks split.
- **Byte format.** A versioned, length-prefixed, domain-separated SHA-256
  stream (see the `state-hash` crate). Independent of map/header iteration order,
  but bound to this layout version.
- **Synthesized content.** The preparation adds what a deploy adds: the clean-URL
  and trailing-slash rules derived from the asset keys, and a `/*` catch-all at
  status `404`, pointing at your own root `404.html` if the directory has one and
  otherwise at the built-in [`404` page](routing.md#not-found-handling), which it
  then adds as well. A root `/*` rule of your own (a single-page app's, say)
  replaces both. All of it comes from the tool rather than from your directory,
  which is why a directory with no `404.html` still matches: the verifier adds, or
  withholds, exactly what the deploy did. It is pinned to the tool's release like
  everything above.

The contract can change between releases; when it does, the format version is
bumped and every previously-computed hash is expected to change. Within a release
series it is frozen: a patch upgrade preserves stored content, so a build that
changed these parameters would silently invalidate every deployed canister's hash.

## Relationship to certification

Certification and the state hash are complementary:

- **Certification** (always on) proves *each response* matches what the canister
  committed to, checked by the visitor's gateway on every request.
- **The state hash** proves *what the canister committed to* matches a known
  source build, verified by you, once, out of band.

Together they chain trust from your source code all the way to the bytes in a
visitor's browser. The last link in that chain is the visitor's gateway: over a
[`raw` URL](how-it-works.md#the-raw-hosts-skip-verification) nobody checks the proof,
so the state hash still says what the canister committed to but no longer guarantees
that a visitor received it.
