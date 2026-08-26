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

These are exactly the hashes the canister already stores and the HTTP gateway
certifies end-to-end. To match the hash while serving forged content, an attacker
would need the certified hashes to equal the real build's, and the gateway forces
served bytes to those hashes. So a matching hash means matching served content.

**Not covered:** raw content bytes are folded in as their certified hashes, never
re-hashed; and permissions / authorization state are out of scope (they don't
affect *what* is served, only *who may sync*).

## How to verify

You need the canister's id and its public source (the repo and the build steps
that produce the served directory).

1. **Reproduce the build.** Check out the source at the deployed version and run
   the build to produce the site directory (`dist/`), exactly as the deploy does.

2. **Compute the hash locally** with the `state-hash` tool, pointed at that
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

3. **Read the canister's hash.** `state_hash` is a public, unguarded method, and
   an *update* call, so the reply is consensus-backed and trustworthy:

   ```sh
   dfx canister call <canister-id> state_hash --network ic
   # (blob "\81\50\a6\5e…")
   ```

4. **Compare.** If the canister's hash equals the one you computed, it serves
   exactly the build you reproduced from source. If it doesn't, either the served
   content, headers, or redirects do not match that source, or it was deployed
   with compressors this tool doesn't know about (see step 2).

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

The contract can change between releases; when it does, the format version is
bumped and every previously-computed hash is expected to change. Within a release
series it is frozen: a patch upgrade preserves stored content, so a build that
changed these parameters would silently invalidate every deployed canister's hash.

## Relationship to certification

Certification and the state hash are complementary:

- **Certification** (always on) proves *each response* matches what the canister
  committed to, verified by the gateway on every request.
- **The state hash** proves *what the canister committed to* matches a known
  source build, verified by you, once, out of band.

Together they chain trust from your source code all the way to the bytes in a
visitor's browser.
