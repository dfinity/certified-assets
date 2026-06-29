# Verifying contents

Certification proves that what the canister **serves** matches what it has
**committed to** — but who decides what it committed to? On its own, an asset
canister could commit to (and certify) anything. The **state hash** closes that
gap: it lets a third party verify the canister serves *exactly a known frontend
build* — the reproducible-build story, but for frontend assets instead of wasm.

The trust root is the **source code**, never the operator's word. A verifier
reproduces the build from public source, computes the hash locally, and compares
it to the canister's. An operator who just hands you a number proves nothing —
that number is only a deploy self-consistency check.

## What the hash covers

`state_hash` is a 32-byte SHA-256 over the canister's **served-content model**:

- every asset, by key → its `content_type`, response headers, and per-encoding
  content hashes (the whole-encoding SHA-256, length, chunk count, and per-chunk
  hashes for large multi-chunk assets);
- the redirect rules, in match order.

These are exactly the hashes the canister already stores and the HTTP gateway
certifies end-to-end. To match the hash while serving forged content, an attacker
would need the certified hashes to equal the real build's — and the gateway forces
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
   # 8150a65e854b9bbb…  (64 hex chars)
   ```

3. **Read the canister's hash.** `state_hash` is a public, unguarded method — and
   an *update* call, so the reply is consensus-backed and trustworthy:

   ```sh
   dfx canister call <canister-id> state_hash --network ic
   # (blob "\81\50\a6\5e…")
   ```

4. **Compare.** If the two hashes are equal, the canister serves exactly the build
   you reproduced from source. If they differ, the served content, headers, or
   redirects do not match that source.

The deploy also prints the hash in the `icp deploy` / sync result (`state hash
<hex>`), so the operator can confirm their own deploy is self-consistent — but
again, that is not third-party verification.

## The frozen contract

The hash is bound to how content is prepared, so a verifier must use a
`state-hash` build **matching the version that deployed the canister**. The
parameters baked into the hash:

- **Compression** — gzip at `flate2`'s default level; brotli at quality 11,
  window 22. Compressed encodings are not reproducible by an independent
  reimplementation, so the verifier reuses this project's preparation code.
- **Chunk boundary** — `MAX_CHUNK_SIZE` (1,900,000 bytes). Per-chunk hashes for
  large assets depend on where chunks split.
- **Byte format** — a versioned, length-prefixed, domain-separated SHA-256
  stream (see the `state-hash` crate). Independent of map/header iteration order,
  but bound to this layout version.

Because there are no production instances and no stored hashes to preserve, this
contract can change between releases; when it does, the format version is bumped
and every previously-computed hash is expected to change.

## Relationship to certification

Certification and the state hash are complementary:

- **Certification** (always on) proves *each response* matches what the canister
  committed to, verified by the gateway on every request.
- **The state hash** proves *what the canister committed to* matches a known
  source build, verified by you, once, out of band.

Together they chain trust from your source code all the way to the bytes in a
visitor's browser.
