# Stable-structures performance: validation plan & report

Status: **Phase 1 merged (#98) · Phase 2 done (heap A/B) · Risk A addressed (self-describing streaming token) · Risk B quantified & accepted · Serve/sync coefficient optimized (content blob arena, §9)** · Owner: Linwei · Last updated: 2026-06-23

## 1. What this is

In #86 we moved canister `State` from heap (main memory) into
`ic-stable-structures`. This removed the pre/post-upgrade serialize-everything
hooks (upgrade safety) and lifted the asset-capacity ceiling (heap is capped;
total asset size is no longer bounded by it).

The open question from the team: **did we pay for that with meaningfully worse
runtime performance?** Two concerns:

1. **Serving latency** (query calls) — serving an asset now reads stable memory
   via the system API instead of the heap.
2. **Sync cycles cost** (update calls) — committing assets now writes a
   `StableBTreeMap` instead of a heap map; more instructions ⇒ more cycles.

This doc records how we'll answer those with numbers (to convince ourselves and
reviewers), and doubles as the how-to-run-the-benchmarks guide once the harness
lands.

## 2. The reframe that makes this tractable: instructions, not latency

The heap→stable change affects **how many Wasm instructions execute per
message** — a deterministic quantity. It does **not** change network latency
(boundary nodes, HTTP gateway, consensus, client RTT). Those are identical
before and after and **cancel out of any comparison**.

Consequences:

- We do **not** need a real network — or mainnet — to evaluate this decision.
  Instruction count is the same on a laptop, a local replica, and mainnet.
- The right primary tool is an **instruction-counting microbenchmark**
  (`canbench`), not wall-clock timing on any network.
- "Local network can't reflect real latency" is true but irrelevant here: it's
  the wrong axis. Latency is unchanged by where bytes are stored.

(If we ever need *absolute* serving latency for a UX/SLA target, that's a
separate measurement — and it would read the same with heap or stable. Out of
scope for this decision; see §7.)

## 3. What actually changed (grounded in the code)

### Serving path (query) — delta is tiny

- Certification/witness work — the heaviest per-request CPU cost — is **still in
  heap** (`NestedTree`/`RbTree`, [certification.rs:306](crates/canister-core/src/certification.rs#L306))
  and **unchanged**. `witness_to_header()` traverses a heap tree
  ([state.rs:489](crates/canister-core/src/state.rs#L489)).
- SHA-256 is precomputed in metadata — **no per-request hashing**.
- The entire stable-introduced delta on a query is:
  - `metadata.get(path)` — log(n) BTree traversal + CBOR decode (small)
    ([state.rs:488](crates/canister-core/src/state.rs#L488))
  - first-chunk `content.get((content_id, 0))` — BTree traversal + `stable64_read`
    memcpy of up to `MAX_CHUNK_SIZE` = 1.9 MB
    ([state.rs:620](crates/canister-core/src/state.rs#L620))
- Each **streaming callback** does `metadata.get` **again** + one chunk read
  ([state.rs:747](crates/canister-core/src/state.rs#L747),
  [state.rs:764](crates/canister-core/src/state.rs#L764)). See Risk A in §6.

Expectation: a few million instructions worst case vs. a 5 B-instruction query
limit (<0.1%), dwarfed by network latency. Benchmarks should confirm this.

### Sync path (update) — delta is real but small

`complete_set_asset_content()` ([state.rs:281](crates/canister-core/src/state.rs#L281)):

- Stable writes: N `content.insert` of ≤1.9 MB chunks + 1 `metadata.insert` +
  2 counter-cell bumps.
- Dominated by costs that **did not change**: SHA-256 hashing (one chunk per
  message, [sync.rs:296](crates/canister-core/src/sync.rs#L296)) and heap
  recertification ([state.rs:324](crates/canister-core/src/state.rs#L324)), plus
  per-message base fee and ingress byte cost.

Expectation: stable-write overhead is a small slice of total sync cost.

## 4. Storage map (reference)

| Data | Type | MemoryId | Loc |
|------|------|----------|-----|
| Authorized set | `StableCell<AuthorizedSet>` | 0 | [state.rs:84](crates/canister-core/src/state.rs#L84) |
| Redirect rules | `StableCell<RedirectRules>` | 1 | [state.rs:87](crates/canister-core/src/state.rs#L87) |
| Session id counter | `StableCell<u64>` | 2 | [state.rs:89](crates/canister-core/src/state.rs#L89) |
| Content id counter | `StableCell<u64>` | 3 | [state.rs:91](crates/canister-core/src/state.rs#L91) |
| Asset metadata | `StableBTreeMap<AssetKey, AssetMeta>` | 4 | [state.rs:94](crates/canister-core/src/state.rs#L94) |
| Content chunks | `StableBTreeMap<ContentChunkKey, Vec<u8>>` | 5 | [state.rs:96](crates/canister-core/src/state.rs#L96) |
| **Cert tree** | `NestedTree` (RbTree) — **heap**, rebuilt on upgrade | — | [certification.rs:306](crates/canister-core/src/certification.rs#L306) |

## 5. Plan

### Phase 1 — `canbench` harness + benchmarks (primary)

Add [`canbench`](https://github.com/dfinity/canbench) to `canister-core`. It
measures instructions, heap, and stable-memory growth per benchmark fn, is
deterministic, runs headless (no replica), and tracks a committed baseline
(`canbench_results.yml`) so regressions show up as diffs in CI.

Benchmarks to write:

1. `serve_small_asset` — `http_request` for a ~10 KB single-chunk asset.
2. `serve_large_asset` — `http_request` + walk **all** streaming callbacks for a
   multi-MB asset (exercises Risk A: per-callback `metadata.get`).
3. `sync_commit` — a sync creating ~100 assets / many chunks; report
   instructions per `SetAssetContent`.
4. `post_upgrade_rebuild` at 1k / 10k / 100k assets — the cert-tree rebuild
   scaling curve (Risk B).

Implemented in [crates/canister-core/src/benches.rs](crates/canister-core/src/benches.rs),
driven by [crates/canister-core/canbench.yml](crates/canister-core/canbench.yml).
Run from `crates/canister-core/`: `canbench` (add `--persist` to update the
committed baseline `canbench_results.yml`). The benches reuse the same internal
`State` driver and synchronous sync loop the unit tests use; canbench runs each
as an isolated PocketIC query, so they need no replica and don't interfere.

**Baseline (canbench 0.6.0, 2026-06-23, post §9 blob arena)** — instructions per call:

| Benchmark | Setup | Instructions | Notes |
|-----------|-------|-------------:|-------|
| `serve_small_asset` | 10 KiB, 1 chunk | **0.152 M** | http_request only |
| `serve_large_asset` | 8 MiB, 8 chunks | **8.60 M** | http_request + 7 streaming callbacks (was 21.4 M pre-§9) |
| `sync_commit` | 50 assets × 4 KiB | **85.4 M** | execute_operations commit (~1.71 M/asset) |
| `sync_commit_large` | 1 asset, 8 MiB | **660.0 M** | one large commit; dominated by unchanged SHA-256 + cert (was 761.2 M pre-§9) |
| `post_upgrade_rebuild` | 100 assets | **126.9 M** | fresh State + rebuild (~1.27 M/asset) |

(Heap/stable-memory increase measured ~0 pages in every measured region —
stable-memory bucket allocation is amortized into setup.)

Reading against limits:

- **Serving is a non-issue.** A small asset is **0.157 M** instructions — ~0.003%
  of the ~5 B per-query limit. Even an 8 MiB asset served across all its
  callbacks is 21.6 M (~0.4%), and that is dominated by the unavoidable byte copy,
  not stable-structure bookkeeping. This settles the serving concern (Concern 1)
  on absolute numbers alone, independent of what heap would have cost.
- **Sync is comfortable.** ~1.83 M instructions per asset committed, dominated by
  SHA-256 + recertification (both heap, unchanged by the migration). The stable
  writes are a small slice. Phase 3 turns this into a cycles figure.
- **Risk B is now quantified — see §6.** The single 100-asset point linearly
  extrapolated to a misleadingly low ~1.3 B at 10k; measuring 1k/10k directly
  shows the rebuild is **super-linear** (the heap cert-tree insert is O(log n)) —
  10k assets actually costs **21.4 B**, and the install/upgrade instruction
  ceiling lands at **~115k assets**. Quantified and accepted; no mitigation now.

**Decision gate:** serving costs are <<1% of the query instruction limit, so the
serving concern is settled. Remaining value of the A/B (Phase 2) is to put a
heap-vs-stable delta on `sync_commit`/`serve_*` for the team.

Next: wire `canbench` into CI to fail on regressions past a threshold (compares
against the committed `canbench_results.yml`).

### Phase 2 — A/B vs. the heap implementation (done, 2026-06-22)

Method: the **quick cross-check** — ported the identical Phase-1 harness onto
`69fd945` (#85, the last heap-based commit, immediately before #86 introduced
stable memory) in a throwaway worktree, with the same sizing constants. Adapted
only to the heap-era API (`State::default()`, `content_encoding: String`). The
post-upgrade analog is `upgrade_roundtrip`: the heap upgrade serializes the whole
`State` to its `serde_cbor` blob and back (`pre_upgrade`/`post_upgrade`) — the
O(total bytes) cost stable structures removes. Caveat: this commit predates #89
(typed encoding + Brotli), so it's a sanity cross-check, not a perfectly
isolated A/B — but it's directly apples-to-apples for these four workloads.

Instructions per call, heap (`69fd945`) vs stable (`main`):

| Benchmark | Heap | Stable | Stable ÷ Heap |
|-----------|-----:|-------:|--------------:|
| `serve_small_asset` (10 KiB) | 71.2 K | 156.6 K | **2.2×** |
| `serve_large_asset` (8 MiB, 8 chunks) | 91.7 K | 21.38 M | **233×** |
| `sync_commit` (50 assets) | 70.9 M | 91.5 M | **1.29×** |
| upgrade (heap roundtrip ↔ stable rebuild), 100 assets | 123.9 M | 126.8 M | **1.02×** |

What the numbers say:

- **Serving small assets: ~2× more, absolutely trivial.** 71 K → 157 K. Both are
  <0.01% of the ~5 B per-query instruction limit. Non-issue, as predicted.
- **Serving large assets: 236× more — and this is the one real cost.** The heap
  version serves content as `RcBytes` (an `Rc` clone, O(1), *no byte copy*); the
  stable version must `stable64_read`-copy every byte out of stable memory, so its
  serve cost is **O(bytes)** (~2.6 instr/byte) where heap was O(1). Even so, 21.6 M
  for a full 8 MiB asset is ~0.4% of one query's budget — and that 21.6 M is the
  **sum across all 8 streaming callbacks**, which in production are 8 separate
  query messages (~2.7 M each for one 1 MiB chunk). Per message it's trivial, and
  all of it is dwarfed by network latency. Real and measurable, not a practical
  problem. (This sharpens Phase-1's "negligible" claim: negligible *per message*,
  but the per-byte read is the genuine architectural cost of the move.)
- **Sync commit: +29%.** 70.9 M → 91.5 M for 50 assets. The stable `BTreeMap`
  writes add ~29% over heap; the rest (hashing, recertification) is shared and
  unchanged. Modest, on an infrequent non-free path.
- **Upgrade: ~equal here, but the scaling diverges in stable's favor.** At 100 ×
  4 KiB (≈400 KiB) the cert-tree rebuild dominates both, so they tie. But heap
  upgrade is **O(total content bytes)** (serialize + deserialize *everything*)
  with a hard instruction-limit **ceiling** — a large enough canister simply
  *can't upgrade*. Stable is **O(asset count)** and never touches content. The
  migration's upgrade win shows up at scale and as removing that cliff, not in
  this small bench.

Bottom line for the team: the stable migration costs ~2× on small-asset serving
(trivial), ~29% on sync, and a real but per-message-trivial O(bytes) read on
large-asset serving — in exchange for unbounded capacity and an upgrade path that
no longer has a serialization ceiling. The serving/sync costs are all far under
the per-message limits and invisible next to network latency.

### Phase 3 — end-to-end cycles on the existing e2e setup (no new infra)

`icp network start` already runs PocketIC under the hood, and `icp canister
status --json` already reports `cycles` (and `memory_size`,
`num_instructions_total`). The e2e harness already drives all of this
([crates/e2e/src/lib.rs](crates/e2e/src/lib.rs)). So we measure real sync cycle
cost with **zero new infrastructure**:

1. Start local replica (e2e `Replica` guard).
2. Deploy + read `icp canister status frontend --json` → record `cycles`.
3. Run a realistic sync.
4. Read `cycles` again → the delta is the sync's cycle cost.

Add this as an e2e measurement (it can print/record rather than assert, or
assert a generous upper bound to catch regressions). This gives the concrete
"syncing this directory costs X cycles" figure for the sync concern.

### Phase 4 — tackle the two risks once numbers are in

Address only what the numbers justify (see §6), one at a time.

## 6. Risks to watch (let benchmarks decide priority)

- **Risk A — per-chunk `metadata.get` in the streaming callback. (Addressed.)**
  Each callback used to re-fetch and deserialize the whole `AssetMeta` (all
  encodings + headers) just to re-derive `content_id`, scaling with chunk count.
  The streaming token is now **self-describing** — it carries `content_id` and
  `num_chunks` directly ([http.rs:30](crates/canister-core/src/http.rs#L30)), so
  the callback hits only `content.get` and skips the metadata lookup + CBOR
  decode entirely ([state.rs:738](crates/canister-core/src/state.rs#L738)).
  `serve_large_asset` confirmed the size of this: **21.61 M → 21.38 M** (−1.0%,
  ~225 K instructions over 7 callbacks ≈ **32 K saved per callback**). Small, as
  predicted — the per-chunk `stable64_read` byte copy (~2.6 M/chunk) dominates
  and is irreducible. The token validation that the old `metadata.get` provided
  is no longer needed: `content_id` is monotonic and never reused, so a stale or
  forged token misses the content store and serves an empty body, which the HTTP
  gateway's `sha256` check on the accumulated stream rejects.
- **Risk B — `post_upgrade_rebuild` scaling. (Quantified & accepted.)** Asset
  *data* no longer needs serialization on upgrade (the win), but we still iterate
  **all** metadata to rebuild the heap cert tree in one `post_upgrade` message
  ([state.rs:956](crates/canister-core/src/state.rs#L956)). The cost is
  **super-linear** — the heap cert-tree (RbTree) insert is O(log n), so total
  rebuild is ~O(n·log n), not the flat per-asset cost the single 100-asset point
  suggested:

  | Assets | Total instr. | Per asset |
  |-------:|-------------:|----------:|
  | 100 | 0.127 B | 1.27 M |
  | 1 000 | 1.69 B | 1.69 M |
  | 10 000 | 21.4 B | 2.14 M |

  Fitting per-asset cost against log(n) and extrapolating to the **300 B
  instruction limit for canister install/upgrade**
  ([resource-limits](https://docs.internetcomputer.org/building-apps/canister-management/resource-limits))
  puts the upgrade ceiling at **~115k assets** (~79k against the older 200 B
  figure). Below it, DTS slices the long `post_upgrade` across rounds
  automatically, so it never blocks the subnet; above it the upgrade traps and
  rolls back — the canister keeps serving on the old code but can't be upgraded
  until the asset count drops.

  **Decision: accept, no mitigation now.** ~115k individually-served files in one
  frontend canister is far past any realistic catalog (typical: tens–hundreds;
  large sites: low thousands), and the super-linear term is inherent to the heap
  cert tree — not the stable reads the migration added. Building it down
  (incremental/lazy certification spread across post-upgrade messages) would trade
  a non-problem for a real availability regression: assets are uncertified until
  the rebuild finishes, so the gateway would reject them during the window. The
  100-asset `post_upgrade_rebuild` bench stays the CI gate — it tracks per-asset
  rebuild cost, so any change that lowers the ceiling surfaces as a regression.
  Escape hatch if a catalog ever nears the ceiling: incremental certification
  (rebuild in batches, 503 for not-yet-certified assets during the window) or
  persisting the cert tree. Not warranted today. (Deferred micro-opt: the rebuild
  does `metadata.keys()` + a per-key `metadata.get()` — two stable traversals per
  asset; one `iter()` pass would shrink the stable-read slice, but that slice is
  small next to the O(n·log n) heap work, so it only nudges the ceiling. Skip
  until the ceiling matters.)

## 7. Out of scope / what we deliberately won't do

- **Local replica wall-clock timing for the heap-vs-stable delta.** Dominated by
  replica scheduling and (for updates) local consensus, no real network latency,
  noisy. Only useful as a "still works" sanity check, not for the decision.
- **Mainnet benchmarking.** Unnecessary — the delta is instruction count, which
  is network-independent. Absolute serving latency (if ever needed) is a
  separate question and would read the same with heap; measure once on a
  playground canister if it comes up.

## 8. Bottom line / framing for the team

The decision isn't "is stable faster than heap" (it's slightly slower per
message). The heap approach had a hard **correctness ceiling**: heap is capped,
and serialize-everything pre/post-upgrade is itself instruction-bounded, so a
large canister eventually **can't upgrade**. Stable structures removes that
cliff. The cost is a few stable reads/writes that we expect to be <<1% of
per-message limits and negligible against network latency.

We benchmark not to re-decide, but to **prove the overhead is negligible** and
to **set CI guardrails** that catch the two real risks (A, B) before they bite.

## 9. Content blob arena — minimizing the serve/sync byte coefficient

Phase 2 measured serving large assets at **~2.6 instr/byte** and accepted it as
"the irreducible O(bytes) copy." A follow-up decomposition showed that was wrong:
most of it was avoidable overhead, not the copy.

### Where 2.6 came from

Content was a `StableBTreeMap<ContentChunkKey, Vec<u8>>`. An *unbounded* value is
stored inline in the BTree node, which (per ic-stable-structures) uses a hardcoded
**1024-byte page size**. A ≤1.9 MB chunk is therefore shredded across ~1,875
overflow pages, and a read walks that chain one small page at a time — a
chain-pointer read **plus** a data read per page (~2 syscalls/KB). The write side
is worse: each page is also allocated and linked, so inserting fragments into ~5
syscalls/KB.

Measured decomposition (8 MiB, isolated from cert/hash/HTTP work):

| Path | instr/byte |
|------|-----------:|
| One contiguous `stable64_read` (floor) | **1.00** |
| `StableBTreeMap<_, Vec<u8>>` read | 2.53 |
| `StableBTreeMap<_, Vec<u8>>` **write** | **12.32** |

So 2.6 ≈ **1.0 irreducible copy + 1.5 page-fragmentation overhead**, and writes
paid ~12× the floor. Bounding the value would raise the page size but the
allocator hands out one fixed page-sized block *per node regardless of fill*
(~8.25× the bound), so bounding at 1.9 MB makes every content node ~15.7 MB —
ruinous for the common small-asset case. A non-starter.

### The fix (implemented)

Decouple "big contiguous reads" from "big page allocations"
([`blob_store.rs`](crates/canister-core/src/blob_store.rs)):

- **Index** — `StableBTreeMap<ContentChunkKey, BlobRef>`, where `BlobRef` is a
  12-byte `(offset, len)`. Tiny fixed entries ⇒ fast traversal, no page waste.
- **Data** — a dedicated raw stable region (`MemoryId(6)`) holding chunk bytes
  contiguously. A read is one index lookup + one `stable64_read`; a write is one
  `stable64_write` + one index insert.
- **Allocator** — an address-ordered, coalescing free list. It is *derived heap
  state*, rebuilt from the index on construction (like the certification tree), so
  there is no new on-stable format to keep upgrade-safe and no `pre_upgrade` hook.
  Chunks are immutable and freed per `content_id`, so the allocator only ever sees
  whole-chunk alloc/free.

### Result (canbench before → after, real measurements)

| Benchmark | Before | After | Δ |
|-----------|-------:|------:|--:|
| `serve_small_asset` (10 KiB) | 0.157 M | 0.152 M | −2.8% |
| `serve_large_asset` (8 MiB) | 21.38 M | **8.60 M** | **−59.8%** |
| `sync_commit` (50 × 4 KiB) | 91.5 M | 85.4 M | −6.7% |
| `sync_commit_large` (8 MiB) | 761.2 M | **660.0 M** | −13.3% (+ 136→0 heap pages) |
| `post_upgrade_rebuild` (100) | 126.8 M | 126.9 M | +0.08% (noise) |

Serving large assets is now **1.01 instr/byte** — essentially the copy floor, a
~2.5× cut. The large-sync win (−101 M) is the content write dropping ~10× to
~1.26 instr/byte; it's masked in the total by the unchanged ~600 M of SHA-256 +
certification. The arena write also drops the per-chunk `to_vec()` heap clone
(the 136→0 `heap_increase`). `post_upgrade_rebuild` is unchanged — the allocator
rebuild (one `iter()` over the index) is lost in the noise of the cert-tree
rebuild.

**Memory tradeoff (minor, accepted):** content now uses two `MemoryManager`
regions (index + data) instead of one, and each rounds up to the 8 MiB bucket
granularity, so a canister with *any* content carries up to ~8 MiB of extra fixed
slack. That's offset at scale by removing the old per-1024-byte-page `ChunkHeader`
overhead (~7 B/KB) and the inline-node fragmentation, and is negligible against a
real catalog. New CI gate: `serve_large_asset` (floor coefficient) and
`sync_commit_large` (write coefficient) join the committed baseline so any
regression of either surfaces as a diff.

## Appendix — commands

```sh
# Phase 1/2: instruction microbenchmarks
cargo install canbench --version 0.6.0 --locked    # one-time; must match canbench-rs 0.6.0
cd crates/canister-core && canbench                # reads canbench.yml in this dir
cd crates/canister-core && canbench --persist      # update the committed baseline

# Phase 3: end-to-end cycle delta (existing e2e infra)
icp network start -d
icp canister status frontend --json   # read "cycles" before
# ... run sync ...
icp canister status frontend --json   # read "cycles" after; diff = sync cost
icp network stop
```
