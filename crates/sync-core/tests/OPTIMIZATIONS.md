# Deferred sync-performance optimizations

Working notes for performance work identified by [`bench_sync.rs`](bench_sync.rs)
but not yet shipped. Each entry says what to do, the measured or expected
impact, and what's blocking us from doing it now.

Run the bench to get current baseline numbers:

```sh
cargo test --release --test bench_sync -- --ignored --nocapture --test-threads=1
```

## 1. Inline trailing chunk into `commit_batch`

`SetAssetContentArguments` has a `last_chunk: Option<Vec<u8>>` field
([canister.rs](../src/canister.rs)) that the canister accepts as content
shipped *inside* `commit_batch` rather than via a separate `create_chunks`
call. Today we always set it to `None`
([sync.rs](../src/sync.rs), `build_operations` — `last_chunk: None`).

**What to do.** For each encoding, if the final chunk is sub-`MAX_CHUNK_SIZE`,
move it out of the upload-pending list and into the `SetAssetContent` op's
`last_chunk`. Budget the total bytes carried this way against the ingress
message limit — `dfx`'s `ic-asset` uses `MAX_CHUNK_SIZE / 2`
(`~950 KB`) as the ceiling.

**Expected impact** (from the bench, post chunk-batching baseline):

| fixture | `create_chunks` now | with `last_chunk` |
|---|---:|---:|
| many_tiny  (1000 × 1 KB) | 1  | **0** |
| many_small (100 × 5 KB)  | 1  | **0** |
| few_medium (10 × 2 MB)   | 12 | **10** (drops 2 trailing-chunk calls) |
| one_huge   (1 × 50 MB)   | 28 | **27** (drops the trailing-chunk call) |

For small/medium projects the entire upload disappears into `commit_batch` and
there is no `create_chunks` round-trip at all.

**Why deferred.** Orthogonal to chunk batching; deserves its own PR so we can
measure the delta cleanly. Some care needed around the inline-budget
accounting: `last_chunk` bytes count toward the `commit_batch` arg size,
which has the same ~2 MB ingress limit, so the budget interacts with the
"split `commit_batch`" work below.

## 2. Split `commit_batch` into bounded sub-batches

Today we commit every operation in one `commit_batch` call
([sync.rs](../src/sync.rs), Phase 3). For projects with thousands of operations
(or with `last_chunk` inlining adding bytes per op), the request may exceed
the ~2 MB ingress message limit and the call will fail outright.

**What to do.** Mirror the SDK's approach
([dfx sync.rs:253-290](../../../sdk/src/canisters/frontend/ic-asset/src/sync.rs#L253-L290)):
split the operations list into batches of at most ~500 ops or ~1.5 MB of
header bytes, commit each batch, send a final empty-ops `commit_batch` to
finalize.

**Expected impact.** Correctness/scaling, not raw speed. At today's typical
project sizes it's a no-op; at 10k+ assets or with `last_chunk` enabled it
prevents outright failure.

**Why deferred.** No project we know of currently hits the limit. Should land
together with `last_chunk` inlining since the two share the ingress-size
budget.

## 3. Eliminate / batch per-asset `get_asset_properties`

[sync.rs](../src/sync.rs) (`sync`, Phase 1) issues one query call per surviving
asset to read its current `(max_age, headers, allow_raw_access)`. N round-trips
for N assets, even though most projects have property drift on zero or one
asset.

**What to do.** Two options:

- **Bulk endpoint.** Add `get_asset_properties_bulk(keys) -> Vec<AssetProperties>`
  to the canister and use it. One round-trip total.
- **Always emit `SetAssetProperties`.** Skip the query entirely and emit a
  `SetAssetProperties` op for every surviving asset with project-desired
  values. Idempotent; trades N query calls for at most N ops in a batch we
  were already going to send.

**Expected impact.** Eliminates one round-trip per asset.

**Why deferred.** Query calls are much cheaper than update calls on the IC
(no consensus), so for typical projects this is unlikely to dominate
wall-clock. Worth profiling a real deployment first to confirm before adding
either of the above.

## 4. Host-side concurrent calls

The plugin compiles to a `wasm32-wasip2` component. WASI Preview 2 is
single-threaded — `std::thread`, `rayon`, and async runtimes are all
unavailable inside the component. So even though the SDK's async fan-out
gives `dfx deploy` 50× concurrency on chunk uploads, that lever isn't
reachable from inside the current plugin model.

**What to do.** Extend the WIT interface
([`sync-plugin/wit/sync-plugin.wit`](../../sync-plugin/wit/sync-plugin.wit)) with a
batch-call import — something like
`canister-call-batch(requests: list<request>) -> list<response>` — and
implement it on the host (native Rust, tokio-based) so multiple update calls
fire concurrently. The plugin would still drive everything synchronously,
but each batch import would expand into N concurrent calls under the hood.

**Expected impact.** Where this helps:

- `one_huge` (1 × 50 MB): 28 MAX-sized `create_chunks` calls. Chunk packing
  can't help (chunks already fill the call). Concurrency could fan these out.

Where this doesn't help (because we already collapsed to 1 call):

- `many_tiny`, `many_small`: nothing left to parallelize.

**Why deferred.** This is a plugin-host interface change, not a
`sync-core` change. The chunk-batching work in this PR already removed the
majority of the call-count gap — large-file uploads remain the only regime
where concurrency would still pay off, and even there only by a constant
factor. Do this only after measuring against a real replica and confirming
large-file uploads are the bottleneck.
