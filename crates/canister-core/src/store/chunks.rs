//! Content chunk store: raw chunk bytes in a contiguous stable region, indexed by
//! `(content_id, chunk_index)`.
//!
//! ## Why not `StableBTreeMap<ContentChunkKey, Vec<u8>>`
//!
//! A `StableBTreeMap` with an *unbounded* value stores each value inline in the
//! BTree node, which uses a fixed 1024-byte page size. A multi-MB chunk is then
//! shredded across ~1 page-per-KB overflow pages, and every read walks that chain
//! one small page at a time (chain-pointer read + data read per page). Measured,
//! that costs **~2.6 instr/byte to read and ~12 instr/byte to write** — vs. a
//! ~1 instr/byte floor for a single contiguous `stable64_read`/`write`. The
//! fragmentation is the entire overhead; the raw copy is irreducible.
//!
//! Bounding the value instead would raise the page size (~8.25× the bound) but the
//! allocator hands out one fixed page-sized block *per node regardless of fill*,
//! so a node holding small chunks would waste megabytes. Content sizes span a few
//! bytes to ~1.9 MB, so that trade is a non-starter.
//!
//! ## Design
//!
//! - **Index** — `StableBTreeMap<ContentChunkKey, ChunkRef>`. Tiny fixed entries
//!   (12-byte key, 12-byte `(offset, len)` value), so the BTree itself is cheap to
//!   traverse and wastes no pages.
//! - **Data** — a dedicated raw stable [`Memory`] region holding chunk bytes
//!   contiguously. A read is one index lookup + one contiguous `read`; a write is
//!   one contiguous `write` + one index insert.
//! - **Allocator** — a derived-heap free list (address-ordered, coalescing). It is
//!   *not* persisted: like the certification tree, it is rebuilt from the index on
//!   construction ([`ChunkStore::init`] calls [`ChunkStore::rebuild`]), so there is no
//!   new on-stable format to keep upgrade-safe.
//!
//! Chunks are immutable once written and freed as a group (per `content_id`) when
//! an encoding is replaced, unset, or its asset deleted — so the allocator only
//! sees whole-chunk alloc/free, never partial rewrites.

use std::borrow::Cow;

use ic_stable_structures::storable::Bound;
use ic_stable_structures::{Memory, StableBTreeMap, Storable};

const WASM_PAGE_SIZE: u64 = 65536;

/// Key into the content chunk store, encoded big-endian (`content_id` then
/// `chunk_index`) as a fixed 12-byte key. `StableBTreeMap` orders keys by their
/// serialized bytes, so big-endian makes byte order match numeric order: a
/// range scan over one `content_id` returns its chunks in `chunk_index` order.
/// (Its `Storable` byte encoding lives in [`crate::store`].)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ContentChunkKey {
    pub(super) content_id: u64,
    pub(super) chunk_index: u32,
}

impl ContentChunkKey {
    pub(super) fn new(content_id: u64, chunk_index: u32) -> Self {
        Self {
            content_id,
            chunk_index,
        }
    }

    /// Inclusive bounds covering every chunk of `content_id`, for range scans
    /// and range deletes: `range(ContentChunkKey::range(cid))`.
    pub(super) fn range(content_id: u64) -> std::ops::RangeInclusive<Self> {
        Self::new(content_id, 0)..=Self::new(content_id, u32::MAX)
    }
}

/// A fixed 12-byte `(offset, len)` reference into the data region. `len` is a
/// `u32` because a single chunk never exceeds `MAX_CHUNK_SIZE` (~1.9 MB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChunkRef {
    offset: u64,
    len: u32,
}

impl Storable for ChunkRef {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = [0u8; 12];
        buf[..8].copy_from_slice(&self.offset.to_le_bytes());
        buf[8..].copy_from_slice(&self.len.to_le_bytes());
        Cow::Owned(buf.to_vec())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        ChunkRef {
            offset: u64::from_le_bytes(bytes[..8].try_into().expect("12-byte ChunkRef")),
            len: u32::from_le_bytes(bytes[8..12].try_into().expect("12-byte ChunkRef")),
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 12,
        is_fixed_size: true,
    };
}

/// A contiguous run of free bytes in the data region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreeSeg {
    offset: u64,
    len: u64,
}

/// Raw chunk bytes in a stable region, keyed by `(content_id, chunk_index)`.
pub(super) struct ChunkStore<M: Memory> {
    index: StableBTreeMap<ContentChunkKey, ChunkRef, M>,
    data: M,
    /// Address-ordered, coalesced free runs strictly below `bump`. Invariants:
    /// sorted by `offset`, no two segments adjacent or overlapping, every segment
    /// ends at or before `bump`. Derived heap state; rebuilt from `index`.
    free: Vec<FreeSeg>,
    /// One past the highest allocated byte; fresh allocations extend from here.
    bump: u64,
}

impl<M: Memory> ChunkStore<M> {
    /// Builds the store over its index and data regions, rebuilding the allocator
    /// from whatever the index already holds. A fresh region yields an empty
    /// allocator; an upgraded one reconstructs the exact free layout.
    pub(super) fn init(index_mem: M, data_mem: M) -> Self {
        let mut store = Self {
            index: StableBTreeMap::init(index_mem),
            data: data_mem,
            free: Vec::new(),
            bump: 0,
        };
        store.rebuild();
        store
    }

    /// Reconstructs `free` + `bump` from the index: sort every live chunk by
    /// offset, treat the gaps between them as free, and set `bump` to the end of
    /// the highest chunk. O(n log n) in the chunk count; runs once per init.
    fn rebuild(&mut self) {
        let mut used: Vec<(u64, u64)> = self
            .index
            .iter()
            .map(|e| {
                let r = e.value();
                (r.offset, r.len as u64)
            })
            .filter(|&(_, len)| len > 0)
            .collect();
        used.sort_unstable_by_key(|&(off, _)| off);

        self.free.clear();
        let mut cursor = 0u64;
        for (off, len) in used {
            if off > cursor {
                self.free.push(FreeSeg {
                    offset: cursor,
                    len: off - cursor,
                });
            }
            cursor = cursor.max(off + len);
        }
        self.bump = cursor;
    }

    /// Reads chunk `(content_id, chunk_index)`, or `None` if it isn't stored.
    // The `set_len`-then-`read` reads into an uninitialized buffer to avoid a
    // pointless zeroing memset (which would add ~0.2 instr/byte over the copy
    // floor). It is sound — see the SAFETY note — and mirrors ic-stable-structures'
    // own `read_to_vec`; `clippy::uninit_vec` flags the idiom generically.
    #[allow(clippy::uninit_vec)]
    pub(super) fn get(&self, content_id: u64, chunk_index: u32) -> Option<Vec<u8>> {
        let r = self
            .index
            .get(&ContentChunkKey::new(content_id, chunk_index))?;
        if r.len == 0 {
            return Some(Vec::new());
        }
        let mut buf: Vec<u8> = Vec::with_capacity(r.len as usize);
        // SAFETY: `set_len(r.len)` matches the just-reserved capacity, and `read`
        // overwrites exactly those `r.len` bytes before `buf` is ever observed.
        // `r.offset + r.len <= bump`, and the region is grown to cover `bump`.
        unsafe { buf.set_len(r.len as usize) };
        self.data.read(r.offset, &mut buf);
        Some(buf)
    }

    /// Writes one chunk's bytes and records its index entry. If the key already
    /// holds a chunk it is freed first (defensive — the live path always allocates
    /// a fresh, never-reused `content_id`, so keys are not overwritten in place).
    pub(super) fn insert(&mut self, content_id: u64, chunk_index: u32, bytes: &[u8]) {
        let key = ContentChunkKey::new(content_id, chunk_index);
        if let Some(old) = self.index.get(&key) {
            self.free_region(old.offset, old.len as u64);
        }
        let offset = self.alloc(bytes.len() as u64);
        if !bytes.is_empty() {
            self.data.write(offset, bytes);
        }
        self.index.insert(
            key,
            ChunkRef {
                offset,
                len: bytes.len() as u32,
            },
        );
    }

    /// Frees every chunk belonging to `content_id`, returning their bytes to the
    /// allocator. Mirrors the old range-delete over the content map.
    pub(super) fn delete_group(&mut self, content_id: u64) {
        let to_free: Vec<(ContentChunkKey, ChunkRef)> = self
            .index
            .range(ContentChunkKey::range(content_id))
            .map(|e| e.into_pair())
            .collect();
        for (key, r) in to_free {
            self.index.remove(&key);
            self.free_region(r.offset, r.len as u64);
        }
    }

    // ---- allocator ----

    /// Reserves `n` bytes and returns their start offset. First-fit over the free
    /// list, else bump-allocates fresh space (growing the region as needed). A
    /// zero-length request reserves nothing and returns `bump` (never read/written).
    fn alloc(&mut self, n: u64) -> u64 {
        if n == 0 {
            return self.bump;
        }
        for i in 0..self.free.len() {
            if self.free[i].len >= n {
                let offset = self.free[i].offset;
                if self.free[i].len == n {
                    self.free.remove(i);
                } else {
                    self.free[i].offset += n;
                    self.free[i].len -= n;
                }
                return offset;
            }
        }
        let offset = self.bump;
        self.bump += n;
        self.ensure_capacity(self.bump);
        offset
    }

    /// Returns `[offset, offset+len)` to the free list, coalescing with adjacent
    /// free runs, then trims any free tail back into `bump`.
    fn free_region(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        let end = offset + len;
        let pos = self.free.partition_point(|s| s.offset < offset);
        let mut seg = FreeSeg { offset, len };

        // Coalesce with the following segment if it starts where this one ends.
        if pos < self.free.len() && self.free[pos].offset == end {
            seg.len += self.free[pos].len;
            self.free.remove(pos);
        }
        // Coalesce with the preceding segment if it ends where this one starts;
        // otherwise insert as a new run.
        if pos > 0 && self.free[pos - 1].offset + self.free[pos - 1].len == offset {
            self.free[pos - 1].len += seg.len;
        } else {
            self.free.insert(pos, seg);
        }

        self.trim_bump();
    }

    /// Drops a free run that reaches `bump` back into the (logically) unallocated
    /// region, keeping the free list short and `bump` tight. Stable memory can't
    /// shrink, so the physical pages stay; they're reused by the next `alloc`.
    fn trim_bump(&mut self) {
        if let Some(last) = self.free.last()
            && last.offset + last.len == self.bump
        {
            self.bump = last.offset;
            self.free.pop();
        }
    }

    /// Grows the data region so it spans at least `end` bytes.
    fn ensure_capacity(&self, end: u64) {
        let have = self.data.size() * WASM_PAGE_SIZE;
        if end > have {
            self.data.grow((end - have).div_ceil(WASM_PAGE_SIZE));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_stable_structures::DefaultMemoryImpl;
    use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};

    fn store() -> ChunkStore<ic_stable_structures::memory_manager::VirtualMemory<DefaultMemoryImpl>>
    {
        let mm = MemoryManager::init(DefaultMemoryImpl::default());
        ChunkStore::init(mm.get(MemoryId::new(0)), mm.get(MemoryId::new(1)))
    }

    #[test]
    fn roundtrip_single_chunk() {
        let mut s = store();
        let bytes = vec![7u8; 5000];
        s.insert(1, 0, &bytes);
        assert_eq!(s.get(1, 0), Some(bytes));
        assert_eq!(s.get(1, 1), None);
        assert_eq!(s.get(2, 0), None);
    }

    #[test]
    fn empty_chunk_roundtrips_without_allocating() {
        let mut s = store();
        s.insert(1, 0, &[]);
        assert_eq!(s.get(1, 0), Some(Vec::new()));
        assert_eq!(s.bump, 0);
        assert!(s.free.is_empty());
    }

    #[test]
    fn multi_chunk_group_is_contiguous_in_order() {
        let mut s = store();
        let c0 = vec![1u8; 1000];
        let c1 = vec![2u8; 2000];
        let c2 = vec![3u8; 1500];
        s.insert(9, 0, &c0);
        s.insert(9, 1, &c1);
        s.insert(9, 2, &c2);
        assert_eq!(s.get(9, 0), Some(c0));
        assert_eq!(s.get(9, 1), Some(c1));
        assert_eq!(s.get(9, 2), Some(c2));
        // Bump-allocated back-to-back, no gaps yet.
        assert_eq!(s.bump, 4500);
        assert!(s.free.is_empty());
    }

    #[test]
    fn delete_group_frees_and_trims_bump() {
        let mut s = store();
        s.insert(1, 0, &vec![1u8; 1000]);
        s.insert(1, 1, &vec![1u8; 1000]);
        assert_eq!(s.bump, 2000);
        s.delete_group(1);
        // Whole tail reclaimed.
        assert_eq!(s.bump, 0);
        assert!(s.free.is_empty());
        assert_eq!(s.get(1, 0), None);
    }

    #[test]
    fn freed_hole_is_reused_by_a_fitting_allocation() {
        let mut s = store();
        s.insert(1, 0, &vec![1u8; 1000]); // [0, 1000)
        s.insert(2, 0, &vec![2u8; 1000]); // [1000, 2000)
        s.insert(3, 0, &vec![3u8; 1000]); // [2000, 3000)
        assert_eq!(s.bump, 3000);

        s.delete_group(2); // frees [1000, 2000)
        assert_eq!(
            s.free,
            vec![FreeSeg {
                offset: 1000,
                len: 1000
            }]
        );
        assert_eq!(s.bump, 3000); // middle hole, bump unchanged

        // A 1000-byte write fills the hole exactly rather than extending bump.
        s.insert(4, 0, &vec![4u8; 1000]);
        assert!(s.free.is_empty());
        assert_eq!(s.bump, 3000);
        // Verify the new chunk landed in the reused hole and reads back.
        assert_eq!(s.get(4, 0), Some(vec![4u8; 1000]));
        assert_eq!(s.get(1, 0), Some(vec![1u8; 1000]));
        assert_eq!(s.get(3, 0), Some(vec![3u8; 1000]));
    }

    #[test]
    fn smaller_allocation_splits_a_hole() {
        let mut s = store();
        s.insert(1, 0, &vec![1u8; 1000]);
        s.insert(2, 0, &vec![2u8; 1000]);
        s.insert(3, 0, &vec![3u8; 1000]);
        s.delete_group(2); // hole [1000, 2000)
        s.insert(4, 0, &vec![4u8; 600]); // takes [1000, 1600)
        assert_eq!(
            s.free,
            vec![FreeSeg {
                offset: 1600,
                len: 400
            }]
        );
        assert_eq!(s.get(4, 0), Some(vec![4u8; 600]));
    }

    #[test]
    fn adjacent_frees_coalesce() {
        let mut s = store();
        for i in 0..4u32 {
            s.insert(1, i, &vec![i as u8 + 1; 1000]);
        }
        assert_eq!(s.bump, 4000);
        // Free the two middle chunks out of order; they must merge into one run,
        // not leave two adjacent segments.
        s.delete_group(1); // deletes all four in key order → tail trimmed to 0
        assert_eq!(s.bump, 0);
        assert!(s.free.is_empty());
    }

    #[test]
    fn coalesce_with_preceding_and_following() {
        let mut s = store();
        // Lay out four blocks, free the 1st and 3rd to make non-adjacent holes,
        // then free the 2nd so it bridges both into a single [0, 3000) run.
        s.insert(0, 0, &vec![0u8; 1000]); // [0,1000)
        s.insert(1, 0, &vec![1u8; 1000]); // [1000,2000)
        s.insert(2, 0, &vec![2u8; 1000]); // [2000,3000)
        s.insert(3, 0, &vec![3u8; 1000]); // [3000,4000)
        s.delete_group(0); // free [0,1000)
        s.delete_group(2); // free [2000,3000)
        assert_eq!(
            s.free,
            vec![
                FreeSeg {
                    offset: 0,
                    len: 1000
                },
                FreeSeg {
                    offset: 2000,
                    len: 1000
                },
            ]
        );
        s.delete_group(1); // free [1000,2000) → bridges into [0,3000)
        assert_eq!(
            s.free,
            vec![FreeSeg {
                offset: 0,
                len: 3000
            }]
        );
        assert_eq!(s.bump, 4000);
        assert_eq!(s.get(3, 0), Some(vec![3u8; 1000]));
    }

    #[test]
    fn rebuild_reconstructs_free_layout_from_index() {
        let mm = MemoryManager::init(DefaultMemoryImpl::default());
        let (idx, dat) = (MemoryId::new(0), MemoryId::new(1));

        // Populate, then poke holes.
        {
            let mut s = ChunkStore::init(mm.get(idx), mm.get(dat));
            for i in 0..5u64 {
                s.insert(i, 0, &vec![i as u8; 1000]);
            }
            s.delete_group(1); // hole [1000,2000)
            s.delete_group(3); // hole [3000,4000)
            assert_eq!(
                s.free,
                vec![
                    FreeSeg {
                        offset: 1000,
                        len: 1000
                    },
                    FreeSeg {
                        offset: 3000,
                        len: 1000
                    },
                ]
            );
            assert_eq!(s.bump, 5000);
        }

        // Re-open over the same memory (simulates an upgrade): the allocator must
        // come back identical from the index alone.
        let s2 = ChunkStore::init(mm.get(idx), mm.get(dat));
        assert_eq!(
            s2.free,
            vec![
                FreeSeg {
                    offset: 1000,
                    len: 1000
                },
                FreeSeg {
                    offset: 3000,
                    len: 1000
                },
            ]
        );
        assert_eq!(s2.bump, 5000);
        assert_eq!(s2.get(0, 0), Some(vec![0u8; 1000]));
        assert_eq!(s2.get(4, 0), Some(vec![4u8; 1000]));
        assert_eq!(s2.get(1, 0), None);
    }

    #[test]
    fn overwriting_a_key_frees_the_old_chunk() {
        let mut s = store();
        s.insert(1, 0, &vec![1u8; 1000]);
        s.insert(1, 0, &vec![2u8; 1000]); // same key, new bytes
        assert_eq!(s.get(1, 0), Some(vec![2u8; 1000]));
        // Old [0,1000) freed, new one reused it → still a single 1000-byte region.
        assert_eq!(s.bump, 1000);
        assert!(s.free.is_empty());
    }

    #[test]
    fn allocation_spanning_many_pages_reads_back() {
        let mut s = store();
        // ~1.9 MB — larger than a 64 KiB wasm page and a manager bucket boundary.
        let big = vec![0xABu8; 1_900_000];
        s.insert(7, 0, &big);
        assert_eq!(s.get(7, 0), Some(big));
    }
}
