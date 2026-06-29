//! The canonical asset-canister **state hash** — a single SHA-256 over an
//! asset canister's served-content model, computed identically by the canister
//! (from stored state) and by an offline verifier (from a `dist/` directory).
//!
//! # What it is for
//!
//! Verify that an asset canister serves exactly a known frontend build — the
//! reproducible-build story, but for frontend assets instead of wasm. A verifier
//! reproduces `dist/` from public source, computes this hash locally (via
//! `asset-prep` / `state-hash-cli`), and compares it to the canister's
//! `state_hash()`. The trust root is the **source code**, never the operator's
//! reported number.
//!
//! # What the hash covers
//!
//! Every asset (by key) → `content_type`, response `headers`, and per-encoding
//! identity: the whole-encoding `sha256`, `content_len`, `num_chunks`, and the
//! per-chunk `(len, sha256)` for multi-chunk encodings; plus the canister's
//! redirect rules in match order. These are exactly the hashes the canister
//! already stores and the HTTP gateway certifies end-to-end, so matching the
//! hash while serving forged content is impossible — see `COMPUTE_STATE_HASH_PLAN.md`.
//!
//! Content **bytes** are folded in as their stored/certified hashes, never
//! re-hashed. Permissions / auth state are out of scope.
//!
//! # The canonical byte format (frozen — version 1)
//!
//! One `Sha256` over a domain-separated, length-prefixed, **little-endian** byte
//! stream. Not serde/candid, to avoid silent format drift. `write_str(s)` is a
//! `u32_le` length prefix followed by the UTF-8 bytes; hashes are fixed 32 bytes.
//!
//! ```text
//! SHA256(
//!   u8  VERSION = 1
//!   u64_le asset_count
//!   for each asset, keys ascending:
//!     write_str(key)
//!     write_str(content_type)
//!     u32_le header_count
//!     for (name, value) sorted by (lowercase(name), value):
//!       write_str(name); write_str(value)
//!     u32_le encoding_count
//!     for (encoding, enc), encoding-tag order Identity(0) < Gzip(1) < Brotli(2):
//!       u8 encoding_tag
//!       bytes32 enc.sha256
//!       u64_le enc.content_len
//!       u32_le enc.num_chunks
//!       if enc.num_chunks > 1:                     // single-chunk: covered by whole sha256
//!         for chunk in index order:
//!           u32_le chunk.len; bytes32 chunk.sha256
//!   u32_le redirect_rule_count
//!   for rule in Vec (match) order:
//!     u8 pattern_tag (Exact = 0 | Subtree = 1); write_str(inner)
//!     write_str(rule.to)
//!     u16_le rule.status
//!     u32_le header_count; for (name, value) sorted: write_str(name); write_str(value)
//! )
//! ```
//!
//! Header order and encoding order are normalized by the encoder (sorted), so the
//! two implementations need only agree on the *set*, not the iteration order.
//! Asset key order, by contrast, is the caller's responsibility — [`digest`]
//! sorts; the canister iterates its key-ordered metadata map directly. Redirect
//! **rules** keep their `Vec` order, which is semantic (first match wins).
//!
//! # Frozen constants the verifier must match (documented, not encoded here)
//!
//! Per-chunk hashes depend on the chunk boundary `MAX_CHUNK_SIZE`, and compressed
//! encodings depend on the exact compressor params (gzip `flate2` default; brotli
//! quality 11 / window 22). Those live in `asset-prep`; a verifier must use a
//! matching `state-hash-cli` version. See `docs/verifying-contents.md`.

use sha2::{Digest, Sha256};
use wire_types::{Encoding, RedirectRule, RulePattern};

/// Byte-format version. Folded in first; bumped only when the layout below
/// changes (which invalidates every previously-computed hash — there are no
/// stored hashes to preserve, so a bump is free).
pub const VERSION: u8 = 1;

/// Per-chunk certification data folded into a multi-chunk encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestChunk {
    pub len: u32,
    pub sha256: [u8; 32],
}

/// One stored encoding of an asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEncoding {
    pub encoding: Encoding,
    /// SHA-256 of the whole encoding (all chunks concatenated). The gateway-
    /// certified body hash of a single-chunk 200.
    pub sha256: [u8; 32],
    /// Total encoded length (sum of all chunk lengths).
    pub content_len: u64,
    /// Number of stored chunks (always ≥ 1).
    pub num_chunks: u32,
    /// Per-chunk `(len, sha256)` in chunk-index order. Must have `num_chunks`
    /// entries when `num_chunks > 1`; ignored (and conventionally empty) when
    /// `num_chunks <= 1`, where the single chunk is covered by [`Self::sha256`].
    pub chunks: Vec<ManifestChunk>,
}

impl ManifestEncoding {
    /// A single-chunk encoding (the common case): the whole `sha256` is also the
    /// only chunk's hash, so no per-chunk data is folded in.
    pub fn single_chunk(encoding: Encoding, sha256: [u8; 32], content_len: u64) -> Self {
        Self {
            encoding,
            sha256,
            content_len,
            num_chunks: 1,
            chunks: Vec::new(),
        }
    }

    /// A multi-chunk encoding. `chunks` is the per-chunk `(len, sha256)` in index
    /// order; `num_chunks` is set to its length and `content_len` to the sum of
    /// the chunk lengths.
    pub fn multi_chunk(encoding: Encoding, sha256: [u8; 32], chunks: Vec<ManifestChunk>) -> Self {
        let content_len = chunks.iter().map(|c| c.len as u64).sum();
        Self {
            encoding,
            sha256,
            content_len,
            num_chunks: chunks.len() as u32,
            chunks,
        }
    }
}

/// One asset, as the hash sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestAsset {
    pub key: String,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub encodings: Vec<ManifestEncoding>,
}

/// The full served-content model: every asset plus the ordered redirect rules.
///
/// Both sides build one of these — the canister from stored `State`, the verifier
/// from a `dist/` directory — and [`digest`] reduces it to the 32-byte hash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub assets: Vec<ManifestAsset>,
    pub redirect_rules: Vec<RedirectRule>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// The canonical 32-byte state hash of this manifest.
    pub fn digest(&self) -> [u8; 32] {
        digest(self)
    }
}

/// The encoding-tag byte. Pinned here (not derived from the enum's declaration
/// order) because it is part of the frozen byte format.
fn encoding_tag(encoding: Encoding) -> u8 {
    match encoding {
        Encoding::Identity => 0,
        Encoding::Gzip => 1,
        Encoding::Brotli => 2,
    }
}

/// Streaming encoder for the canonical byte format. The canister drives this
/// incrementally — one asset per message — so a many-asset state stays within
/// the per-message instruction limit, while [`digest`] drives it in one pass.
/// Both produce identical bytes, hence identical hashes.
///
/// Usage contract: [`begin`](Self::begin) once, then [`write_asset`](Self::write_asset)
/// for every asset **in ascending key order**, then exactly one
/// [`write_redirect_rules`](Self::write_redirect_rules), then
/// [`finish`](Self::finish).
#[derive(Clone)]
pub struct StateHasher {
    hasher: Sha256,
}

impl std::fmt::Debug for StateHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The Sha256 mid-state is opaque; don't try to render it.
        f.write_str("StateHasher")
    }
}

impl StateHasher {
    /// Starts a fresh hash, folding in the version byte and the asset count.
    pub fn begin(asset_count: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update([VERSION]);
        hasher.update(asset_count.to_le_bytes());
        Self { hasher }
    }

    /// Folds in one asset. Headers and encodings are sorted internally, so the
    /// caller need not pre-sort them; asset key order is the caller's job.
    pub fn write_asset(&mut self, asset: &ManifestAsset) {
        write_str(&mut self.hasher, &asset.key);
        write_str(&mut self.hasher, &asset.content_type);
        write_headers(&mut self.hasher, &asset.headers);

        let mut encodings: Vec<&ManifestEncoding> = asset.encodings.iter().collect();
        encodings.sort_by_key(|e| encoding_tag(e.encoding));
        self.hasher.update((encodings.len() as u32).to_le_bytes());
        for enc in encodings {
            self.hasher.update([encoding_tag(enc.encoding)]);
            self.hasher.update(enc.sha256);
            self.hasher.update(enc.content_len.to_le_bytes());
            self.hasher.update(enc.num_chunks.to_le_bytes());
            if enc.num_chunks > 1 {
                for chunk in &enc.chunks {
                    self.hasher.update(chunk.len.to_le_bytes());
                    self.hasher.update(chunk.sha256);
                }
            }
        }
    }

    /// Folds in the redirect rules, in `Vec` (match) order. Called exactly once,
    /// after all assets.
    pub fn write_redirect_rules(&mut self, rules: &[RedirectRule]) {
        self.hasher.update((rules.len() as u32).to_le_bytes());
        for rule in rules {
            let (tag, inner) = match &rule.from {
                RulePattern::Exact(p) => (0u8, p),
                RulePattern::Subtree(p) => (1u8, p),
            };
            self.hasher.update([tag]);
            write_str(&mut self.hasher, inner);
            write_str(&mut self.hasher, &rule.to);
            self.hasher.update(rule.status.to_le_bytes());
            write_headers(&mut self.hasher, &rule.headers);
        }
    }

    /// Finalizes the hash.
    pub fn finish(self) -> [u8; 32] {
        let out = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&out);
        hash
    }
}

fn write_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u32).to_le_bytes());
    hasher.update(s.as_bytes());
}

/// Length-prefixed header block, sorted by `(lowercase(name), value)` so the
/// hash is independent of the order the two sides happen to emit headers in.
fn write_headers(hasher: &mut Sha256, headers: &[(String, String)]) {
    let mut sorted: Vec<&(String, String)> = headers.iter().collect();
    sorted.sort_by(|a, b| {
        a.0.to_ascii_lowercase()
            .cmp(&b.0.to_ascii_lowercase())
            .then_with(|| a.1.cmp(&b.1))
    });
    hasher.update((sorted.len() as u32).to_le_bytes());
    for (name, value) in sorted {
        write_str(hasher, name);
        write_str(hasher, value);
    }
}

/// Computes the canonical 32-byte state hash of `manifest`.
///
/// Assets are sorted by key here, so callers may pass them in any order; this is
/// the single source of the format the canister streams incrementally.
pub fn digest(manifest: &Manifest) -> [u8; 32] {
    let mut assets: Vec<&ManifestAsset> = manifest.assets.iter().collect();
    assets.sort_by(|a, b| a.key.cmp(&b.key));

    let mut hasher = StateHasher::begin(assets.len() as u64);
    for asset in assets {
        hasher.write_asset(asset);
    }
    hasher.write_redirect_rules(&manifest.redirect_rules);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn asset(key: &str) -> ManifestAsset {
        ManifestAsset {
            key: key.to_string(),
            content_type: "text/html".to_string(),
            headers: vec![],
            encodings: vec![ManifestEncoding::single_chunk(Encoding::Identity, h(1), 10)],
        }
    }

    // --- Determinism and order-independence ---

    #[test]
    fn digest_is_deterministic() {
        let m = Manifest {
            assets: vec![asset("/index.html")],
            redirect_rules: vec![],
        };
        assert_eq!(digest(&m), digest(&m));
    }

    #[test]
    fn asset_order_does_not_matter() {
        let a = asset("/a.html");
        let b = asset("/b.html");
        let m1 = Manifest {
            assets: vec![a.clone(), b.clone()],
            redirect_rules: vec![],
        };
        let m2 = Manifest {
            assets: vec![b, a],
            redirect_rules: vec![],
        };
        assert_eq!(digest(&m1), digest(&m2));
    }

    #[test]
    fn header_order_does_not_matter_but_set_does() {
        let mut a = asset("/x");
        a.headers = vec![
            ("X-A".to_string(), "1".to_string()),
            ("X-B".to_string(), "2".to_string()),
        ];
        let mut b = asset("/x");
        b.headers = vec![
            ("X-B".to_string(), "2".to_string()),
            ("X-A".to_string(), "1".to_string()),
        ];
        let mut c = asset("/x");
        c.headers = vec![("X-A".to_string(), "1".to_string())];

        let dig = |asset: ManifestAsset| {
            digest(&Manifest {
                assets: vec![asset],
                redirect_rules: vec![],
            })
        };
        assert_eq!(dig(a), dig(b), "reordered headers hash the same");
        assert_ne!(
            dig(c.clone()),
            dig(asset("/x")),
            "removing a header changes it"
        );
    }

    #[test]
    fn encoding_order_does_not_matter() {
        let mut a = asset("/x");
        a.encodings = vec![
            ManifestEncoding::single_chunk(Encoding::Identity, h(1), 10),
            ManifestEncoding::single_chunk(Encoding::Gzip, h(2), 5),
        ];
        let mut b = asset("/x");
        b.encodings = vec![
            ManifestEncoding::single_chunk(Encoding::Gzip, h(2), 5),
            ManifestEncoding::single_chunk(Encoding::Identity, h(1), 10),
        ];
        let dig = |asset: ManifestAsset| {
            digest(&Manifest {
                assets: vec![asset],
                redirect_rules: vec![],
            })
        };
        assert_eq!(dig(a), dig(b));
    }

    // --- Sensitivity: every field is covered ---

    #[test]
    fn changing_any_field_changes_the_hash() {
        let base = Manifest {
            assets: vec![asset("/index.html")],
            redirect_rules: vec![],
        };
        let base_d = digest(&base);

        let mut k = base.clone();
        k.assets[0].key = "/other.html".to_string();
        assert_ne!(digest(&k), base_d, "key");

        let mut ct = base.clone();
        ct.assets[0].content_type = "text/plain".to_string();
        assert_ne!(digest(&ct), base_d, "content_type");

        let mut hd = base.clone();
        hd.assets[0].headers = vec![("a".to_string(), "b".to_string())];
        assert_ne!(digest(&hd), base_d, "headers");

        let mut sh = base.clone();
        sh.assets[0].encodings[0].sha256 = h(9);
        assert_ne!(digest(&sh), base_d, "encoding sha256");

        let mut cl = base.clone();
        cl.assets[0].encodings[0].content_len = 999;
        assert_ne!(digest(&cl), base_d, "content_len");

        let mut nc = base.clone();
        nc.assets[0].encodings[0].num_chunks = 2;
        assert_ne!(digest(&nc), base_d, "num_chunks");
    }

    #[test]
    fn multi_chunk_per_chunk_hashes_are_covered() {
        let multi = |chunks: Vec<ManifestChunk>| {
            let mut a = asset("/big.bin");
            a.content_type = "application/octet-stream".to_string();
            a.encodings = vec![ManifestEncoding::multi_chunk(
                Encoding::Identity,
                h(7),
                chunks,
            )];
            digest(&Manifest {
                assets: vec![a],
                redirect_rules: vec![],
            })
        };
        let base = multi(vec![
            ManifestChunk {
                len: 100,
                sha256: h(1),
            },
            ManifestChunk {
                len: 50,
                sha256: h(2),
            },
        ]);
        let diff_chunk_hash = multi(vec![
            ManifestChunk {
                len: 100,
                sha256: h(1),
            },
            ManifestChunk {
                len: 50,
                sha256: h(3),
            },
        ]);
        let diff_chunk_len = multi(vec![
            ManifestChunk {
                len: 100,
                sha256: h(1),
            },
            ManifestChunk {
                len: 51,
                sha256: h(2),
            },
        ]);
        assert_ne!(base, diff_chunk_hash, "per-chunk sha256 is folded in");
        assert_ne!(base, diff_chunk_len, "per-chunk len is folded in");
    }

    #[test]
    fn single_chunk_ignores_per_chunk_vec() {
        // A single-chunk encoding is covered by its whole sha256; stray per-chunk
        // entries (num_chunks <= 1) must not affect the hash.
        let mut with = asset("/x");
        with.encodings = vec![ManifestEncoding {
            encoding: Encoding::Identity,
            sha256: h(1),
            content_len: 10,
            num_chunks: 1,
            chunks: vec![ManifestChunk {
                len: 10,
                sha256: h(1),
            }],
        }];
        let without = asset("/x"); // single_chunk(): empty chunks
        let dig = |asset: ManifestAsset| {
            digest(&Manifest {
                assets: vec![asset],
                redirect_rules: vec![],
            })
        };
        assert_eq!(dig(with), dig(without));
    }

    // --- Redirect rules ---

    #[test]
    fn redirect_rule_order_matters() {
        let r1 = RedirectRule {
            from: RulePattern::Exact("/a".to_string()),
            to: "/x".to_string(),
            status: 301,
            headers: vec![],
        };
        let r2 = RedirectRule {
            from: RulePattern::Subtree("/b/".to_string()),
            to: "/y".to_string(),
            status: 302,
            headers: vec![],
        };
        let m1 = Manifest {
            assets: vec![],
            redirect_rules: vec![r1.clone(), r2.clone()],
        };
        let m2 = Manifest {
            assets: vec![],
            redirect_rules: vec![r2, r1],
        };
        assert_ne!(digest(&m1), digest(&m2), "rule order is semantic");
    }

    #[test]
    fn redirect_rule_fields_are_covered() {
        let base_rule = RedirectRule {
            from: RulePattern::Exact("/old".to_string()),
            to: "/new".to_string(),
            status: 301,
            headers: vec![],
        };
        let base = Manifest {
            assets: vec![],
            redirect_rules: vec![base_rule.clone()],
        };
        let d = digest(&base);

        let mut pat = base.clone();
        pat.redirect_rules[0].from = RulePattern::Subtree("/old".to_string());
        assert_ne!(digest(&pat), d, "Exact vs Subtree pattern tag");

        let mut to = base.clone();
        to.redirect_rules[0].to = "/elsewhere".to_string();
        assert_ne!(digest(&to), d, "target");

        let mut st = base.clone();
        st.redirect_rules[0].status = 302;
        assert_ne!(digest(&st), d, "status");

        let mut hd = base.clone();
        hd.redirect_rules[0].headers = vec![("x".to_string(), "y".to_string())];
        assert_ne!(digest(&hd), d, "rule headers");
    }

    // --- Streaming vs one-shot equivalence ---

    #[test]
    fn streaming_matches_digest() {
        // Drive the StateHasher by hand (the canister's path) and assert it
        // equals digest() (the verifier's path) on the same key-sorted input.
        let mut a = asset("/a.html");
        a.encodings = vec![
            ManifestEncoding::single_chunk(Encoding::Identity, h(1), 10),
            ManifestEncoding::single_chunk(Encoding::Gzip, h(2), 5),
        ];
        let b = asset("/b.html");
        let rules = vec![RedirectRule {
            from: RulePattern::Subtree("/p/".to_string()),
            to: "/q".to_string(),
            status: 308,
            headers: vec![("h".to_string(), "v".to_string())],
        }];

        let manifest = Manifest {
            assets: vec![b.clone(), a.clone()], // out of order on purpose
            redirect_rules: rules.clone(),
        };

        let mut hasher = StateHasher::begin(2);
        hasher.write_asset(&a); // ascending key order: /a then /b
        hasher.write_asset(&b);
        hasher.write_redirect_rules(&rules);
        assert_eq!(hasher.finish(), digest(&manifest));
    }

    // --- Golden vector: pins the exact byte format against silent drift ---

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn golden_vector_empty_manifest() {
        // The empty manifest is just: VERSION(1) ++ asset_count(0u64_le) ++
        // redirect_rule_count(0u32_le). Independently reconstruct those exact
        // bytes, and also pin the literal digest so any format drift is loud.
        let d = digest(&Manifest::default());

        let expected_bytes = {
            let mut hasher = Sha256::new();
            hasher.update([1u8]);
            hasher.update(0u64.to_le_bytes());
            hasher.update(0u32.to_le_bytes());
            let out = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&out);
            hash
        };
        assert_eq!(
            d, expected_bytes,
            "empty-manifest bytes drifted from the spec"
        );

        assert_eq!(
            hex_lower(&d),
            "8150a65e854b9bbbd52eefd048eb025c76fe48f0475c0f942c9db9eda40a94c3",
            "empty-manifest golden digest drifted",
        );
    }
}
