//! The compressors a sync applies, supplied by the caller.
//!
//! Which encodings a sync stores, and how they are produced, is a **deploy-time
//! choice made by the program driving the sync** — not something this crate
//! fixes. The cost is asymmetric and lands on different people: compressing
//! costs the deployer seconds, and *not* compressing (or compressing weakly)
//! costs every visitor a larger transfer for as long as the deploy is live. Only
//! the caller knows which side of that trade it is on, so the caller brings the
//! compressors.
//!
//! `sync-plugin` — and therefore every `icp deploy` — injects
//! [`Compressors::canonical`]: gzip at `flate2`'s default level, brotli at
//! quality 11 / window 22. That is the preparation `docs/verifying-contents.md`
//! describes and the one `state-hash-cli` can reproduce. A platform embedding
//! `sync-agent` may inject anything else, including [`Compressors::none`].
//!
//! # The encoding set is closed
//!
//! Only gzip and brotli can be plugged, because the *labels* are not ours to
//! extend: `wire_types::Encoding` is a Candid variant on the wire, a key in the
//! canister's stable state, a tag byte in the frozen state-hash format, and the
//! vocabulary the canister negotiates `Accept-Encoding` against. A new coding
//! would mean a canister that understands it — not a caller-side choice. What is
//! caller-side is the *function* behind each label, which is where every
//! parameter (quality, window, level, the compressor crate itself) lives.
//!
//! # Contract: a compressor must be pure
//!
//! A sync skips re-encoding an asset whose uncompressed hash the canister
//! already holds, inferring that the stored compressed bytes are what these
//! compressors would produce. That inference requires each function to be a
//! **pure, deterministic function of its input** — same bytes in, same bytes
//! out, on every call and every run.
//!
//! Whoever sets a compressor owns that property. The canonical registry has it
//! (`flate2` writes `mtime=0`, so no clock leaks into the gzip header). A
//! function that embeds a timestamp, samples a random seed, or splits blocks
//! non-deterministically across threads breaks it, and the symptom is a sync that
//! re-prepares and re-uploads everything on every deploy — the [`canary`] sees a
//! different fingerprint each time. Two other things are also the caller's:
//! emitting bytes that actually decode as the declared coding, and not panicking.
//!
//! [`canary`]: crate::canary

use std::sync::Arc;
use wire_types::Encoding;

/// A compressor: uncompressed bytes in, encoded bytes out.
///
/// Must be pure and deterministic — see the [module docs](self#contract-a-compressor-must-be-pure).
pub type CompressFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

/// The compressors to apply to compressible assets, one slot per pluggable
/// encoding. `None` means "don't store this encoding at all" — no function runs,
/// nothing is uploaded, and the canister unsets it on the next sync.
///
/// Identity is not a slot: the uncompressed copy is always stored (it is the
/// fallback body, and its hash is what the sync diff pivots on), and it is never
/// produced by a compressor.
#[derive(Clone)]
pub struct Compressors {
    pub gzip: Option<CompressFn>,
    pub br: Option<CompressFn>,
}

impl Compressors {
    /// The canonical preparation: gzip at `flate2`'s default level, brotli at
    /// quality 11 / window 22.
    ///
    /// What `sync-plugin` injects, so what every `icp deploy` produces, and the
    /// only registry `state-hash-cli` can reproduce a canister's state hash from.
    /// Its output bytes are pinned by golden vectors in this module — nothing in
    /// semver protects them, and a drift costs every deployed canister a full
    /// re-upload.
    #[cfg(feature = "canonical-compressors")]
    pub fn canonical() -> Self {
        Self {
            gzip: Some(Arc::new(|bytes: &[u8]| {
                use std::io::Write;
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(bytes).map_err(|e| format!("gzip: {e}"))?;
                e.finish().map_err(|e| format!("gzip finish: {e}"))
            })),
            br: Some(Arc::new(|bytes: &[u8]| {
                use std::io::Write;
                let mut out = Vec::new();
                {
                    let mut w = brotli::CompressorWriter::new(&mut out, 4096, 11, 22);
                    w.write_all(bytes).map_err(|e| format!("brotli: {e}"))?;
                    w.flush().map_err(|e| format!("brotli flush: {e}"))?;
                }
                Ok(out)
            })),
        }
    }

    /// No compressors: every asset is stored as its uncompressed copy only.
    ///
    /// Preparation becomes reading and hashing, and one copy of each asset goes
    /// over the wire instead of up to three — cheapest on both phases, at the
    /// cost of a much larger transfer for every visitor. Nothing about the stored
    /// bytes then depends on a compressor implementation.
    pub fn none() -> Self {
        Self {
            gzip: None,
            br: None,
        }
    }

    /// The compressor for `encoding`, if one is set. Always `None` for
    /// `Identity`, which is stored as-is rather than produced.
    pub fn for_encoding(&self, encoding: Encoding) -> Option<&CompressFn> {
        match encoding {
            Encoding::Identity => None,
            Encoding::Gzip => self.gzip.as_ref(),
            Encoding::Brotli => self.br.as_ref(),
        }
    }

    /// Whether no compressor is set at all, i.e. only identity will be stored.
    pub fn is_empty(&self) -> bool {
        self.gzip.is_none() && self.br.is_none()
    }

    /// The set compressors with their encodings, in a fixed order independent of
    /// anything the caller does — so the [`canary`](crate::canary) fingerprint
    /// never depends on incidental ordering.
    pub(crate) fn present(&self) -> impl Iterator<Item = (Encoding, &CompressFn)> {
        [
            (Encoding::Gzip, self.gzip.as_ref()),
            (Encoding::Brotli, self.br.as_ref()),
        ]
        .into_iter()
        .filter_map(|(encoding, f)| f.map(|f| (encoding, f)))
    }

    /// Which slots are set, as a bitmask. Folded into the canary so "gzip absent"
    /// is structurally distinct from any set of compressed bytes, rather than
    /// distinct only because no bytes happened to be folded in for it.
    pub(crate) fn presence_bits(&self) -> u8 {
        u8::from(self.gzip.is_some()) | u8::from(self.br.is_some()) << 1
    }
}

/// Renders which slots are set. The functions themselves are opaque — a
/// `dyn Fn` has nothing to show — which is also why `Compressors` has no
/// `PartialEq`: two registries are compared through the canary fingerprint of
/// what they *produce*, never by identity.
impl std::fmt::Debug for Compressors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compressors")
            .field("gzip", &self.gzip.is_some())
            .field("br", &self.br.is_some())
            .finish()
    }
}

#[cfg(all(test, feature = "canonical-compressors"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Read;

    fn canonical_gzip(data: &[u8]) -> Vec<u8> {
        (Compressors::canonical().gzip.unwrap())(data).unwrap()
    }

    fn canonical_br(data: &[u8]) -> Vec<u8> {
        (Compressors::canonical().br.unwrap())(data).unwrap()
    }

    // --- registry shape ---

    #[test]
    fn canonical_sets_both_slots() {
        let c = Compressors::canonical();
        assert!(!c.is_empty());
        assert!(c.for_encoding(Encoding::Gzip).is_some());
        assert!(c.for_encoding(Encoding::Brotli).is_some());
        assert_eq!(c.presence_bits(), 0b11);
        assert_eq!(
            c.present().map(|(e, _)| e).collect::<Vec<_>>(),
            vec![Encoding::Gzip, Encoding::Brotli]
        );
    }

    #[test]
    fn none_sets_no_slots() {
        let c = Compressors::none();
        assert!(c.is_empty());
        assert_eq!(c.presence_bits(), 0);
        assert_eq!(c.present().count(), 0);
    }

    /// Identity is stored as-is, never produced — so it has no slot even when
    /// both compressors are set.
    #[test]
    fn identity_never_has_a_compressor() {
        assert!(
            Compressors::canonical()
                .for_encoding(Encoding::Identity)
                .is_none()
        );
    }

    #[test]
    fn presence_bits_distinguish_every_combination() {
        let one = |gzip: bool, br: bool| {
            let c = Compressors::canonical();
            Compressors {
                gzip: gzip.then(|| c.gzip.clone().unwrap()),
                br: br.then(|| c.br.clone().unwrap()),
            }
            .presence_bits()
        };
        let bits = [
            one(false, false),
            one(true, false),
            one(false, true),
            one(true, true),
        ];
        assert_eq!(bits, [0b00, 0b01, 0b10, 0b11]);
    }

    // --- round trips ---

    #[test]
    fn canonical_gzip_round_trip() {
        let original = b"hello gzip world, hello gzip world";
        let mut decompressed = Vec::new();
        flate2::read::GzDecoder::new(canonical_gzip(original).as_slice())
            .read_to_end(&mut decompressed)
            .unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn canonical_brotli_round_trip() {
        let original = b"hello brotli world, hello brotli world";
        let mut decompressed = Vec::new();
        brotli::Decompressor::new(canonical_br(original).as_slice(), 4096)
            .read_to_end(&mut decompressed)
            .unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn canonical_compressors_are_deterministic() {
        let input = golden_input();
        assert_eq!(canonical_gzip(&input), canonical_gzip(&input));
        assert_eq!(canonical_br(&input), canonical_br(&input));
    }

    // --- golden vectors ---
    //
    // The canonical compressors' *output bytes*, pinned. Nothing in the
    // compressor crates promises these: compressed output isn't part of a
    // published API, so a semver-compatible bump may re-tune heuristics, and
    // `flate2`'s DEFLATE bytes depend on which backend feature unification
    // selected. RFC 1951 and RFC 7932 don't settle it either — they specify
    // decoders.
    //
    // Changing these bytes is legal but expensive: every canister deployed with
    // the canonical registry re-uploads every compressible asset on its next
    // sync, and every previously-published state hash stops matching. So this
    // fires at PR time, before anything ships. The canary (`crate::canary`)
    // covers the other window — a *deploy* whose compressors differ from the
    // canister's, including registries CI never sees.
    //
    // **If this fails**: something changed how the canonical registry compresses.
    // Check for a dependency bump (`brotli`, `flate2`, `miniz_oxide`), a `flate2`
    // backend feature pulled in by another crate, or an edit to `canonical`
    // above. If the change is intended, update the goldens here and in
    // `canary::canonical_fingerprint_is_pinned`, and expect the re-uploads.

    /// A fixed input with enough structure for both compressors to make real
    /// choices — a uniform run would survive almost any heuristic change.
    fn golden_input() -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..256 {
            out.extend_from_slice(
                format!("line {i}: the quick brown fox jumps over it\n").as_bytes(),
            );
        }
        out
    }

    fn digest_of(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn canonical_gzip_output_is_pinned() {
        let encoded = canonical_gzip(&golden_input());
        assert_eq!(encoded.len(), 730, "gzip output length drifted");
        assert_eq!(
            digest_of(&encoded),
            [
                53, 21, 232, 48, 211, 165, 56, 190, 113, 46, 204, 53, 164, 16, 135, 245, 158, 67,
                167, 35, 218, 133, 12, 150, 25, 243, 215, 140, 95, 197, 49, 211,
            ],
            "gzip output bytes drifted"
        );
    }

    #[test]
    fn canonical_brotli_output_is_pinned() {
        let encoded = canonical_br(&golden_input());
        assert_eq!(encoded.len(), 353, "brotli output length drifted");
        assert_eq!(
            digest_of(&encoded),
            [
                212, 217, 148, 219, 167, 195, 250, 83, 46, 171, 21, 217, 14, 42, 139, 156, 216,
                254, 76, 185, 100, 97, 88, 156, 47, 215, 255, 52, 180, 230, 245, 5,
            ],
            "brotli output bytes drifted"
        );
    }
}
