//! A fingerprint of *how a sync compresses*, used to make lazy encoding safe.
//!
//! `sync-core` skips encoding an asset whose uncompressed hash the canister
//! already holds, inferring that the stored compressed encodings are the ones
//! this sync's compressors would produce. That inference is only sound while the
//! compressors behave identically — and nothing guarantees they will. The
//! compressors are supplied by the caller (see [`Compressors`]), so they can
//! change simply because a different program ran the sync; and even for a fixed
//! registry, compressed output is not part of a crate's API surface, so a
//! semver-compatible `brotli` bump may legally re-tune its heuristics,
//! `flate2`'s DEFLATE bytes depend on which backend feature unification
//! selected, and neither is fixed by a specification (RFC 7932 and RFC 1951
//! define *decoders*).
//!
//! So instead of pinning that down by convention and hoping, the sync records
//! what its compressors actually did. The canary is the hash of a frozen input
//! run through the registry in use; the canister stores the value written
//! alongside its assets. A mismatch means "the compressors moved", and the sync
//! falls back to re-preparing everything eagerly — which is exactly the
//! pre-lazy-encoding behaviour, so the canister re-converges on its own.
//!
//! Because it fingerprints *what the injected functions produce*, it needs no
//! knowledge of them: swapping brotli's quality, dropping gzip, or supplying a
//! different crate entirely all show up here, and each costs one full re-upload
//! and nothing more.
//!
//! **This is detection, not proof.** Compressor behaviour is a function over all
//! inputs and the canary samples it at one point, so a change that alters real
//! bundles but not this input would slip through. [`input`] is therefore built
//! from deliberately varied material — long repeats, prose, structured text and
//! incompressible noise — to exercise as many encoder decision paths as a few
//! kilobytes can. What it catches reliably is what actually happens in practice:
//! a version bump, a backend swap, or a parameter change, all of which change
//! essentially every output. A miss leaves the sync exactly where it would be
//! with no canary at all, so this can only reduce the exposure, never add to it.
//!
//! It also assumes each compressor is **pure** — the contract stated in
//! [`Compressors`]. A non-deterministic one yields a fresh fingerprint every
//! deploy, which costs a full re-upload each time but never stores wrong bytes.
//!
//! [`input`] is frozen: changing it changes every canister's canary and forces
//! one full re-upload each. `input_is_frozen` guards it in CI.
//!
//! [`Compressors`]: crate::compressors::Compressors

use sha2::{Digest, Sha256};

use crate::compressors::Compressors;
use crate::prepare::MAX_CHUNK_SIZE;

/// Size of the canary input. Big enough to cross the encoders' internal block
/// boundaries and exercise several match strategies, small enough that
/// compressing it costs single-digit milliseconds even at brotli q11.
const INPUT_LEN: usize = 6 * 1024;

/// The frozen canary input: four regions with deliberately different characters,
/// so an encoder change that only fires on one kind of data still shows up.
///
/// 1. a long repeat (long-match / distance-cache paths),
/// 2. prose-like text (static dictionary, literal entropy coding),
/// 3. structured source-like text (mixed punctuation, short repeats),
/// 4. high-entropy bytes (the no-match path, literal coding).
fn input() -> Vec<u8> {
    let mut out = Vec::with_capacity(INPUT_LEN);
    let quarter = INPUT_LEN / 4;

    while out.len() < quarter {
        out.extend_from_slice(b"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb");
    }
    out.truncate(quarter);

    while out.len() < 2 * quarter {
        out.extend_from_slice(
            b"the quick brown fox jumps over the lazy dog while the sun sets slowly. ",
        );
    }
    out.truncate(2 * quarter);

    while out.len() < 3 * quarter {
        out.extend_from_slice(
            br#"{"key":"value","n":12345,"nested":{"a":[1,2,3],"b":null},"s":"text"}"#,
        );
    }
    out.truncate(3 * quarter);

    // A fixed xorshift64* stream: deterministic, no dependencies, and not
    // meaningfully compressible. The constants are frozen along with the rest.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    while out.len() < INPUT_LEN {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(INPUT_LEN);

    out
}

/// This registry's compression fingerprint: the hash of the frozen input under
/// every compressor it sets, folded together with which slots are set and the
/// preparation constants that shape the stored form.
///
/// Deliberately routed through the caller's own functions — the same calls real
/// assets take — so any change in how a sync compresses is reflected here.
/// `MAX_CHUNK_SIZE` is folded in because it decides the chunk layout a skipped
/// asset's manifest entry depends on, and the presence mask because an absent
/// compressor must be structurally distinct from any bytes a present one could
/// produce.
pub fn fingerprint(compressors: &Compressors) -> Result<[u8; 32], String> {
    let data = input();

    let mut hasher = Sha256::new();
    hasher.update(b"certified-assets preparation canary v2");
    hasher.update((MAX_CHUNK_SIZE as u64).to_le_bytes());
    hasher.update([compressors.presence_bits()]);
    for (encoding, compress) in compressors.present() {
        let encoded = compress(&data)?;
        hasher.update(encoding.label().as_bytes());
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(Sha256::digest(&encoded));
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canary input is frozen: changing it invalidates every canister's
    /// stored canary and forces a full re-upload on each. If this fails because
    /// you meant to change it, bump the domain-separation string in
    /// `fingerprint` too, and expect the re-uploads.
    #[test]
    fn input_is_frozen() {
        let digest: [u8; 32] = Sha256::digest(input()).into();
        assert_eq!(digest, INPUT_DIGEST, "canary input drifted");
    }

    /// SHA-256 of [`input`]. A golden value, not a derived one.
    const INPUT_DIGEST: [u8; 32] = [
        113, 10, 158, 48, 203, 255, 77, 203, 177, 240, 217, 133, 13, 80, 34, 205, 230, 236, 159,
        173, 213, 2, 80, 98, 23, 34, 183, 131, 37, 107, 232, 145,
    ];

    #[test]
    fn input_has_the_expected_shape() {
        let input = input();
        assert_eq!(input.len(), INPUT_LEN);
        // The four regions must actually differ, or the varied-material argument
        // in this module's docs is false.
        let quarter = INPUT_LEN / 4;
        let regions: Vec<&[u8]> = input.chunks(quarter).collect();
        for (i, a) in regions.iter().enumerate() {
            for b in regions.iter().skip(i + 1) {
                assert_ne!(a, b, "canary regions must differ");
            }
        }
    }

    /// An empty registry still has a well-defined fingerprint — no compressor
    /// runs, but the preparation constants and the empty presence mask are folded
    /// in, so switching away from it is detected like any other change.
    #[test]
    fn empty_registry_has_a_fingerprint() {
        let none = Compressors::none();
        assert_eq!(fingerprint(&none).unwrap(), fingerprint(&none).unwrap());
    }
}

#[cfg(all(test, feature = "canonical-compressors"))]
mod canonical_tests {
    use super::*;
    use crate::compressors::CompressFn;
    use std::io::Write;
    use std::sync::Arc;

    /// The whole point: the fingerprint is stable for a fixed registry, so an
    /// unchanged toolchain never triggers a spurious re-upload.
    #[test]
    fn fingerprint_is_deterministic() {
        let canonical = Compressors::canonical();
        assert_eq!(
            fingerprint(&canonical).unwrap(),
            fingerprint(&canonical).unwrap()
        );
    }

    /// The canonical registry's fingerprint value, pinned — the CI half of the
    /// pair. A drift here means the next deploy against any existing canister
    /// re-prepares and re-uploads every asset, and every published state hash
    /// stops matching. That is a legitimate thing to do, but not by accident: see
    /// the guidance on the golden vectors in `compressors.rs`, which say *which*
    /// compressor moved.
    #[test]
    fn canonical_fingerprint_is_pinned() {
        assert_eq!(
            fingerprint(&Compressors::canonical()).unwrap(),
            [
                81, 121, 116, 25, 223, 32, 50, 163, 167, 90, 92, 196, 140, 74, 43, 211, 72, 62,
                202, 218, 160, 199, 84, 130, 111, 120, 88, 162, 240, 68, 13, 18,
            ],
            "canonical compression fingerprint drifted"
        );
    }

    fn brotli_at(quality: u32) -> CompressFn {
        Arc::new(move |bytes: &[u8]| {
            let mut out = Vec::new();
            {
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
                w.write_all(bytes).map_err(|e| format!("brotli: {e}"))?;
                w.flush().map_err(|e| format!("brotli flush: {e}"))?;
            }
            Ok(out)
        })
    }

    /// The property the whole design rests on: a registry that produces
    /// different bytes has a different fingerprint, so the sync re-prepares
    /// instead of trusting stale stored encodings. Covers every axis a caller
    /// can move — parameters, dropping a slot, and dropping both.
    #[test]
    fn different_registries_have_different_fingerprints() {
        let canonical = Compressors::canonical();
        let fp = |c: &Compressors| fingerprint(c).unwrap();

        let tuned_quality = Compressors {
            gzip: canonical.gzip.clone(),
            br: Some(brotli_at(9)),
        };
        let no_gzip = Compressors {
            gzip: None,
            br: canonical.br.clone(),
        };
        let no_brotli = Compressors {
            gzip: canonical.gzip.clone(),
            br: None,
        };

        let all = [
            ("canonical", fp(&canonical)),
            ("brotli q9", fp(&tuned_quality)),
            ("no gzip", fp(&no_gzip)),
            ("no brotli", fp(&no_brotli)),
            ("none", fp(&Compressors::none())),
        ];
        for (i, (label_a, a)) in all.iter().enumerate() {
            for (label_b, b) in all.iter().skip(i + 1) {
                assert_ne!(a, b, "{label_a} and {label_b} must not collide");
            }
        }
    }

    /// ...and the fingerprint tracks the compressors' *output*, not just the
    /// constants folded in around them: a registry whose functions differ only
    /// in what they return still fingerprints differently.
    #[test]
    fn fingerprint_tracks_compressed_bytes() {
        let same_slots_different_bytes = Compressors {
            gzip: Compressors::canonical().gzip,
            br: Some(Arc::new(|_: &[u8]| Ok(b"not really brotli".to_vec()))),
        };
        assert_eq!(
            same_slots_different_bytes.presence_bits(),
            Compressors::canonical().presence_bits(),
            "this test is only meaningful if the presence masks match"
        );
        assert_ne!(
            fingerprint(&same_slots_different_bytes).unwrap(),
            fingerprint(&Compressors::canonical()).unwrap()
        );
    }

    /// A compressor that fails propagates its error rather than silently
    /// fingerprinting as something else.
    #[test]
    fn compressor_error_propagates() {
        let broken = Compressors {
            gzip: Some(Arc::new(|_: &[u8]| Err("boom".to_string()))),
            br: None,
        };
        assert_eq!(fingerprint(&broken), Err("boom".to_string()));
    }
}
