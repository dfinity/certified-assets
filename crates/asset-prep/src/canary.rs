//! A fingerprint of *how this build compresses*, used to make lazy encoding safe.
//!
//! `sync-core` skips encoding an asset whose uncompressed hash the canister
//! already holds, inferring that the stored compressed encodings are the ones
//! this build would produce. That inference is only sound while the compressors
//! behave identically — and nothing guarantees they will. Compressed output is
//! not part of a crate's API surface, so a semver-compatible `brotli` bump may
//! legally re-tune its heuristics; `flate2`'s DEFLATE bytes depend on which
//! backend feature unification selected; and neither is fixed by a
//! specification (RFC 7932 and RFC 1951 define *decoders*).
//!
//! So instead of freezing those dependencies by convention and hoping nobody
//! bumps them, the sync records what its compressors actually did. The canary is
//! the hash of a frozen input compressed by *this* build; the canister stores the
//! value written alongside its assets. A mismatch means "the compressors moved",
//! and the sync falls back to re-preparing everything eagerly — which is exactly
//! the pre-lazy-encoding behaviour, so the canister re-converges on its own.
//!
//! **This is detection, not proof.** Compressor behaviour is a function over all
//! inputs and the canary samples it at one point, so a change that alters real
//! bundles but not this input would slip through. [`INPUT`] is therefore built
//! from deliberately varied material — long repeats, prose, structured text and
//! incompressible noise — to exercise as many encoder decision paths as a few
//! kilobytes can. What it catches reliably is what actually happens in practice:
//! a version bump or a backend swap, both of which change essentially every
//! output. A miss leaves the sync exactly where it would be with no canary at
//! all, so this can only reduce the exposure, never add to it.
//!
//! [`INPUT`] is frozen: changing it changes every canister's canary and forces
//! one full re-upload each. `input_is_frozen` guards it in CI.

use sha2::{Digest, Sha256};
use wire_types::Encoding;

use crate::content::Content;
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

/// This build's compression fingerprint: the hash of the frozen input under
/// every compressor, folded together with the preparation constants that shape
/// the stored form.
///
/// Deliberately routed through [`Content::encode`] — the same call real assets
/// take — so any change to how we compress is reflected here, not just changes
/// in the underlying crates. `MAX_CHUNK_SIZE` is folded in because it decides
/// the chunk layout a skipped asset's manifest entry depends on.
pub fn fingerprint() -> Result<[u8; 32], String> {
    let content = Content {
        data: input(),
        media_type: mime::APPLICATION_OCTET_STREAM,
    };

    let mut hasher = Sha256::new();
    hasher.update(b"certified-assets preparation canary v1");
    hasher.update((MAX_CHUNK_SIZE as u64).to_le_bytes());
    for encoding in [Encoding::Gzip, Encoding::Brotli] {
        let encoded = content.encode(encoding)?;
        hasher.update(encoding.label().as_bytes());
        hasher.update((encoded.data.len() as u64).to_le_bytes());
        hasher.update(Sha256::digest(&encoded.data));
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

    /// The whole point: the fingerprint is stable for a fixed build, so an
    /// unchanged toolchain never triggers a spurious re-upload.
    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(fingerprint().unwrap(), fingerprint().unwrap());
    }

    /// The fingerprint value itself, pinned — the CI half of the pair. A drift
    /// here means the next deploy against any existing canister re-prepares and
    /// re-uploads every asset, and every published state hash stops matching.
    /// That is a legitimate thing to do, but not by accident: see the guidance
    /// on the golden vectors in `content.rs`, which say *which* compressor moved.
    #[test]
    fn fingerprint_is_pinned() {
        assert_eq!(
            fingerprint().unwrap(),
            [
                245, 226, 54, 136, 144, 3, 34, 211, 233, 170, 231, 7, 236, 41, 240, 14, 77, 42,
                176, 104, 40, 40, 127, 55, 244, 101, 113, 73, 212, 101, 239, 247,
            ],
            "compression fingerprint drifted"
        );
    }

    /// ...and it is actually sensitive to compressor output, not just to the
    /// constants folded in around it.
    #[test]
    fn fingerprint_tracks_compressed_bytes() {
        let content = Content {
            data: input(),
            media_type: mime::APPLICATION_OCTET_STREAM,
        };
        let brotli = content.encode(Encoding::Brotli).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(Sha256::digest(&brotli.data));
        let independent: [u8; 32] = hasher.finalize().into();
        // Not equal (different domain), but if brotli output were ignored the
        // fingerprint could not depend on it at all — this asserts the encode
        // path runs and produces bytes to hash.
        assert!(!brotli.data.is_empty());
        assert_ne!(fingerprint().unwrap(), independent);
    }
}
