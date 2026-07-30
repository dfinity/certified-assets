//! `state-hash` — compute an asset canister's canonical **state hash** from a
//! local `dist/` directory, offline.
//!
//! The verifier's half of the reproducible-frontend story: reproduce `dist/`
//! from public source, run this on it, and compare the printed hash to the
//! canister's `state_hash()`. If they match, the canister serves exactly that
//! build. The trust root is the source you reproduced — never an operator's
//! reported number.
//!
//! This binary depends only on `asset-prep` (preparation + hashing) and, through
//! it, `state-hash` (the frozen byte format). It links no canister-call code,
//! identity, or deploy capability, so a verifier vetting it has a minimal
//! surface to read.
//!
//! Usage:
//!   state-hash <dist-dir>
//!
//! `<dist-dir>` is the built site directory (the same one passed to a deploy),
//! including any `_headers` / `_redirects` files. Prints one 64-char hex hash
//! per preparation mode — `compressed` (what `icp deploy` produces) and
//! `uncompressed` — since the same directory hashes differently depending on
//! whether compressed encodings were stored. A canister matches exactly one.
//! On error, prints a message to stderr and exits non-zero.
//!
//! The `compressed` hash is bound to a contract — the compressor parameters
//! (gzip `flate2` default; brotli quality 11 / window 22), the compressor
//! implementations themselves, and `MAX_CHUNK_SIZE` — so a verifier must use a
//! `state-hash` build matching the deploying plugin's version. The
//! `uncompressed` hash depends on no compressor at all. See
//! `docs/verifying-contents.md`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "state-hash".to_string());

    let dir = match (args.next(), args.next()) {
        (Some(dir), None) if !dir.starts_with('-') => dir,
        (Some(flag), _) if flag == "-h" || flag == "--help" => {
            print_usage(&program);
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("error: expected exactly one argument, a path to a built site directory\n");
            print_usage(&program);
            return ExitCode::FAILURE;
        }
    };

    // A deploy either stores compressed encodings alongside the uncompressed
    // copy or doesn't, and the two produce different state hashes from the same
    // directory. Rather than ask the verifier which was used — a question they
    // often can't answer, and a flag that would invite more flags — print both
    // and let them see which one the canister reports.
    let modes = [
        (asset_prep::Compression::Enabled, "compressed"),
        (asset_prep::Compression::Disabled, "uncompressed"),
    ];
    for (compression, label) in modes {
        match asset_prep::state_hash_for_dir(&dir, compression) {
            Ok(hash) => println!("{label:<14}{}", hex::encode(hash)),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn print_usage(program: &str) {
    eprintln!("Usage: {program} <dist-dir>");
    eprintln!();
    eprintln!("Computes the canonical state hash of a built site directory and prints it as hex,");
    eprintln!("to compare against an asset canister's `state_hash()`. Include any `_headers` and");
    eprintln!("`_redirects` files in <dist-dir>, exactly as deployed.");
}
