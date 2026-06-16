//! Bundle version: the semver release identity shared by the canister and its
//! paired sync plugin.
//!
//! The canister and the sync plugin ship together as one bundle and are upgraded
//! as a locked pair. Both compile [`VERSION`] in: the canister exposes it via the
//! `version` query, and the plugin refuses to sync unless the canister reports
//! the identical version. A mismatch means the deployed canister wasn't paired
//! with this plugin — most often `icp sync` after bumping the recipe without
//! re-installing the canister.
//!
//! # What the number means
//!
//! The single workspace version (`CARGO_PKG_VERSION`, e.g. `0.1.0`) doubles as
//! the on-chain release identity, so the version *value* also tells you whether
//! moving the canister between two releases keeps its state:
//!
//! - **Non-breaking** — the canister can be upgraded in place
//!   (`install_code` mode `upgrade`); `post_upgrade` runs and recovers assets and
//!   redirect rules from stable memory.
//! - **Breaking** — the canister must be reinstalled (`install_code` mode
//!   `reinstall`); `post_upgrade` does *not* run, so all state is wiped and a
//!   fresh sync re-uploads every asset and redirect rule.
//!
//! We follow Cargo's 0.x convention to encode that distinction (see
//! [`Version::series`]):
//!
//! - while `major == 0`: a **minor** bump is breaking (`0.1.x → 0.2.0`,
//!   reinstall), a **patch** bump is non-breaking (`0.1.0 → 0.1.1`, upgrade);
//! - from `1.0.0` on: a **major** bump is breaking, minor/patch are non-breaking.
//!
//! Bumping is a deliberate human decision — the relevant axis is canister *state*
//! upgradability, which a conventional-commit marker can't infer on its own.
//!
//! The value comes from `CARGO_PKG_VERSION` at compile time, so every build —
//! dev or release — knows its own version; there is no "unstamped" build. The
//! release pipeline tags the commit `v<version>` and verifies it matches the
//! workspace version (see the `Makefile` `tag` target and the release workflow).

use candid::CandidType;
use serde::{Deserialize, Serialize};

/// Semver version this artifact was built from, taken verbatim from the
/// workspace `version` in `Cargo.toml`.
///
/// Fields are declared major → minor → patch, so the derived [`Ord`] is exactly
/// semver precedence (we never use pre-release suffixes). It derives
/// [`CandidType`] so the canister can return it from the `version` query and the
/// plugin can decode and compare it.
#[derive(
    CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// This artifact's version, parsed from `CARGO_PKG_VERSION` at compile time.
///
/// `CARGO_PKG_VERSION` is always set by cargo to this crate's version, which
/// inherits the single workspace version — so the canister and plugin built from
/// the same checkout always agree, and bumping the version in `Cargo.toml`
/// recompiles everything downstream.
pub const VERSION: Version = parse_version(env!("CARGO_PKG_VERSION"));

/// Parse a plain `major.minor.patch` string into a [`Version`] at compile time.
/// Anything that isn't exactly three dot-separated decimal fields fails the
/// build — we never publish a pre-release/build-metadata suffix, so the parser
/// stays this strict on purpose.
const fn parse_version(s: &str) -> Version {
    let bytes = s.as_bytes();
    let mut parts = [0u32; 3];
    let mut idx = 0; // which field we're filling: 0=major, 1=minor, 2=patch
    let mut seen_digit = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'.' {
            assert!(seen_digit, "CARGO_PKG_VERSION field must contain digits");
            assert!(idx < 2, "CARGO_PKG_VERSION must be major.minor.patch");
            idx += 1;
            seen_digit = false;
        } else {
            assert!(
                b >= b'0' && b <= b'9',
                "CARGO_PKG_VERSION must be numeric major.minor.patch"
            );
            parts[idx] = parts[idx] * 10 + (b - b'0') as u32;
            seen_digit = true;
        }
        i += 1;
    }
    assert!(
        idx == 2 && seen_digit,
        "CARGO_PKG_VERSION must be major.minor.patch"
    );
    Version {
        major: parts[0],
        minor: parts[1],
        patch: parts[2],
    }
}

impl Version {
    /// The breaking-change series this version belongs to. Two versions keep the
    /// canister's state across a switch (a plain `upgrade`) iff their series
    /// match; crossing a series boundary is breaking and requires a reinstall
    /// plus a full re-upload. Cargo's 0.x rule: pre-1.0 the minor is the breaking
    /// axis so the series is `(0, minor)`; from 1.0 the major alone is, so it's
    /// `(major, 0)`.
    pub const fn series(self) -> (u32, u32) {
        if self.major == 0 {
            (0, self.minor)
        } else {
            (self.major, 0)
        }
    }

    /// Whether switching the canister between `self` and `other` is non-breaking
    /// (an in-place `upgrade` preserves state), as opposed to a breaking change
    /// that needs a reinstall and full re-upload.
    pub const fn upgrade_compatible_with(self, other: Version) -> bool {
        let a = self.series();
        let b = other.series();
        a.0 == b.0 && a.1 == b.1
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn v(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn parse_version_reads_major_minor_patch() {
        assert_eq!(parse_version("0.1.0"), v(0, 1, 0));
        assert_eq!(parse_version("12.34.56"), v(12, 34, 56));
    }

    #[test]
    fn cargo_pkg_version_parses() {
        // The build-time constant must parse, i.e. Cargo.toml stays plain semver.
        assert_eq!(VERSION, parse_version(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn display_renders_dotted_triple() {
        assert_eq!(v(0, 1, 0).to_string(), "0.1.0");
        assert_eq!(v(1, 20, 3).to_string(), "1.20.3");
    }

    #[test]
    fn ord_follows_semver_precedence() {
        assert!(v(0, 1, 0) < v(0, 1, 1));
        assert!(v(0, 1, 9) < v(0, 2, 0));
        assert!(v(0, 9, 9) < v(1, 0, 0));
    }

    #[test]
    fn upgrade_compatibility_follows_0x_rule() {
        // Pre-1.0: patch-only is non-breaking, minor is breaking.
        assert!(v(0, 1, 0).upgrade_compatible_with(v(0, 1, 5)));
        assert!(!v(0, 1, 0).upgrade_compatible_with(v(0, 2, 0)));
        // From 1.0: minor/patch are non-breaking, major is breaking.
        assert!(v(1, 0, 0).upgrade_compatible_with(v(1, 4, 2)));
        assert!(!v(1, 9, 0).upgrade_compatible_with(v(2, 0, 0)));
    }
}
