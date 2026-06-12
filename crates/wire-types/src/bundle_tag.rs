//! Bundle tag: the release identity shared by the canister and its paired sync
//! plugin.
//!
//! The canister and the sync plugin ship together as one bundle and are only
//! expected to work with their exact counterpart. Both compile [`BUNDLE_TAG`]
//! in: the canister exposes it via the `bundle_tag` query, and the plugin
//! refuses to sync unless the canister reports the identical tag. A mismatch
//! means the deployed canister wasn't upgraded to match the plugin (e.g. `icp
//! sync` after bumping the recipe without re-installing).
//!
//! The tag is the build time as a `YYYYMMDDhhmm` decimal in UTC — e.g.
//! 202606121430 for 2026-06-12 14:30 — packed into one integer. The fixed-width
//! fields run most-significant first (year → minute), so a plain numeric compare
//! is already chronological: the plugin uses it to tell the user whether the
//! canister is older or newer. The value is human-readable as-is, so
//! [`format_tag`] only has to punctuate it — no calendar math.

/// Bundle tag this artifact was built from: the build time as a `YYYYMMDDhhmm`
/// decimal (UTC), or `None` for an unstamped dev build.
///
/// The value is injected at build time from `ASSETS_BUNDLE_TAG`. The release
/// pipeline derives it once from the released commit's UTC committer time
/// (`TZ=UTC git log -1 --date=format-local:%Y%m%d%H%M --format=%cd`) and passes
/// the same value to both the canister and plugin builds — deriving it
/// separately per build could yield differing minutes and never match. It's read
/// via `option_env!`, which the compiler tracks: when the variable is unset
/// (every local/dev build) the value stays `None`, so this crate — and
/// everything downstream — is not recompiled. The recompile happens only when
/// the tag changes, i.e. at release. No build script needed.
///
/// `None` is the unstamped dev build and orders before any real tag.
pub const BUNDLE_TAG: Option<u64> = match option_env!("ASSETS_BUNDLE_TAG") {
    Some(s) => Some(parse_tag(s)),
    None => None,
};

/// Parse the injected `ASSETS_BUNDLE_TAG` into its `YYYYMMDDhhmm` integer at
/// compile time. Anything that isn't exactly twelve digits forming a valid UTC
/// date-time fails the build rather than silently shipping a bogus tag — the
/// release pipeline must supply a clean `YYYYMMDDhhmm`.
const fn parse_tag(s: &str) -> u64 {
    let bytes = s.as_bytes();
    assert!(
        bytes.len() == 12,
        "ASSETS_BUNDLE_TAG must be 12 digits (YYYYMMDDhhmm, UTC)"
    );
    let mut i = 0;
    let mut val: u64 = 0;
    while i < bytes.len() {
        let b = bytes[i];
        assert!(
            b >= b'0' && b <= b'9',
            "ASSETS_BUNDLE_TAG must be decimal digits (YYYYMMDDhhmm, UTC)"
        );
        val = val * 10 + (b - b'0') as u64;
        i += 1;
    }
    // Reject malformed fields at the build, not at runtime. The year is
    // unconstrained; the rest must be real month/day/hour/minute values.
    let month = (val / 1_000_000) % 100;
    let day = (val / 10_000) % 100;
    let hour = (val / 100) % 100;
    let minute = val % 100;
    assert!(
        month >= 1 && month <= 12,
        "ASSETS_BUNDLE_TAG month must be 01–12"
    );
    assert!(day >= 1 && day <= 31, "ASSETS_BUNDLE_TAG day must be 01–31");
    assert!(hour <= 23, "ASSETS_BUNDLE_TAG hour must be 00–23");
    assert!(minute <= 59, "ASSETS_BUNDLE_TAG minute must be 00–59");
    val
}

/// Render a [`BUNDLE_TAG`] value as `YYYY-MM-DD HH:MM UTC` for human-readable
/// diagnostics; `None` (the unstamped dev build) renders as a label. The tag is
/// already a `YYYYMMDDhhmm` decimal, so this just splits the fixed-width fields
/// and punctuates them — no date arithmetic.
pub fn format_tag(tag: Option<u64>) -> String {
    let Some(tag) = tag else {
        return "unstamped (dev build)".to_string();
    };
    let year = tag / 100_000_000;
    let month = (tag / 1_000_000) % 100;
    let day = (tag / 10_000) % 100;
    let hour = (tag / 100) % 100;
    let minute = tag % 100;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tag_renders_utc_timestamp() {
        // YYYYMMDDhhmm = 202606121430 -> 2026-06-12 14:30 UTC.
        assert_eq!(format_tag(Some(202_606_121_430)), "2026-06-12 14:30 UTC");
        assert_eq!(format_tag(Some(200_001_010_000)), "2000-01-01 00:00 UTC");
    }

    #[test]
    fn format_tag_marks_unstamped_dev_build() {
        assert_eq!(format_tag(None), "unstamped (dev build)");
    }

    #[test]
    fn parse_tag_reads_twelve_digit_yyyymmddhhmm() {
        assert_eq!(parse_tag("202606121430"), 202_606_121_430);
        assert_eq!(parse_tag("200001010000"), 200_001_010_000);
    }

    #[test]
    fn newer_tag_compares_greater() {
        // A plain numeric compare is chronological (2000 < 2026).
        assert!(Some(202_606_121_430) > Some(200_001_010_000u64));
        // Unstamped dev build orders before any real tag.
        assert!(None < Some(200_001_010_000u64));
    }
}
