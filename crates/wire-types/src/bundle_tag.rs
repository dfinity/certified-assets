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
//! The tag is a monotonic integer (minutes since the Unix epoch, UTC) rather
//! than a formatted string, so ordering is genuine numeric comparison — the
//! plugin uses it to tell the user whether the canister is older or newer — and
//! [`format_tag`] can render it back to a human-readable UTC timestamp for
//! diagnostics.

/// Bundle tag this artifact was built from: minutes since the Unix epoch (UTC),
/// or `None` for an unstamped dev build.
///
/// The value is injected at build time from `ASSETS_BUNDLE_TAG` — a decimal
/// minutes-since-epoch string the release pipeline computes once and passes to
/// both builds, e.g. `ASSETS_BUNDLE_TAG=$(( $(date -u +%s) / 60 ))`. Deriving it
/// separately per build would yield differing minutes and never match. It's
/// read via `option_env!`, which the compiler tracks: when the variable is
/// unset (every local/dev build) the value stays `None`, so this crate — and
/// everything downstream — is not recompiled. The recompile happens only when
/// the tag changes, i.e. at release. No build script needed.
///
/// `None` is the unstamped dev build — distinct from `Some(0)`, which would be
/// the epoch itself — and orders before any real tag.
pub const BUNDLE_TAG: Option<u64> = match option_env!("ASSETS_BUNDLE_TAG") {
    Some(s) => Some(parse_tag(s)),
    None => None,
};

/// Parse the injected `ASSETS_BUNDLE_TAG` decimal string into minutes at compile
/// time. A non-decimal or empty value fails the build rather than silently
/// degrading the tag — the release pipeline must supply clean digits.
const fn parse_tag(s: &str) -> u64 {
    let bytes = s.as_bytes();
    assert!(!bytes.is_empty(), "ASSETS_BUNDLE_TAG must not be empty");
    let mut i = 0;
    let mut val: u64 = 0;
    while i < bytes.len() {
        let b = bytes[i];
        assert!(
            b >= b'0' && b <= b'9',
            "ASSETS_BUNDLE_TAG must be decimal digits (minutes since the Unix epoch, UTC)"
        );
        val = val * 10 + (b - b'0') as u64;
        i += 1;
    }
    val
}

/// Render a [`BUNDLE_TAG`] value as `YYYY-MM-DD HH:MM UTC` for human-readable
/// diagnostics; `None` (the unstamped dev build) renders as a label. Conversion
/// is dependency-free (Howard Hinnant's civil-from-days) so `wire-types` stays
/// light.
pub fn format_tag(tag: Option<u64>) -> String {
    let Some(tag) = tag else {
        return "unstamped (dev build)".to_string();
    };
    let days = tag / 1440;
    let mins = tag % 1440;
    let (hour, minute) = (mins / 60, mins % 60);

    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year (Mar-based), [0, 365]
    let mp = (5 * doy + 2) / 153; // Mar-based month, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tag_renders_utc_timestamp() {
        // 2021-01-01 00:00:00 UTC = 1609459200s = 26824320 minutes since epoch.
        assert_eq!(format_tag(Some(26_824_320)), "2021-01-01 00:00 UTC");
        // Same day, 14:30 UTC: +14*60+30 = +870 minutes.
        assert_eq!(format_tag(Some(26_824_320 + 870)), "2021-01-01 14:30 UTC");
        assert_eq!(format_tag(Some(1)), "1970-01-01 00:01 UTC");
        // Some(0) is the epoch itself, no longer a sentinel.
        assert_eq!(format_tag(Some(0)), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn format_tag_marks_unstamped_dev_build() {
        assert_eq!(format_tag(None), "unstamped (dev build)");
    }

    #[test]
    fn parse_tag_reads_decimal_minutes() {
        assert_eq!(parse_tag("26824320"), 26_824_320);
        assert_eq!(parse_tag("0"), 0);
    }
}
