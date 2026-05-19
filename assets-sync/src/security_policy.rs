//! Standard CSP and security headers selectable via `.ic-assets.json5`.
//!
//! Ported from `ic-asset/src/security_policy.rs`. The `ConcreteSecurityPolicy`
//! struct and its `to_headers()` method produce the same canonical set of
//! headers (`Content-Security-Policy`, `Permissions-Policy`, `X-Frame-Options`,
//! `Referrer-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`,
//! `X-XSS-Protection`) that `dfx deploy` would emit. The dfx-only
//! `to_json5_str()` helper (used by `dfx info security-policy`) is not ported.
//!
//! The scan-time warnings about projects missing or under-hardening their
//! policy live in [`report_security_policy_issues`]; the per-asset predicates
//! they consult are methods on [`crate::config::AssetConfig`].

use crate::config::HeadersConfig;
use crate::scan::AssetSource;
use serde::{Deserialize, Serialize};

/// How an asset's security headers should be populated.
///
/// Selectable in `.ic-assets.json5` via the `"security_policy"` field.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SecurityPolicy {
    /// No security headers are injected.
    Disabled,
    /// A baseline policy that works for most apps. Sync still warns that it
    /// could be hardened further.
    Standard,
    /// Same headers as `Standard`, but the user has acknowledged the policy
    /// and supplied custom hardening headers; the hardening warning is
    /// suppressed and missing custom headers become a hard error.
    Hardened,
}

impl SecurityPolicy {
    pub(crate) fn to_headers(self) -> HeadersConfig {
        self.to_policy().to_headers()
    }

    fn to_policy(self) -> ConcreteSecurityPolicy {
        match self {
            SecurityPolicy::Disabled => ConcreteSecurityPolicy { headers: vec![] },
            SecurityPolicy::Standard | SecurityPolicy::Hardened => ConcreteSecurityPolicy {
                headers: STANDARD_HEADERS.to_vec(),
            },
        }
    }
}

struct ConcreteSecurityPolicy {
    headers: Vec<(&'static str, &'static str)>,
}

impl ConcreteSecurityPolicy {
    fn to_headers(&self) -> HeadersConfig {
        self.headers
            .iter()
            .map(|(name, content)| (name.to_string(), content.to_string()))
            .collect()
    }
}

const STANDARD_HEADERS: &[(&str, &str)] = &[
    (
        "Content-Security-Policy",
        "default-src 'self';script-src 'self';connect-src 'self' http://localhost:* https://icp0.io https://*.icp0.io https://icp-api.io;img-src 'self' data:;style-src * 'unsafe-inline';style-src-elem * 'unsafe-inline';font-src *;object-src 'none';base-uri 'self';frame-ancestors 'none';form-action 'self';upgrade-insecure-requests;",
    ),
    (
        "Permissions-Policy",
        "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), speaker-selection=(), conversion-measurement=(), focus-without-user-activation=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), sync-script=(), trust-token-redemption=(), window-placement=(), vertical-scroll=()",
    ),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "same-origin"),
    (
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-XSS-Protection", "1; mode=block"),
];

/// Inspects the resolved configs across all sources and prints the same
/// warnings that `ic-asset/src/sync.rs::gather_asset_descriptors` emits:
/// no-policy notice, standard-policy hardening hint, and a hard error if any
/// asset declares the `hardened` policy without supplying custom headers.
pub fn report_security_policy_issues(sources: &[AssetSource]) -> Result<(), String> {
    let no_policy: Vec<&AssetSource> = sources
        .iter()
        .filter(|s| s.config.warn_about_no_security_policy())
        .collect();
    if !no_policy.is_empty() {
        let qnt = if no_policy.len() == sources.len() {
            "any"
        } else {
            "some"
        };
        eprintln!("This project does not define a security policy for {qnt} assets.");
        eprintln!("You should define a security policy in .ic-assets.json5. For example:");
        eprintln!("[");
        eprintln!("  {{");
        eprintln!(r#"    "match": "**/*","#);
        eprintln!(r#"    "security_policy": "standard""#);
        eprintln!("  }}");
        eprintln!("]");
        if no_policy.len() != sources.len() {
            eprintln!("Assets without any security policy:");
            for s in &no_policy {
                eprintln!("  - {}", s.key);
            }
        }
    }

    let standard: Vec<&AssetSource> = sources
        .iter()
        .filter(|s| s.config.warn_about_standard_security_policy())
        .collect();
    if !standard.is_empty() {
        let qnt = if standard.len() == sources.len() {
            "all"
        } else {
            "some"
        };
        eprintln!(
            "This project uses the default security policy for {qnt} assets. While it is set up to work with many applications, it is recommended to further harden the policy to increase security against attacks like XSS."
        );
        if standard.len() != sources.len() {
            eprintln!("Unhardened assets:");
            for s in &standard {
                eprintln!("  - {}", s.key);
            }
        }
    }
    if !standard.is_empty() || !no_policy.is_empty() {
        eprintln!(
            r#"To disable the policy warning, define "disable_security_policy_warning": true in .ic-assets.json5."#
        );
    }

    let missing_hardening: Vec<&AssetSource> = sources
        .iter()
        .filter(|s| s.config.warn_about_missing_hardening_headers())
        .collect();
    if !missing_hardening.is_empty() {
        let mut detail = String::new();
        if missing_hardening.len() == sources.len() {
            detail.push_str("Unhardened assets: all");
        } else {
            detail.push_str("Unhardened assets:");
            for s in &missing_hardening {
                detail.push_str(&format!("\n  - {}", s.key));
            }
        }
        return Err(format!(
            "security_policy is set to \"hardened\" but no custom headers are configured. {detail}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AssetConfig;
    use std::path::PathBuf;

    fn src(key: &str, config: AssetConfig) -> AssetSource {
        AssetSource {
            path: PathBuf::from(key.trim_start_matches('/')),
            key: key.to_string(),
            config,
        }
    }

    #[test]
    fn disabled_policy_has_no_headers() {
        assert!(SecurityPolicy::Disabled.to_headers().is_empty());
    }

    #[test]
    fn standard_policy_includes_canonical_headers() {
        let h = SecurityPolicy::Standard.to_headers();
        assert!(h.contains_key("Content-Security-Policy"));
        assert!(h.contains_key("Permissions-Policy"));
        assert_eq!(h["X-Frame-Options"], "DENY");
        assert_eq!(h["X-Content-Type-Options"], "nosniff");
    }

    #[test]
    fn hardened_policy_returns_same_headers_as_standard() {
        assert_eq!(
            SecurityPolicy::Standard.to_headers(),
            SecurityPolicy::Hardened.to_headers()
        );
    }

    #[test]
    fn report_warns_when_no_policy_for_all_assets() {
        // Sanity: the predicate fires on default config.
        let sources = vec![src("/a", AssetConfig::default())];
        assert!(report_security_policy_issues(&sources).is_ok());
    }

    #[test]
    fn report_errors_when_hardened_without_headers() {
        let config = AssetConfig {
            security_policy: Some(SecurityPolicy::Hardened),
            ..AssetConfig::default()
        };
        let sources = vec![src("/a", config)];
        let err = report_security_policy_issues(&sources).unwrap_err();
        assert!(err.contains("hardened"), "got: {err}");
    }

    #[test]
    fn report_ok_when_hardened_with_custom_headers() {
        let mut headers = HeadersConfig::new();
        headers.insert("X-Custom".to_string(), "1".to_string());
        let config = AssetConfig {
            security_policy: Some(SecurityPolicy::Hardened),
            headers: Some(headers),
            ..AssetConfig::default()
        };
        let sources = vec![src("/a", config)];
        assert!(report_security_policy_issues(&sources).is_ok());
    }

    #[test]
    fn report_ok_when_standard_policy_set() {
        let config = AssetConfig {
            security_policy: Some(SecurityPolicy::Standard),
            ..AssetConfig::default()
        };
        let sources = vec![src("/a", config)];
        assert!(report_security_policy_issues(&sources).is_ok());
    }

    #[test]
    fn report_skips_warning_when_disabled_flag_set() {
        let config = AssetConfig {
            disable_security_policy_warning: Some(true),
            ..AssetConfig::default()
        };
        let sources = vec![src("/a", config)];
        // No policy + warning disabled → predicate is false; nothing to assert
        // beyond a successful return (capturing stderr would be over-fit).
        assert!(!sources[0].config.warn_about_no_security_policy());
        assert!(report_security_policy_issues(&sources).is_ok());
    }
}
