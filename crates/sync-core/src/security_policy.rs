//! Content-Security-Policy presets, ported from `ic-asset`'s `security_policy.rs`.
//!
//! `.ic-assets.json5` may set `"security_policy": "standard" | "hardened" |
//! "disabled"` as shorthand for a curated set of response headers. We keep the
//! header generation (`to_headers`) and the `Display` impl; the dfx-only json5
//! pretty-printer is dropped.

use crate::config::HeadersConfig;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
/// Asset synchronization will warn if insufficient security headers are set.
/// To help with security headers these options are provided, which can be set
/// in `.ic-assets.json5` with the `"security_policy"` field.
pub enum SecurityPolicy {
    /// No security policy provided by asset sync.
    Disabled,
    /// The default security policy that will work for most dapps but could be
    /// more secure. Asset sync will still warn that it could be hardened.
    Standard,
    /// Use the default security policy with custom improvements. Same as
    /// `Standard`, but disables the "could be hardened" warning.
    Hardened,
}

struct ConcreteSecurityPolicy {
    /// (header_name, header_content)
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

impl SecurityPolicy {
    fn to_policy(self) -> ConcreteSecurityPolicy {
        match self {
            SecurityPolicy::Disabled => ConcreteSecurityPolicy { headers: vec![] },
            SecurityPolicy::Standard | SecurityPolicy::Hardened => ConcreteSecurityPolicy {
                headers: vec![
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
                ],
            },
        }
    }

    pub(crate) fn to_headers(self) -> HeadersConfig {
        self.to_policy().to_headers()
    }
}

impl Display for SecurityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityPolicy::Disabled => write!(f, "disabled"),
            SecurityPolicy::Standard => write!(f, "standard"),
            SecurityPolicy::Hardened => write!(f, "hardened"),
        }
    }
}
