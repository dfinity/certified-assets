//! Types and pure helpers for access protection — the `State`-free data layer
//! of the "private app" feature.
//!
//! This module owns the protection domain's data: the public Candid API types
//! ([`ProtectionStatus`], [`TokenInfo`], [`IssueTokenArgs`]), the persisted
//! shapes ([`ProtectionSettings`], [`TokenMeta`]), and the credential-channel
//! plumbing that has no business touching `State` — parsing the
//! `certified_assets_access` cookie out of a request, parsing the `token=…`
//! field out of a login `POST` body, rendering the `Set-Cookie` value, and —
//! crucially — the **certified unauthenticated / redeem responses**
//! ([`ProtectionResponse`]). Keeping their byte shape here, behind constructors
//! that both the certify path and the serve path call, guarantees the leaf the
//! canister certifies and the response it actually serves can never drift apart
//! (the same discipline `asset.rs` follows for normal assets).
//!
//! Nothing here reads canister state or the system API, so it is all directly
//! unit-testable. The access-protection behavior — which consumes these types
//! and the cookie/form helpers — lives in the state machine's `protection`
//! submodule (see [`crate::state`]).

use crate::cert::{
    CertificateExpression, NestedTreeKey, build_ic_certificate_expression_from_headers,
    build_ic_certificate_expression_header, response_hash,
};
use crate::http::HttpRequest;
use candid::CandidType;
use ic_representation_independent_hash::Value;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Reported by `check_protection_status` so the platform UI can tell a healthy
/// private app from a degraded one (login page absent — see the access-protection
/// design, "missing login page fails closed").
#[derive(Clone, Debug, PartialEq, Eq, CandidType, serde::Deserialize)]
pub enum ProtectionStatus {
    /// Public app — access protection is off.
    Disabled,
    /// Private app, healthy: the login-page asset is present.
    Enabled { login_page: String },
    /// Private app, degraded: access protection is on but the named login-page asset
    /// hasn't been synced. The app stays protected (no content is served); a
    /// sync including the page heals it to `Enabled`.
    EnabledLoginPageMissing { login_page: String },
}

/// One live access token, as `list_tokens` reports it (no secret material — the
/// plaintext value is never stored).
#[derive(Clone, Debug, PartialEq, Eq, CandidType, serde::Deserialize)]
pub struct TokenInfo {
    pub label: String,
    pub expires_at: u64,
}

/// Arguments to `issue_token`. A record (rather than positional args) so the two
/// `text` fields — the label and the optional chosen value — can't be swapped.
#[derive(Clone, Debug, CandidType, serde::Deserialize)]
pub struct IssueTokenArgs {
    /// Human label — the token's unique identifier (issue/revoke/list).
    pub label: String,
    /// Lifetime in seconds from now.
    pub ttl_secs: u32,
    /// A chosen (typeable) passphrase, or `None` for a high-entropy random token.
    pub value: Option<String>,
}

/// Cookie name carrying the access token. The value *is* the token; access
/// protection hashes it and looks it up. Named for its scope: this is an `HttpOnly`,
/// server-only credential defined and consumed entirely within this repo —
/// unlike the client-facing, cross-component `ic_env` cookie — so it doesn't
/// borrow the `ic_` namespace, and the `certified_assets_` qualifier keeps it
/// from ever colliding with a user-supplied `_headers` cookie.
const ACCESS_COOKIE: &str = "certified_assets_access";

/// `SHA-256` of a presented token value — the key into the access-protection
/// index (`State::token_index`). Lets access protection match a cookie without
/// storing the plaintext value anywhere.
pub(crate) fn token_id(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// The `Set-Cookie` value handed back on a successful redeem. Host-only (no
/// `Domain`), `HttpOnly` (page scripts can't read it), `Secure`, and a session
/// cookie (no `Max-Age` → dies on tab close). `SameSite=None; Partitioned` (CHIPS)
/// so the credential is delivered when the app is shown inside a **cross-site
/// iframe** (e.g. a preview embedded in another site): a plain cross-site cookie is
/// blocked by Safari and restricted by Chrome/Firefox, whereas a partitioned cookie
/// is scoped to the embedding top-level site and delivered there. `Partitioned` also
/// keeps the cookie from riding along to arbitrary *other* embedders. Must be
/// byte-identical between the certify path (`issue_token`) and the serve path
/// (redeem), since it is part of the certified response hash.
fn access_cookie(value: &str) -> String {
    format!("{ACCESS_COOKIE}={value}; HttpOnly; Secure; SameSite=None; Partitioned; Path=/")
}

/// Every `certified_assets_access=` value present in the request's `Cookie` header(s). The
/// browser sends *all* cookies for the origin concatenated (here at least this
/// canister's own `ic_env`), so we scan `; `-separated pairs and pick out ours —
/// plain string parsing, unaffected by whatever else rides along. Returns every
/// match (a client could carry a stale and a fresh `certified_assets_access`); access
/// protection accepts if *any* is valid.
pub(crate) fn access_cookie_values(req: &HttpRequest) -> Vec<String> {
    let mut values = Vec::new();
    for (name, value) in &req.headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in value.split(';') {
            let pair = pair.trim();
            if let Some(v) = pair.strip_prefix(&format!("{ACCESS_COOKIE}=")) {
                values.push(v.to_string());
            }
        }
    }
    values
}

/// The token value from an `application/x-www-form-urlencoded` login `POST` body
/// (`token=<value>`), URL-decoded. `None` if absent. Decodes `+` as space and
/// `%XX` escapes so a controller-chosen passphrase round-trips exactly.
pub(crate) fn parse_form_token(body: &[u8]) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    for field in body.split('&') {
        if let Some(raw) = field.strip_prefix("token=") {
            let plus_decoded = raw.replace('+', " ");
            return percent_decode_str(&plus_decoded)
                .decode_utf8()
                .ok()
                .map(|c| c.to_string());
        }
    }
    None
}

/// A fixed, certifiable response the protection layer serves: an unauthenticated
/// redirect/401, or a login redeem outcome. Carries only the "intrinsic" headers
/// (no `IC-CertificateExpression`/`IC-Certificate` — those are appended at
/// certify/serve time). The constructors are the single source of truth for each
/// response's bytes; [`Self::cert_expr`]/[`Self::response_hash`] derive exactly
/// what the certified leaf needs, mirroring [`crate::redirect::build_synthetic_entry`].
#[derive(Clone, Debug)]
pub struct ProtectionResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ProtectionResponse {
    /// `307 → <login_page>` — the unauthenticated response for HTML paths
    /// (humans navigating to a document) and for any non-asset path (SPA routes,
    /// rule paths, true 404s). Empty body.
    pub fn redirect_to_login(login_page: &str) -> Self {
        Self {
            status: 307,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("location".to_string(), login_page.to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
            ],
            body: Vec::new(),
        }
    }

    /// `401` — the unauthenticated response for non-HTML assets (JS/CSS/img/JSON).
    /// A redirect there would deliver login HTML as the wrong content type
    /// (`Unexpected token '<'`, broken image); a `401` is the correct, detectable
    /// signal that lets an expired-session client react.
    pub fn unauthorized() -> Self {
        Self {
            status: 401,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
            ],
            body: b"401 Unauthorized".to_vec(),
        }
    }

    /// Successful redeem: `302 → "/"` setting the access cookie. The cookie value
    /// is per-token, so each token certifies its own redeem response.
    pub fn redeem_success(token_value: &str) -> Self {
        Self {
            status: 302,
            headers: vec![
                ("location".to_string(), "/".to_string()),
                ("set-cookie".to_string(), access_cookie(token_value)),
                ("cache-control".to_string(), "no-store".to_string()),
            ],
            body: Vec::new(),
        }
    }

    /// Failed redeem: a `401` re-prompt at the login path. One per `login_page`,
    /// shared by every wrong/expired/absent token.
    pub fn redeem_failure() -> Self {
        Self {
            status: 401,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
            ],
            body: b"401 Unauthorized".to_vec(),
        }
    }

    fn certified_header_values(&self) -> Vec<(String, Value)> {
        self.headers
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect()
    }

    /// The certificate expression for this response (certifies its header names).
    pub fn cert_expr(&self) -> CertificateExpression {
        build_ic_certificate_expression_from_headers(&self.certified_header_values())
    }

    /// The v2 response hash for this response, including the synthesized
    /// `ic-certificateexpression` header (which is itself certified).
    pub fn response_hash(&self) -> [u8; 32] {
        let cert_expr = self.cert_expr();
        let cert_expr_header = build_ic_certificate_expression_header(&cert_expr);
        let mut certified = self.certified_header_values();
        certified.push((cert_expr_header.0, Value::String(cert_expr_header.1)));
        let body_hash: [u8; 32] = Sha256::digest(&self.body).into();
        response_hash(&certified, self.status, &body_hash).0
    }
}

/// Access-protection configuration. When `login_page` is `Some`, access
/// protection is **on**: unauthenticated requests get a certified redirect/401
/// instead of asset content, and the named asset is the exempt login surface.
/// `None` (the default) means a fully public app — access protection, the
/// no-store override, and the unauthenticated certified siblings are all absent,
/// so a public canister is bit-for-bit unchanged. Persisted in its own
/// `StableCell` (see the `Storable` impl in [`crate::store`]) so toggling
/// protection is a single small write.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProtectionSettings {
    pub login_page: Option<String>,
}

/// Per-token metadata, keyed by the token's **label** — the unique identifier a
/// controller uses to issue/revoke/list. (The hot-path check doesn't read this; it
/// uses the in-heap `token_index`, rebuilt from these records on upgrade.) Holds
/// the value hash (so revoke/GC can drop the matching `token_index` entry, and the
/// index can be rebuilt), the expiry, and the certified-tree path of this token's
/// `POST <login_page>` redeem response (`302 → "/"` + `Set-Cookie`). The redeem
/// leaf's hash is derived from the plaintext cookie value, so storing the *path*
/// lets the canister re-insert it on upgrade and remove it on revoke/GC **without**
/// ever holding the plaintext. `token_id = SHA-256(value)`, so the plaintext is
/// never stored either. Persisted as CBOR (see [`crate::store`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMeta {
    /// `SHA-256(value)` — links this token to its `token_index` entry and lets the
    /// index be reconstructed on upgrade.
    pub token_id: [u8; 32],
    /// Absolute expiry in nanoseconds; access protection rejects once `now >= expires_at`.
    pub expires_at: u64,
    /// Full `HashTreePath` (as a `Vec<NestedTreeKey>`) of the certified redeem
    /// response for this token, at the `login_page` subtree.
    pub redeem_path: Vec<NestedTreeKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_bytes::ByteBuf;

    fn req_with_headers(headers: Vec<(&str, &str)>) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            url: "/".to_string(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: ByteBuf::new(),
            certificate_version: Some(2),
        }
    }

    #[test]
    fn extracts_access_cookie_ignoring_others() {
        let req = req_with_headers(vec![(
            "Cookie",
            "ic_env=abc%3D; certified_assets_access=tok123; analytics=1",
        )]);
        assert_eq!(access_cookie_values(&req), vec!["tok123".to_string()]);
    }

    #[test]
    fn no_access_cookie_yields_empty() {
        let req = req_with_headers(vec![("Cookie", "ic_env=abc; analytics=1")]);
        assert!(access_cookie_values(&req).is_empty());
    }

    #[test]
    fn collects_multiple_access_cookies() {
        let req = req_with_headers(vec![
            ("cookie", "certified_assets_access=stale"),
            ("Cookie", "certified_assets_access=fresh"),
        ]);
        assert_eq!(
            access_cookie_values(&req),
            vec!["stale".to_string(), "fresh".to_string()]
        );
    }

    #[test]
    fn parses_form_token() {
        assert_eq!(
            parse_form_token(b"token=abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            parse_form_token(b"foo=1&token=abc123&bar=2"),
            Some("abc123".to_string())
        );
        assert_eq!(
            parse_form_token(b"token=a+b%20c"),
            Some("a b c".to_string())
        );
        assert_eq!(parse_form_token(b"password=x"), None);
    }

    #[test]
    fn access_cookie_is_embeddable_by_default() {
        // The default must work inside a cross-site iframe out of the box (the
        // Caffeine preview use case): `SameSite=None; Secure; Partitioned` (CHIPS).
        // Host-only (no `Domain`) and a session cookie (no `Max-Age`).
        assert_eq!(
            access_cookie("tok"),
            "certified_assets_access=tok; HttpOnly; Secure; SameSite=None; Partitioned; Path=/"
        );
    }

    #[test]
    fn token_id_is_sha256_of_value() {
        let expected: [u8; 32] = Sha256::digest(b"hunter2").into();
        assert_eq!(token_id("hunter2"), expected);
    }

    #[test]
    fn distinct_responses_have_distinct_hashes() {
        // The status code folds into the response hash, so a 307 and a 401 at the
        // same path are always distinguishable leaves.
        let r307 = ProtectionResponse::redirect_to_login("/login.html").response_hash();
        let r401 = ProtectionResponse::unauthorized().response_hash();
        assert_ne!(r307, r401);
        // Per-token redeem responses differ by their cookie value.
        let a = ProtectionResponse::redeem_success("tokA").response_hash();
        let b = ProtectionResponse::redeem_success("tokB").response_hash();
        assert_ne!(a, b);
    }
}
