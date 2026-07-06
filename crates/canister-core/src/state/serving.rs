//! The HTTP read path: `http_request` and everything it fans out to.
//!
//! This is the `impl State` half that turns a request into a certified
//! response. It reads content from [`crate::store::Store`] and witnesses from
//! [`crate::cert::Certifier`] but never mutates either — serving is
//! read-only over the state the sync/certify paths build up. Access protection
//! runs ahead of resolution here in `http_request`; the responses it serves are
//! built in [`super::protection`].

use super::State;
use crate::asset::{headers_for, range_headers_for, AssetMeta, EncodingMeta};
use crate::http::{HeaderField, HttpRequest, HttpResponse};
use ic_certification::Hash;
use percent_encoding::percent_decode_str;
use serde_bytes::ByteBuf;
use std::fmt;
use wire_types::{Encoding, RedirectRule};

#[derive(Debug, PartialEq, Eq)]
enum UrlDecodeError {
    InvalidPercentEncoding,
}

impl fmt::Display for UrlDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPercentEncoding => write!(f, "invalid percent encoding"),
        }
    }
}

/// Decodes a percent encoded string according to https://url.spec.whatwg.org/#percent-decode
///
/// This is a wrapper around the percent-encoding crate.
///
/// The rules that it follow by are:
/// - Start with an empty sequence of bytes of the output
/// - Convert the input to a sequence of bytes
/// - if the byte is `%` and the next two bytes are hex, convet the hex value to a byte
///   and add it to the output, otherwise add the byte to the output
/// - convert the output byte sequence to a UTF-8 string and return it. If the conversion
///   fails return an error.
fn url_decode(url: &str) -> Result<String, UrlDecodeError> {
    match percent_decode_str(url).decode_utf8() {
        Ok(result) => Ok(result.to_string()),
        Err(_) => Err(UrlDecodeError::InvalidPercentEncoding),
    }
}

/// Parse an `If-None-Match` request header into the content hashes the client
/// already holds. Our `ETag` is `"<hex sha256>"` (see [`crate::asset::etag_value`]),
/// so each token is unquoted and hex-decoded back to a 32-byte hash; the weak
/// prefix `W/` is stripped first (RFC 7232 §3.2 mandates the weak comparison for
/// `If-None-Match`). Tokens we can't read as a 32-byte hash — `*`, or any
/// validator we didn't mint — simply don't match, so the client gets a normal
/// 200.
fn parse_if_none_match(value: &str) -> Vec<Hash> {
    value
        .split(',')
        .filter_map(|token| {
            let token = token.trim();
            let token = token.strip_prefix("W/").unwrap_or(token).trim();
            let token = token.strip_prefix('"')?.strip_suffix('"')?;
            let bytes = hex::decode(token).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
        .collect()
}

/// Phase 0 spike: parse the *start* byte of a single `Range: bytes=<start>-[end]`
/// header. The end is ignored (we serve the containing chunk). Multi-range
/// (comma) and suffix (`bytes=-N`) forms return `None` → the request is served
/// as a normal full response.
fn parse_range_start(value: &str) -> Option<usize> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, _end) = spec.split_once('-')?;
    start.trim().parse::<usize>().ok()
}

impl State {
    pub fn http_request(&self, req: HttpRequest, certificate: &[u8], now: u64) -> HttpResponse {
        let mut encodings: Vec<Encoding> = vec![];
        let mut etags: Vec<Hash> = vec![];
        let mut range_start: Option<usize> = None;
        for (name, value) in req.headers.iter() {
            if name.eq_ignore_ascii_case("Accept-Encoding") {
                encodings.extend(Encoding::parse_accept_encoding(value));
            } else if name.eq_ignore_ascii_case("If-None-Match") {
                etags.extend(parse_if_none_match(value));
            } else if name.eq_ignore_ascii_case("Range") {
                range_start = parse_range_start(value);
            }
        }

        let path = match req.url.find('?') {
            Some(i) => &req.url[..i],
            None => &req.url[..],
        };

        match url_decode(path) {
            Ok(path) => {
                // ---- access protection ----
                // Runs before asset/redirect resolution so an unauthenticated
                // request never reaches asset content (a public app skips this
                // entirely — `protection_login_page()` is `None`).
                if let Some(login_page) = self.protection_login_page() {
                    if path == login_page {
                        // The login surface is exempt. A POST is a login
                        // attempt (validate + Set-Cookie / 401); a GET serves the
                        // page itself, so it falls through to normal serving.
                        if req.method.eq_ignore_ascii_case("POST") {
                            return self.serve_redeem(&req, &login_page, certificate, now);
                        }
                    } else if !self.cookie_token_valid(&req, now) {
                        return self.serve_unauthenticated(&path, &login_page, certificate);
                    }
                }
                self.build_http_response(certificate, &path, encodings, etags, range_start)
            }
            // Malformed percent-encoding (invalid UTF-8 once decoded). This 400
            // is intentionally uncertified: the body is per-request (it echoes
            // the bad path), so it can't be pinned to a certified hash, and a
            // malformed URL has no certifiable response anyway. The HTTP gateway
            // rejects uncertified responses, so a browser never sees this body —
            // it surfaces only to a direct query call of `http_request` (e.g.
            // `dfx canister call`), where it serves as a diagnostic.
            Err(err) => HttpResponse {
                status_code: 400,
                headers: vec![],
                body: ByteBuf::from(format!("failed to decode path '{path}': {err}")),
                upgrade: None,
            },
        }
    }

    /// The first redirect rule (declaration order) that matches `path` and has a
    /// certified entry, or `None`. This is the shared spine of both request
    /// resolvers — the normal serve path ([`Self::build_http_response`]) and
    /// access protection ([`Self::serve_unauthenticated`]) — which each do
    /// their own thing with the match (serve it vs. serve a 307 at its location)
    /// but agree on *which* rule wins. A rule without a certified entry (shadowed
    /// by an asset, or an alias to a missing target) is skipped, exactly as
    /// serving requires — the gateway rejects a witness for an uncertified path.
    pub(crate) fn matching_rule(
        &self,
        path: &str,
    ) -> Option<(&RedirectRule, &crate::redirect::CertifiedRuleEntry)> {
        self.store
            .redirect_rules()
            .iter()
            .enumerate()
            .find_map(|(idx, rule)| {
                if !crate::redirect::matches(rule, path) {
                    return None;
                }
                let entry = self.certifier.rule_entry(idx)?;
                Some((rule, entry))
            })
    }

    fn build_http_response(
        &self,
        certificate: &[u8],
        path: &str,
        requested_encodings: Vec<Encoding>,
        etags: Vec<Hash>,
        range_start: Option<usize>,
    ) -> HttpResponse {
        // Asset at the requested path wins. A content-less asset (no encoding to
        // serve) yields `None` here and falls through to the rule scan, so a
        // wildcard rule can still cover it.
        if let Some(meta) = self.store.get_asset(&path.to_string()) {
            let cert_header = self.certifier.witness_to_header(path, certificate);
            if let Some(response) = self.build_asset_response(
                &meta,
                &requested_encodings,
                Some(&cert_header),
                &etags,
                None,
                range_start,
            ) {
                return response;
            }
        }

        // Scan redirect rules in declaration order; first certified match wins.
        if let Some((rule, entry)) = self.matching_rule(path) {
            return self.build_redirect_rule_response(
                rule,
                entry,
                path,
                certificate,
                &requested_encodings,
                &etags,
                range_start,
            );
        }

        let certificate_header = self.certifier.witness_to_header(path, certificate);
        HttpResponse::build_404(certificate_header)
    }

    /// Builds the 200/304 (or status-overridden) response for the best matching
    /// encoding of `meta`, or `None` if the asset has no encodings. Every
    /// encoding present in the metadata is certified, so encoding selection is
    /// just preference order.
    #[allow(clippy::too_many_arguments)]
    fn build_asset_response(
        &self,
        meta: &AssetMeta,
        requested_encodings: &[Encoding],
        certificate_header: Option<&HeaderField>,
        etags: &[Hash],
        status_override: Option<u16>,
        range_start: Option<usize>,
    ) -> Option<HttpResponse> {
        // A status-overridden response (a 4xx custom error page) is served as a
        // single inline body with that status — there is no way to deliver a
        // multi-chunk body under a non-200 status now that callback streaming is
        // gone and 206 reassembly always yields a 200 (see D6). So restrict those
        // to single-chunk encodings; the certify side does the same.
        let acceptable = |e: &Encoding| match status_override {
            Some(_) => meta.encodings.get(e).is_some_and(|enc| enc.num_chunks == 1),
            None => meta.encodings.contains_key(e),
        };
        // Honour the client's listed order first; if it expressed no acceptable
        // encoding, fall back to our preference order (identity-first).
        let encoding = requested_encodings
            .iter()
            .copied()
            .find(|e| acceptable(e))
            .or_else(|| {
                Encoding::PREFERENCE_ORDER
                    .into_iter()
                    .find(|e| acceptable(e))
            })?;
        let enc = meta.encodings.get(&encoding)?;
        Some(self.build_ok_http_response(
            meta,
            encoding,
            enc,
            certificate_header,
            etags,
            status_override,
            range_start,
        ))
    }

    /// Builds the response for one encoding.
    ///
    /// When `status_override` is `None` this serves the normal 200/304 path
    /// (etag-based not-modified). When it is `Some(s)` — used by redirect rules
    /// that serve a custom error page — the response always carries the body
    /// with status `s`, and the etag / 304 logic is skipped.
    #[allow(clippy::too_many_arguments)]
    fn build_ok_http_response(
        &self,
        meta: &AssetMeta,
        encoding: Encoding,
        enc: &EncodingMeta,
        certificate_header: Option<&HeaderField>,
        etags: &[Hash],
        status_override: Option<u16>,
        range_start: Option<usize>,
    ) -> HttpResponse {
        // Serve multi-chunk encodings as certified 206s. A plain GET (no Range)
        // returns chunk 0 — that is what drives the gateway's Flow B reassembly
        // into a full 200. A Range request returns the containing chunk (start
        // snapped down to the chunk boundary). Conditional (304) and
        // status-override (4xx error-page) responses keep their normal path; the
        // latter only ever reaches here with a single-chunk encoding.
        if status_override.is_none() && !etags.contains(&enc.sha256) && enc.num_chunks > 1 {
            let start = range_start.unwrap_or(0);
            if let Some(response) =
                self.build_range_response(meta, encoding, enc, start, certificate_header)
            {
                return response;
            }
        }

        let mut headers = headers_for(
            &self.certifier.effective_headers(&self.store, meta),
            &meta.content_type,
            encoding,
            &enc.sha256,
        );
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }

        // Reaching here means a single-chunk body — multi-chunk 200s are served as
        // 206 above, and multi-chunk 4xx error pages are filtered out in
        // `build_asset_response` — so the whole body is chunk 0. The
        // canister-managed `etag` header is already in `headers` (and certified),
        // so both the 200 and the 304 carry it.
        let (status_code, body) = if let Some(status) = status_override {
            (
                status,
                ByteBuf::from(self.store.read_chunk(enc.content_id, 0)),
            )
        } else if etags.contains(&enc.sha256) {
            // Conditional request matched: serve the certified 304 (empty body).
            (304, ByteBuf::new())
        } else {
            (200, ByteBuf::from(self.store.read_chunk(enc.content_id, 0)))
        };

        HttpResponse {
            status_code,
            headers,
            body,
            upgrade: None,
        }
    }

    /// Build a certified 206 for the chunk containing byte `start` (snapped down
    /// to the chunk boundary). Returns `None` (caller falls back to the normal 200
    /// path) when the encoding is empty or `start` is past the end.
    ///
    /// Lean: locates the target chunk by scanning `chunk_certs` (tiny fixed
    /// entries, early exit), then reads only that one chunk's bytes.
    fn build_range_response(
        &self,
        meta: &AssetMeta,
        encoding: Encoding,
        enc: &EncodingMeta,
        start: usize,
        certificate_header: Option<&HeaderField>,
    ) -> Option<HttpResponse> {
        let total = enc.content_len as usize;
        if total == 0 {
            return None;
        }
        // An out-of-range start (no byte to satisfy) is treated as "ignore the
        // Range": serve chunk 0, which the gateway reassembles into the full 200.
        // Returning `None` here would instead fall through to a plain 200 carrying
        // only chunk 0 — a truncated body for a multi-chunk asset.
        let start = if start >= total { 0 } else { start };
        // Find the chunk whose [offset, offset+len) contains `start`.
        let mut offset = 0usize;
        let mut target: Option<(u32, usize, usize)> = None; // (chunk_index, chunk_start, len)
        for (chunk_index, cc) in self.store.chunk_certs_of(enc.content_id) {
            let len = cc.len as usize;
            if start < offset + len {
                target = Some((chunk_index, offset, len));
                break;
            }
            offset += len;
        }
        let (chunk_index, chunk_start, len) = target?;

        let chunk = self.store.read_chunk(enc.content_id, chunk_index);
        let content_range = format!("bytes {}-{}/{}", chunk_start, chunk_start + len - 1, total);
        let mut headers = range_headers_for(
            &self.certifier.effective_headers(&self.store, meta),
            &meta.content_type,
            encoding,
            &enc.sha256,
            &content_range,
        );
        if let Some(head) = certificate_header {
            headers.push((head.0.clone(), head.1.clone()));
        }
        Some(HttpResponse {
            status_code: 206,
            headers,
            body: ByteBuf::from(chunk),
            upgrade: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_redirect_rule_response(
        &self,
        rule: &RedirectRule,
        entry: &crate::redirect::CertifiedRuleEntry,
        path: &str,
        certificate: &[u8],
        requested_encodings: &[Encoding],
        etags: &[Hash],
        range_start: Option<usize>,
    ) -> HttpResponse {
        let cert_header =
            self.certifier
                .witness_to_header_with_location(path, &entry.location, certificate);
        match &entry.kind {
            crate::redirect::CertifiedRuleEntryKind::Synthetic { expression } => {
                // Synthetic entries only cover 3xx redirects — empty body.
                let cert_expr_header =
                    crate::cert::build_ic_certificate_expression_header(expression);
                let mut headers = crate::redirect::certified_headers(rule);
                headers.push((cert_expr_header.0, cert_expr_header.1));
                headers.push(cert_header);

                HttpResponse {
                    status_code: rule.status,
                    headers,
                    body: ByteBuf::new(),
                    upgrade: None,
                }
            }
            crate::redirect::CertifiedRuleEntryKind::AliasOf { target_key, status } => {
                let Some(meta) = self.store.get_asset(target_key) else {
                    return HttpResponse::build_404(cert_header);
                };
                let status_override = (*status != 200).then_some(*status);
                self.build_asset_response(
                    &meta,
                    requested_encodings,
                    Some(&cert_header),
                    etags,
                    status_override,
                    range_start,
                )
                .unwrap_or_else(|| HttpResponse::build_404(cert_header))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{url_decode, UrlDecodeError};

    #[test]
    fn check_url_decode() {
        assert_eq!(url_decode("/%"), Ok("/%".to_string()));
        assert_eq!(url_decode("/%%"), Ok("/%%".to_string()));
        assert_eq!(url_decode("/%e%"), Ok("/%e%".to_string()));

        assert_eq!(url_decode("/%20%a"), Ok("/ %a".to_string()));
        assert_eq!(url_decode("/%%+a%20+%@"), Ok("/%%+a +%@".to_string()));
        assert_eq!(
            url_decode("/has%percent.txt"),
            Ok("/has%percent.txt".to_string())
        );

        assert_eq!(url_decode("/%%2"), Ok("/%%2".to_string()));
        assert_eq!(url_decode("/%C3%A6"), Ok("/æ".to_string()));
        assert_eq!(url_decode("/%c3%a6"), Ok("/æ".to_string()));

        assert_eq!(url_decode("/a+b+c%20d"), Ok("/a+b+c d".to_string()));

        assert_eq!(
            url_decode("/capture-d%E2%80%99e%CC%81cran-2023-10-26-a%CC%80.txt"),
            // `%CC%81`/`%CC%80` are combining acute/grave, so the decoded form is
            // NFD (base letter + combining mark), written here as explicit escapes.
            Ok("/capture-d\u{2019}e\u{301}cran-2023-10-26-a\u{300}.txt".to_string())
        );

        assert_eq!(
            url_decode("/%FF%FF"),
            Err(UrlDecodeError::InvalidPercentEncoding)
        );
    }
}
