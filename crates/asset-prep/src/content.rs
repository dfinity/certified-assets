//! Loading asset content and deciding whether it is worth compressing.
//!
//! *How* content is compressed is not here — it comes from the caller's
//! [`Compressors`](crate::compressors::Compressors) registry. This module only
//! reads bytes, resolves a media type, and answers whether a compressor should be
//! offered the asset at all.

use mime::Mime;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Content {
    pub data: Vec<u8>,
    pub media_type: Mime,
}

impl Content {
    pub fn load(path: &Path) -> Result<Content, String> {
        let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let media_type = mime_guess::from_path(path)
            .first()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
        Ok(Content { data, media_type })
    }

    pub fn sha256(&self) -> Vec<u8> {
        Sha256::digest(&self.data).to_vec()
    }
}

/// Whether content of this media type is worth compressing.
///
/// This is the *policy* half of encoding selection and stays fixed here; the
/// caller chooses which compressors exist, not which media types they apply to.
/// A compressible asset is offered to every compressor the caller set; whether
/// the result is kept is decided afterwards by a size check against identity —
/// see `PlannedAsset::encode`.
///
/// Compressible:
/// - all `text/*` (html, css, plain, markdown, csv, …);
/// - JavaScript and WebAssembly;
/// - structured types with a `+json` / `+xml` suffix — this one rule catches
///   `image/svg+xml`, `application/xhtml+xml`, `application/rss+xml`, etc. —
///   plus the bare `application/json` / `application/xml`;
/// - uncompressed font containers (`font/ttf`, `font/otf`, `.eot`).
///
/// Already-compressed formats are left alone: images/audio/video, archives, and
/// `font/woff` + `font/woff2` (which embed their own compression — `woff2` is
/// itself Brotli, so re-compressing only wastes space and CPU).
pub fn is_compressible(media_type: &Mime) -> bool {
    let ty = media_type.type_();
    let subtype = media_type.subtype();

    if ty == mime::TEXT {
        return true;
    }
    if ty == mime::FONT {
        return !matches!(subtype.as_str(), "woff" | "woff2");
    }
    if let Some(suffix) = media_type.suffix()
        && (suffix == mime::JSON || suffix == mime::XML)
    {
        return true;
    }
    subtype == mime::JAVASCRIPT
        || subtype == mime::JSON
        || subtype == mime::XML
        || matches!(subtype.as_str(), "wasm" | "vnd.ms-fontobject")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_compressible ---

    fn mime_of(s: &str) -> Mime {
        s.parse().unwrap()
    }

    #[test]
    fn compressible_types() {
        for s in [
            "text/html",
            "text/css",
            "text/plain",
            "text/markdown",
            "application/javascript",
            "text/javascript",
            "application/json",
            "application/vnd.api+json",
            "application/xml",
            "text/xml",
            "image/svg+xml",
            "application/xhtml+xml",
            "application/rss+xml",
            "application/wasm",
            "font/ttf",
            "font/otf",
            "application/vnd.ms-fontobject",
        ] {
            assert!(is_compressible(&mime_of(s)), "{s} should be compressible");
        }
    }

    #[test]
    fn incompressible_types() {
        for s in [
            "image/png",
            "image/jpeg",
            "image/webp",
            "video/mp4",
            "audio/mpeg",
            "font/woff",
            "font/woff2",
            "application/zip",
            "application/octet-stream",
        ] {
            assert!(
                !is_compressible(&mime_of(s)),
                "{s} should NOT be compressible"
            );
        }
    }

    // --- sha256 ---

    fn content(data: &[u8]) -> Content {
        Content {
            data: data.to_vec(),
            media_type: mime::TEXT_PLAIN,
        }
    }

    #[test]
    fn sha256_deterministic() {
        let c = content(b"same input");
        assert_eq!(c.sha256(), c.sha256());
    }

    #[test]
    fn sha256_differs_for_different_content() {
        assert_ne!(content(b"aaa").sha256(), content(b"bbb").sha256());
    }

    // --- Content::load ---

    #[test]
    fn load_reads_bytes_and_infers_html_mime() {
        use std::io::Write;
        let mut f = tempfile::Builder::new().suffix(".html").tempfile().unwrap();
        f.write_all(b"<html></html>").unwrap();
        let c = Content::load(f.path()).unwrap();
        assert_eq!(c.data, b"<html></html>");
        assert_eq!(c.media_type.type_(), mime::TEXT);
        assert_eq!(c.media_type.subtype(), mime::HTML);
    }

    #[test]
    fn load_infers_png_mime() {
        use std::io::Write;
        let mut f = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        f.write_all(b"\x00").unwrap();
        let c = Content::load(f.path()).unwrap();
        assert_eq!(c.media_type.type_(), mime::IMAGE);
        assert_eq!(c.media_type.subtype(), mime::PNG);
    }

    #[test]
    fn load_unknown_extension_falls_back_to_octet_stream() {
        use std::io::Write;
        let mut f = tempfile::Builder::new()
            .suffix(".xyz123unknown")
            .tempfile()
            .unwrap();
        f.write_all(b"binary data").unwrap();
        let c = Content::load(f.path()).unwrap();
        assert_eq!(c.media_type, mime::APPLICATION_OCTET_STREAM);
    }
}
