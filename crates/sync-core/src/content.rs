//! Loading and encoding asset content.
//!
//! Mirrors `ic-asset`'s `asset/content.rs` and `asset/content_encoder.rs`.

use mime::Mime;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use wire_types::Encoding;

#[derive(Clone)]
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

    pub fn encode(&self, encoding: Encoding) -> Result<Content, String> {
        match encoding {
            Encoding::Identity => Ok(self.clone()),
            Encoding::Gzip => {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(&self.data).map_err(|e| format!("gzip: {e}"))?;
                let data = e.finish().map_err(|e| format!("gzip finish: {e}"))?;
                Ok(Content {
                    data,
                    media_type: self.media_type.clone(),
                })
            }
            Encoding::Brotli => {
                let mut compressed = Vec::new();
                {
                    let mut w = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
                    w.write_all(&self.data)
                        .map_err(|e| format!("brotli: {e}"))?;
                    w.flush().map_err(|e| format!("brotli flush: {e}"))?;
                }
                Ok(Content {
                    data: compressed,
                    media_type: self.media_type.clone(),
                })
            }
        }
    }

    pub fn sha256(&self) -> Vec<u8> {
        Sha256::digest(&self.data).to_vec()
    }
}

/// Whether content of this media type is worth compressing.
///
/// We deliberately support a small, curated set of encodings (Identity, Gzip,
/// Brotli) rather than the full IANA list — trading a little bandwidth for
/// implementation simplicity and bounded canister storage. Compressible:
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
    if let Some(suffix) = media_type.suffix() {
        if suffix == mime::JSON || suffix == mime::XML {
            return true;
        }
    }
    subtype == mime::JAVASCRIPT
        || subtype == mime::JSON
        || subtype == mime::XML
        || matches!(subtype.as_str(), "wasm" | "vnd.ms-fontobject")
}

/// The encodings to *attempt* for a given media type: every compressible asset
/// gets Brotli and Gzip alongside the always-present uncompressed Identity copy;
/// everything else is stored as Identity only. Whether a produced compressed
/// encoding is actually kept is decided afterwards by a size check against
/// Identity — see `prepare_content_asset`.
pub fn encoders_for(media_type: &Mime) -> Vec<Encoding> {
    if is_compressible(media_type) {
        vec![Encoding::Identity, Encoding::Gzip, Encoding::Brotli]
    } else {
        vec![Encoding::Identity]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn content(data: &[u8]) -> Content {
        Content {
            data: data.to_vec(),
            media_type: mime::TEXT_PLAIN,
        }
    }

    // --- is_compressible / encoders_for ---

    fn mime_of(s: &str) -> Mime {
        s.parse().unwrap()
    }

    const ALL_THREE: [Encoding; 3] = [Encoding::Identity, Encoding::Gzip, Encoding::Brotli];

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
            let m = mime_of(s);
            assert!(is_compressible(&m), "{s} should be compressible");
            assert_eq!(encoders_for(&m), ALL_THREE.to_vec(), "{s}");
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
            let m = mime_of(s);
            assert!(!is_compressible(&m), "{s} should NOT be compressible");
            assert_eq!(encoders_for(&m), vec![Encoding::Identity], "{s}");
        }
    }

    // --- encode ---

    #[test]
    fn encode_identity_passthrough() {
        let c = content(b"hello world");
        let out = c.encode(Encoding::Identity).unwrap();
        assert_eq!(out.data, b"hello world");
    }

    #[test]
    fn encode_gzip_round_trip() {
        use flate2::read::GzDecoder;

        let original = b"hello gzip world, hello gzip world";
        let c = content(original);
        let compressed = c.encode(Encoding::Gzip).unwrap();

        let mut decoder = GzDecoder::new(compressed.data.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn encode_brotli_round_trip() {
        let original = b"hello brotli world, hello brotli world";
        let c = content(original);
        let compressed = c.encode(Encoding::Brotli).unwrap();

        let mut decompressed = Vec::new();
        brotli::Decompressor::new(compressed.data.as_slice(), 4096)
            .read_to_end(&mut decompressed)
            .unwrap();
        assert_eq!(decompressed, original);
    }

    // --- sha256 ---

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
