//! Loading and encoding asset content.
//!
//! Mirrors `ic-asset`'s `asset/content.rs` and `asset/content_encoder.rs`.

use mime::Mime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoder {
    Identity,
    Gzip,
    /// Serialized as `"brotli"`; also accepted as `"br"` for compatibility.
    #[serde(alias = "br")]
    Brotli,
}

impl Encoder {
    pub fn name(&self) -> &'static str {
        match self {
            Encoder::Identity => "identity",
            Encoder::Gzip => "gzip",
            Encoder::Brotli => "br",
        }
    }
}

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

    pub fn encode(&self, encoder: Encoder) -> Result<Content, String> {
        match encoder {
            Encoder::Identity => Ok(self.clone()),
            Encoder::Gzip => {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(&self.data).map_err(|e| format!("gzip: {e}"))?;
                let data = e.finish().map_err(|e| format!("gzip finish: {e}"))?;
                Ok(Content {
                    data,
                    media_type: self.media_type.clone(),
                })
            }
            Encoder::Brotli => {
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

/// Returns the encoders to apply for a given media type, matching `ic-asset`'s policy.
pub fn encoders_for(media_type: &Mime) -> Vec<Encoder> {
    match (media_type.type_(), media_type.subtype()) {
        (mime::TEXT, _) | (_, mime::JAVASCRIPT) | (_, mime::HTML) => {
            vec![Encoder::Identity, Encoder::Gzip]
        }
        _ => vec![Encoder::Identity],
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

    // --- encoders_for ---

    #[test]
    fn encoders_for_text_html() {
        let mime: Mime = "text/html".parse().unwrap();
        assert_eq!(encoders_for(&mime), vec![Encoder::Identity, Encoder::Gzip]);
    }

    #[test]
    fn encoders_for_text_css() {
        let mime: Mime = "text/css".parse().unwrap();
        assert_eq!(encoders_for(&mime), vec![Encoder::Identity, Encoder::Gzip]);
    }

    #[test]
    fn encoders_for_application_javascript() {
        let mime: Mime = "application/javascript".parse().unwrap();
        assert_eq!(encoders_for(&mime), vec![Encoder::Identity, Encoder::Gzip]);
    }

    #[test]
    fn encoders_for_text_javascript() {
        let mime: Mime = "text/javascript".parse().unwrap();
        assert_eq!(encoders_for(&mime), vec![Encoder::Identity, Encoder::Gzip]);
    }

    #[test]
    fn encoders_for_image_png() {
        let mime: Mime = "image/png".parse().unwrap();
        assert_eq!(encoders_for(&mime), vec![Encoder::Identity]);
    }

    #[test]
    fn encoders_for_application_wasm() {
        let mime: Mime = "application/wasm".parse().unwrap();
        assert_eq!(encoders_for(&mime), vec![Encoder::Identity]);
    }

    #[test]
    fn encoders_for_unknown_uses_octet_stream() {
        assert_eq!(
            encoders_for(&mime::APPLICATION_OCTET_STREAM),
            vec![Encoder::Identity]
        );
    }

    // --- encode ---

    #[test]
    fn encode_identity_passthrough() {
        let c = content(b"hello world");
        let out = c.encode(Encoder::Identity).unwrap();
        assert_eq!(out.data, b"hello world");
    }

    #[test]
    fn encode_gzip_round_trip() {
        use flate2::read::GzDecoder;

        let original = b"hello gzip world, hello gzip world";
        let c = content(original);
        let compressed = c.encode(Encoder::Gzip).unwrap();

        let mut decoder = GzDecoder::new(compressed.data.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn encode_brotli_round_trip() {
        let original = b"hello brotli world, hello brotli world";
        let c = content(original);
        let compressed = c.encode(Encoder::Brotli).unwrap();

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
