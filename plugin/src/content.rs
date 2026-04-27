//! Loading and encoding asset content.
//!
//! Mirrors `ic-asset`'s `asset/content.rs` and `asset/content_encoder.rs`.

use mime::Mime;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentEncoder {
    Identity,
    Gzip,
    #[allow(dead_code)]
    Brotli,
}

impl ContentEncoder {
    pub fn name(&self) -> &'static str {
        match self {
            ContentEncoder::Identity => "identity",
            ContentEncoder::Gzip => "gzip",
            ContentEncoder::Brotli => "br",
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

    pub fn encode(&self, encoder: ContentEncoder) -> Result<Content, String> {
        match encoder {
            ContentEncoder::Identity => Ok(self.clone()),
            ContentEncoder::Gzip => {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(&self.data).map_err(|e| format!("gzip: {e}"))?;
                let data = e.finish().map_err(|e| format!("gzip finish: {e}"))?;
                Ok(Content {
                    data,
                    media_type: self.media_type.clone(),
                })
            }
            ContentEncoder::Brotli => {
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

/// Default encoders for a media type. Matches `ic-asset`'s policy.
pub fn default_encoders(media_type: &Mime) -> Vec<ContentEncoder> {
    match (media_type.type_(), media_type.subtype()) {
        (mime::TEXT, _) | (_, mime::JAVASCRIPT) | (_, mime::HTML) => {
            vec![ContentEncoder::Identity, ContentEncoder::Gzip]
        }
        _ => vec![ContentEncoder::Identity],
    }
}
