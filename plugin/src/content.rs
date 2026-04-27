//! Loading and encoding asset content.
//!
//! Mirrors `ic-asset`'s `asset/content.rs` and `asset/content_encoder.rs`.

use mime::Mime;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoder {
    Identity,
    Gzip,
    #[allow(dead_code)]
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
