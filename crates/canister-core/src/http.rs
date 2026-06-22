use crate::certification::{
    build_ic_certificate_expression_from_headers, build_ic_certificate_expression_header,
};
use crate::rc_bytes::RcBytes;
use candid::{define_function, CandidType, Deserialize};
use serde_bytes::ByteBuf;

pub type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    pub body: ByteBuf,
    pub certificate_version: Option<u16>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: RcBytes,
    pub upgrade: Option<bool>,
    pub streaming_strategy: Option<StreamingStrategy>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StreamingCallbackToken {
    /// Content group to stream from. Carrying it lets the streaming callback
    /// read chunks straight from the content store, with no `AssetMeta`
    /// lookup/decode per chunk — the token is fully self-describing.
    pub content_id: u64,
    /// Index of the chunk this token requests.
    pub index: u32,
    /// Total chunks in the content group; the callback emits a follow-on token
    /// while `index + 1 < num_chunks`.
    pub num_chunks: u32,
    /// Full-asset hash, carried for the HTTP gateway's streamed-response check.
    pub sha256: ByteBuf,
}

define_function!(pub CallbackFunc : (StreamingCallbackToken) -> (StreamingCallbackHttpResponse) query);
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum StreamingStrategy {
    Callback {
        callback: CallbackFunc,
        token: StreamingCallbackToken,
    },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse {
    pub body: RcBytes,
    pub token: Option<StreamingCallbackToken>,
}

impl StreamingCallbackToken {
    /// Builds the token for the chunk *after* `chunk_index`, or `None` when
    /// `chunk_index` is the last chunk. Self-contained: it carries
    /// `content_id`/`num_chunks`/`sha256` so the streaming callback can serve
    /// the next chunk without ever reloading the asset's `AssetMeta`.
    pub fn create_token(
        content_id: u64,
        num_chunks: u32,
        sha256: ByteBuf,
        chunk_index: usize,
    ) -> Option<Self> {
        let next_index = chunk_index + 1;
        if next_index >= num_chunks as usize {
            None
        } else {
            Some(StreamingCallbackToken {
                content_id,
                index: next_index as u32,
                num_chunks,
                sha256,
            })
        }
    }
}

impl HttpRequest {
    pub fn get_path(&self) -> &str {
        match self.url.find('?') {
            Some(i) => &self.url[..i],
            None => &self.url[..],
        }
    }
}

impl HttpResponse {
    pub fn build_404(certificate_header: HeaderField) -> HttpResponse {
        let base_404 = Self::uncertified_404();
        let mut headers = base_404.headers.clone();
        headers.push(certificate_header);
        let certificate_expression =
            build_ic_certificate_expression_from_headers(&base_404.headers);
        let cert_expr_header = build_ic_certificate_expression_header(&certificate_expression);
        headers.push(cert_expr_header);
        HttpResponse {
            headers,
            ..base_404
        }
    }

    pub fn uncertified_404() -> HttpResponse {
        HttpResponse {
            status_code: 404,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: RcBytes::from(ByteBuf::from("not found")),
            upgrade: None,
            streaming_strategy: None,
        }
    }
}
