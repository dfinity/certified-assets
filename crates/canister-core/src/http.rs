use crate::certification::{
    build_ic_certificate_expression_from_headers, build_ic_certificate_expression_header,
};
use crate::rc_bytes::RcBytes;
use candid::{define_function, CandidType, Deserialize, Nat};
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
    pub key: String,
    pub content_encoding: String,
    pub index: Nat,
    // We don't care about the sha, we just want to be backward compatible.
    pub sha256: Option<ByteBuf>,
}

define_function!(pub CallbackFunc : (StreamingCallbackToken) -> (Option<StreamingCallbackHttpResponse>) query);
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
    pub fn create_token(
        enc_name: &str,
        content_chunks_count: usize,
        content_sha256: [u8; 32],
        key: &str,
        chunk_index: usize,
    ) -> Option<Self> {
        if chunk_index + 1 >= content_chunks_count {
            None
        } else {
            Some(StreamingCallbackToken {
                key: key.to_string(),
                content_encoding: enc_name.to_string(),
                index: Nat::from(chunk_index + 1),
                sha256: Some(ByteBuf::from(content_sha256)),
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
    pub fn build_400(err_msg: &str) -> Self {
        HttpResponse {
            status_code: 400,
            headers: vec![],
            body: RcBytes::from(ByteBuf::from(err_msg)),
            upgrade: None,
            streaming_strategy: None,
        }
    }

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
