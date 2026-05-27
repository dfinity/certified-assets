use crate::certification::{
    build_ic_certificate_expression_from_headers, build_ic_certificate_expression_header,
};
use crate::rc_bytes::RcBytes;
use candid::{define_function, CandidType, Deserialize, Nat};
use serde_bytes::ByteBuf;

/// The file to serve if the requested file wasn't found.
pub const FALLBACK_FILE: &str = "/index.html";

const HTTP_REDIRECT_PERMANENT: u16 = 308;

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

    pub fn get_header_value(&self, header_key: &str) -> Option<&String> {
        self.headers
            .iter()
            .find_map(|(k, v)| k.eq_ignore_ascii_case(header_key).then_some(v))
    }

    pub fn redirect_from_raw_to_certified_domain(&self) -> HttpResponse {
        #[cfg(not(test))]
        let canister_id = ic_cdk::api::canister_self().to_text();
        #[cfg(test)]
        let canister_id = self.get_canister_id();

        let location = match self.get_header_value("Host") {
            Some(host_header) if host_header.ends_with("ic0.app") => {
                format!("https://{canister_id}.ic0.app{path}", path = self.url)
            }
            _ => format!("https://{canister_id}.icp0.io{path}", path = self.url),
        };
        HttpResponse::build_redirect(HTTP_REDIRECT_PERMANENT, location)
    }

    #[cfg(test)]
    pub fn get_canister_id(&self) -> &str {
        if let Some(host_header) = self.get_header_value("Host") {
            if host_header.contains(".localhost")
                || host_header.contains(".io")
                || host_header.contains(".app")
            {
                return host_header.split('.').next().unwrap();
            } else if let Some(t) = self.url.split("canisterId=").nth(1) {
                let x = t.split_once('&');
                if let Some(c) = x {
                    return c.0;
                }
            }
        }
        unreachable!()
    }

    pub fn is_raw_domain(&self) -> bool {
        if let Some(host_header) = self.get_header_value("Host") {
            host_header.contains(".raw.ic")
        } else {
            false
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

    pub fn build_redirect(status_code: u16, location: String) -> HttpResponse {
        HttpResponse {
            status_code,
            headers: vec![("Location".to_string(), location)],
            body: RcBytes::from(ByteBuf::default()),
            upgrade: None,
            streaming_strategy: None,
        }
    }
}
