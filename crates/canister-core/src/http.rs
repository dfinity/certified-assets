use crate::cert::{
    build_ic_certificate_expression_from_headers, build_ic_certificate_expression_header,
};
use candid::{CandidType, Deserialize};
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
    pub body: ByteBuf,
    pub upgrade: Option<bool>,
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
            body: ByteBuf::from("not found"),
            upgrade: None,
        }
    }
}
