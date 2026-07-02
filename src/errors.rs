use thiserror::Error;
#[derive(Error, Debug)]
pub enum PayError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("other: {0}")]
    Other(String),
    #[error("Alipay API error: {code} - {msg}")]
    Alipay { code: String, msg: String },
}

impl PayError {
    pub fn from_alipay_response(response: &serde_json::Value) -> Self {
        let code = response.get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();
        let msg = response.get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .to_string();

        PayError::Alipay { code, msg }
    }
}