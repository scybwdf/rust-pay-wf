use crate::config::WechatConfig;
use crate::errors::PayError;
use crate::utils::{aes_gcm_decrypt, rsa_verify_sha256_pem};
use crate::wechat::certs::PlatformCerts;
use std::collections::HashMap;
use std::sync::Arc;
pub struct WechatNotify {
    cfg: Arc<WechatConfig>,
    certs: Arc<PlatformCerts>,
}
impl WechatNotify {
    pub fn new(cfg: Arc<WechatConfig>, certs: Arc<PlatformCerts>) -> Self {
        Self { cfg, certs }
    }
    pub async fn verify_and_decrypt(
        &self,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Result<serde_json::Value, PayError> {
        println!("headers: {:?}", headers);
        let ts = headers
            .get("wechatpay-timestamp")
            .map(String::as_str)
            .unwrap_or("");
        let nonce = headers
            .get("wechatpay-nonce")
            .map(String::as_str)
            .unwrap_or("");
        let signature = headers
            .get("wechatpay-signature")
            .map(String::as_str)
            .unwrap_or("");
        let serial = headers
            .get("wechatpay-serial")
            .map(String::as_str)
            .unwrap_or("");
        let msg = format!("{}\n{}\n{}\n", ts, nonce, body);
        // 1️⃣ 优先从缓存拿
        let mut pub_pem = self.certs.get_by_serial(serial);

        // 2️⃣ 如果没有，就尝试 refresh 一次再取
        if pub_pem.is_none() {
            if let Err(e) = self.certs.refresh().await {
                return Err(PayError::Crypto(format!("refresh certs failed: {}", e)));
            }
            pub_pem = self.certs.get_by_serial(serial);
        }
        // 3️⃣ 还是没有，就报错
        let pub_pem = pub_pem.ok_or_else(|| {
            PayError::Other(format!("platform cert {} not found after refresh", serial))
        })?;
        println!("pub_pem: {:?}", pub_pem);
        if pub_pem.is_empty() {
            return Err(PayError::Other(
                "wechat notify platform public key empty".to_string(),
            ));
        }
        let ok = rsa_verify_sha256_pem(&pub_pem, &msg, signature)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        if !ok {
            return Err(PayError::Other(
                "wechat notify invalid signature".to_string(),
            ));
        }
        let v: serde_json::Value = serde_json::from_str(body).map_err(|e| PayError::Json(e))?;
        if let Some(resource) = v.get("resource") {
            let ad = resource
                .get("associated_data")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let nonce_r = resource.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
            let ciphertext = resource
                .get("ciphertext")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let plain = aes_gcm_decrypt(&self.cfg.api_v3_key, ad, nonce_r, ciphertext)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;
            let pj: serde_json::Value =
                serde_json::from_str(&plain).map_err(|e| PayError::Json(e))?;
            return Ok(pj);
        }
        Ok(v)
    }
}
