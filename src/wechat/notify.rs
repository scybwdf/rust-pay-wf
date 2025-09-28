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
    pub fn verify_and_decrypt(
        &self,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Result<serde_json::Value, PayError> {
        println!("headers: {:?}", headers);
        let ts = headers
            .get("Wechatpay-Timestamp")
            .map(String::as_str)
            .unwrap_or("");
        let nonce = headers
            .get("Wechatpay-Nonce")
            .map(String::as_str)
            .unwrap_or("");
        let signature = headers
            .get("Wechatpay-Signature")
            .map(String::as_str)
            .unwrap_or("");
        let serial = headers
            .get("Wechatpay-Serial")
            .map(String::as_str)
            .unwrap_or("");
        let msg = format!("{}\n{}\n{}\n", ts, nonce, body);
        /*     let pub_pem = self
        .certs
        .get_by_serial(serial)
        .ok_or(PayError::Other(format!(
            "platform cert {} not found",
            serial
        )))?;*/
        let pub_pem = if let Some(get_pub_pem) = self.certs.get_by_serial(serial) {
            get_pub_pem
        } else {
            self.cfg.platform_public_key_pem.clone().unwrap_or_default()
        };
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
