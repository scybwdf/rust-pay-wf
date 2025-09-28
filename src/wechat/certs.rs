use crate::config::WechatConfig;
use crate::utils::{
    aes_gcm_decrypt, extract_pubkey_from_cert, gen_nonce, now_ts, retry_async, rsa_sign_sha256_pem,
};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use url::Url;
pub struct PlatformCerts {
    pub map: Arc<Mutex<HashMap<String, String>>>,
    client: Client,
    cfg: Arc<WechatConfig>,
}
impl PlatformCerts {
    pub fn new(cfg: Arc<WechatConfig>) -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
            client: Client::new(),
            cfg,
        }
    }
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let url = "https://api.mch.weixin.qq.com/v3/certificates";
        let ts = now_ts();
        let nonce = gen_nonce(32);
        let method = "GET";
        let parsed = Url::parse(url)?;
        let path = if let Some(query) = parsed.query() {
            format!("{}?{}", parsed.path(), query)
        } else {
            parsed.path().to_string()
        };
        let sign_str = format!("{}\n{}\n{}\n{}\n\n", method, path, ts, nonce);
        let signature = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_str)?;
        let auth = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}""#,
            self.cfg.mchid, nonce, ts, self.cfg.serial_no, signature
        );
        let client = &self.client;
        let txt = retry_async(3, || async {
            let r = client
                .get(url)
                .header("Authorization", auth.clone())
                .header("Accept", "application/json")
                .header("User-Agent", "rust_pay_wf")
                .send()
                .await?;
            Ok::<String, reqwest::Error>(r.text().await?)
        })
        .await?;
        println!("[refresh]  body={}", txt);
        let v: Value = serde_json::from_str(&txt)?;
        if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
            let mut m = self.map.lock().unwrap();
            m.clear();
            for cert in arr {
                if let (Some(serial), Some(resource)) =
                    (cert.get("serial_no"), cert.get("encrypt_certificate"))
                {
                    let cipher = resource
                        .get("ciphertext")
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    let nonce_r = resource.get("nonce").and_then(|c| c.as_str()).unwrap_or("");
                    let aad = resource
                        .get("associated_data")
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    let pem = aes_gcm_decrypt(&self.cfg.api_v3_key, aad, nonce_r, cipher)?;
                    let pub_pem = extract_pubkey_from_cert(&pem)?; // 提取公钥
                    println!("[refresh] store cert serial={} pub_pem={}", serial.as_str().unwrap_or_default().to_string(), pub_pem);
                    m.insert(serial.as_str().unwrap_or_default().to_string(), pub_pem);
                }
            }
        }
        Ok(())
    }
    pub fn get_by_serial(&self, serial: &str) -> Option<String> {
        let m = self.map.lock().unwrap();
        m.get(serial).cloned()
    }
}
