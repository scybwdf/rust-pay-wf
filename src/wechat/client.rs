use crate::config::{Mode, WechatConfig};
use crate::errors::PayError;
use crate::utils::{gen_nonce, now_ts, rsa_sign_sha256_pem};
use crate::wechat::certs::PlatformCerts;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use url::Url;

pub struct WechatClient {
    cfg: Arc<WechatConfig>,
    http: Client,
    certs: Arc<PlatformCerts>,
    base_url: String,
    mode: Mode,
    //timeout_ms: u64,
    max_retries: usize,
}

impl WechatClient {
    pub fn with_mode(cfg: Arc<WechatConfig>, mode: Mode) -> Self {
        let http = Client::builder()
            .user_agent("ysp-rust-pay/0.1")
            .build()
            .expect("client");
        let certs = Arc::new(PlatformCerts::new(cfg.clone()));
        let base_url = match mode {
            Mode::Sandbox => "https://api.mch.weixin.qq.com/sandboxnew".to_string(),
            _ => "https://api.mch.weixin.qq.com".to_string(),
        };
        Self {
            cfg,
            http,
            certs,
            base_url,
            mode,
           // timeout_ms: 10000,
            max_retries: 3,
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn mp(&self, mut order: Value) -> Result<Value, PayError> {
        if !order.get("appid").is_some() {
            if let Some(appid) = &self.cfg.appid_mp {
                order["appid"] = json!(appid.clone());
            }
        }
        if let Mode::Service = self.mode {
            if !order.get("sub_mchid").is_some() {
                if let Some(sub) = &self.cfg.sub_mchid {
                    order["sub_mchid"] = json!(sub.clone());
                }
            }
            if !order.get("appid").is_some() {
                if let Some(subapp) = &self.cfg.sub_appid {
                    order["appid"] = json!(subapp.clone());
                }
            }
        }
        let body = json!({
            "mchid": self.cfg.mchid,
            "appid": order.get("appid").and_then(|v| v.as_str()).unwrap_or(""),
            "description": order.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            "out_trade_no": order.get("out_trade_no").and_then(|v| v.as_str()).unwrap_or(""),
            "notify_url": order.get("notify_url").and_then(|v| v.as_str()).unwrap_or(""),
            "amount": order.get("amount").cloned().unwrap_or(json!({"total":1})),
            "payer": order.get("payer").cloned().unwrap_or(json!({}))
        });
        let url = self.endpoint("/v3/pay/transactions/jsapi");
        let resp = self.sign_and_post("POST", &url, &body).await?;
        if let Some(prepay_id) = resp.get("prepay_id").and_then(|v| v.as_str()) {
            let time_stamp = now_ts();
            let nonce_str = gen_nonce(32);
            let package = format!("prepay_id={}", prepay_id);
            let sign_src = format!(
                "{}\n{}\n{}\n{}\n",
                resp.get("appid").and_then(|v| v.as_str()).unwrap_or(""),
                &self.cfg.mchid,
                &package,
                &time_stamp
            );
            let pay_sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;
            return Ok(
                json!({"appId": resp.get("appid").and_then(|v| v.as_str()).unwrap_or(""), "timeStamp": time_stamp, "nonceStr": nonce_str, "package": package, "signType": "RSA", "paySign": pay_sign }),
            );
        }
        Ok(resp)
    }

    pub async fn mini(&self, mut order: Value) -> Result<Value, PayError> {
        if !order.get("appid").is_some() {
            if let Some(appid) = &self.cfg.appid_mini {
                order["appid"] = json!(appid.clone());
            }
        }
        if let Mode::Service = self.mode {
            if !order.get("sub_mchid").is_some() {
                if let Some(sub) = &self.cfg.sub_mchid {
                    order["sub_mchid"] = json!(sub.clone());
                }
            }
        }
        let url = self.endpoint("/v3/pay/transactions/jsapi");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        if let Some(prepay_id) = resp.get("prepay_id").and_then(|v| v.as_str()) {
            let time_stamp = now_ts();
            let nonce_str = gen_nonce(32);
            let package = format!("prepay_id={}", prepay_id);
            let sign_src = format!(
                "{}\n{}\n{}\n{}\n",
                resp.get("appid").and_then(|v| v.as_str()).unwrap_or(""),
                &self.cfg.mchid,
                &package,
                &time_stamp
            );
            let pay_sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;
            return Ok(
                json!({"appId": resp.get("appid").and_then(|v| v.as_str()).unwrap_or(""), "timeStamp": time_stamp, "nonceStr": nonce_str, "package": package, "signType": "RSA", "paySign": pay_sign }),
            );
        }
        Ok(resp)
    }

    pub async fn h5(&self, mut order: Value) -> Result<Value, PayError> {
        if !order.get("mchid").is_some() {
            order["mchid"] = json!(self.cfg.mchid.clone());
        }
        if let Mode::Service = self.mode {
            if !order.get("sub_mchid").is_some() {
                if let Some(sub) = &self.cfg.sub_mchid {
                    order["sub_mchid"] = json!(sub.clone());
                }
            }
        }
        let url = self.endpoint("/v3/pay/transactions/h5");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn app(&self, mut order: Value) -> Result<Value, PayError> {
        if let Some(appid) = &self.cfg.appid_app {
            order["appid"] = json!(appid.clone());
        }
        if let Mode::Service = self.mode {
            if !order.get("sub_mchid").is_some() {
                if let Some(sub) = &self.cfg.sub_mchid {
                    order["sub_mchid"] = json!(sub.clone());
                }
            }
        }
        let url = self.endpoint("/v3/pay/transactions/app");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn scan(&self, mut order: Value) -> Result<Value, PayError> {
        if !order.get("mchid").is_some() {
            order["mchid"] = json!(self.cfg.mchid.clone());
        }
        if let Mode::Service = self.mode {
            if !order.get("sub_mchid").is_some() {
                if let Some(sub) = &self.cfg.sub_mchid {
                    order["sub_mchid"] = json!(sub.clone());
                }
            }
        }
        let url = self.endpoint("/v3/pay/transactions/native");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn pos(&self, mut order: Value) -> Result<Value, PayError> {
        if !order.get("mchid").is_some() {
            order["mchid"] = json!(self.cfg.mchid.clone());
        }
        if let Mode::Service = self.mode {
            if !order.get("sub_mchid").is_some() {
                if let Some(sub) = &self.cfg.sub_mchid {
                    order["sub_mchid"] = json!(sub.clone());
                }
            }
        }
        let url = self.endpoint("/v3/pay/partner/transactions/micropay");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn transfer(&self, order: Value) -> Result<Value, PayError> {
        let url = self.endpoint("/v3/transfer/batches");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn refresh_platform_certs(&self) -> Result<(), PayError> {
        self.certs
            .refresh()
            .await
            .map_err(|e| PayError::Other(format!("refresh platform certs: {}", e)))?;
        Ok(())
    }

    pub async fn sign_and_post(
        &self,
        method: &str,
        url: &str,
        body: &Value,
    ) -> Result<Value, PayError> {
        let body_str = if method == "GET" {
            "".to_string()
        } else {
            body.to_string()
        };
        let timestamp = now_ts();
        let nonce = gen_nonce(32);
        let parsed = Url::parse(url).map_err(|e| PayError::Other(format!("parse url: {}", e)))?;
        let path = if let Some(query) = parsed.query() {
            format!("{}?{}", parsed.path(), query)
        } else {
            parsed.path().to_string()
        };
        let sign_str = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            method, path, timestamp, nonce, body_str
        );
        let signature = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_str)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        let auth = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{mchid}",nonce_str="{nonce}",timestamp="{ts}",serial_no="{serial}",signature="{sig}""#,
            mchid = self.cfg.mchid,
            nonce = nonce,
            ts = timestamp,
            serial = self.cfg.serial_no,
            sig = signature
        );
        let client = &self.http;
        let send_req = || async {
            let mut req = match method {
                "GET" => client.get(url),
                "POST" => client.post(url),
                _ => {
                    return Err(PayError::Other(format!("unsupported method: {}", method)));
                }
            };
            req = req
                .header("Authorization", auth.clone())
                .header("Accept", "application/json")
                .header("User-Agent", "ysp-rust-pay/0.1");
            if method == "POST" {
                req = req
                    .header("Content-Type", "application/json")
                    .body(body_str.clone());
            }
            let resp = req.send().await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(PayError::Other(format!(
                    "HTTP request failed: {} - {}",
                    status, text
                )));
            }
            let v: Value = serde_json::from_str(&text)?;
            Ok(v)
        };
        let v = crate::utils::retry_async(self.max_retries, send_req)
            .await
            .map_err(|e| PayError::Other(format!(
                "HTTP request failed:{}",
             e
            )))?;
        Ok(v)
    }
    
}
