use crate::config::{AlipayConfig, Mode};
use crate::errors::PayError;
use crate::utils::rsa_sign_sha256_pem;
use reqwest::Client;
use std::collections::BTreeMap;
use std::sync::Arc;
use urlencoding::encode;

pub struct AlipayClient {
    cfg: Arc<AlipayConfig>,
    http: Client,
    gateway: String,
    mode: Mode,
}

impl AlipayClient {
    pub fn with_mode(cfg: Arc<AlipayConfig>, mode: Mode) -> Self {
        let gateway = match mode {
            Mode::Sandbox => "https://openapi.alipaydev.com/gateway.do".to_string(),
            _ => cfg.gateway.clone(),
        };
        Self {
            cfg,
            http: Client::new(),
            gateway,
            mode,
        }
    }

    fn build_sign_string(params: &BTreeMap<String, String>) -> String {
        params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    }

    async fn do_get(
        &self,
        params: BTreeMap<String, String>,
    ) -> Result<serde_json::Value, PayError> {
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}?{}", self.gateway, query);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| PayError::Http(e))?
            .text()
            .await
            .map_err(|e| PayError::Http(e))?;
        let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| PayError::Json(e))?;
        Ok(v)
    }

    pub async fn app(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_merchant_id").is_some() {
                if let Some(sid) = &self.cfg.sub_merchant_id {
                    order["sub_merchant_id"] = serde_json::json!(sid.clone());
                }
            }
        }
        let mut params = BTreeMap::new();
        params.insert("app_id".into(), self.cfg.app_id.clone());
        params.insert("method".into(), "alipay.trade.app.pay".into());
        params.insert("format".into(), "json".into());
        params.insert("charset".into(), self.cfg.charset.clone());
        params.insert("sign_type".into(), self.cfg.sign_type.clone());
        params.insert(
            "timestamp".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        params.insert("version".into(), "1.0".to_string());
        if let Some(n) = order.get("notify_url").and_then(|v| v.as_str()) {
            params.insert("notify_url".into(), n.to_string());
        }
        params.insert("biz_content".into(), order.to_string());
        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        params.insert("sign".into(), sign);
        let order_str = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(serde_json::json!({ "order_string": order_str }))
    }

    pub fn wap(&self, mut order: serde_json::Value) -> Result<String, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_merchant_id").is_some() {
                if let Some(sid) = &self.cfg.sub_merchant_id {
                    order["sub_merchant_id"] = serde_json::json!(sid.clone());
                }
            }
        }
        let mut params = BTreeMap::new();
        params.insert("app_id".into(), self.cfg.app_id.clone());
        params.insert("method".into(), "alipay.trade.wap.pay".into());
        params.insert("format".into(), "json".into());
        params.insert("charset".into(), self.cfg.charset.clone());
        params.insert("sign_type".into(), self.cfg.sign_type.clone());
        params.insert(
            "timestamp".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        params.insert("version".into(), "1.0".to_string());
        if let Some(n) = order.get("notify_url").and_then(|v| v.as_str()) {
            params.insert("notify_url".into(), n.to_string());
        }
        params.insert("biz_content".into(), order.to_string());
        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        params.insert("sign".into(), sign);
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!("{}?{}", self.gateway, query))
    }

    pub fn page(&self, mut order: serde_json::Value) -> Result<String, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_merchant_id").is_some() {
                if let Some(sid) = &self.cfg.sub_merchant_id {
                    order["sub_merchant_id"] = serde_json::json!(sid.clone());
                }
            }
        }
        let mut params = BTreeMap::new();
        params.insert("app_id".into(), self.cfg.app_id.clone());
        params.insert("method".into(), "alipay.trade.page.pay".into());
        params.insert("format".into(), "json".into());
        params.insert("charset".into(), self.cfg.charset.clone());
        params.insert("sign_type".into(), self.cfg.sign_type.clone());
        params.insert(
            "timestamp".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        params.insert("version".into(), "1.0".to_string());
        if let Some(n) = order.get("notify_url").and_then(|v| v.as_str()) {
            params.insert("notify_url".into(), n.to_string());
        }
        params.insert("biz_content".into(), order.to_string());
        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        params.insert("sign".into(), sign);
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!("{}?{}", self.gateway, query))
    }

    pub async fn scan(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_merchant_id").is_some() {
                if let Some(sid) = &self.cfg.sub_merchant_id {
                    order["sub_merchant_id"] = serde_json::json!(sid.clone());
                }
            }
        }
        let mut params = BTreeMap::new();
        params.insert("app_id".into(), self.cfg.app_id.clone());
        params.insert("method".into(), "alipay.trade.precreate".into());
        params.insert("format".into(), "json".into());
        params.insert("charset".into(), self.cfg.charset.clone());
        params.insert("sign_type".into(), self.cfg.sign_type.clone());
        params.insert(
            "timestamp".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        params.insert("version".into(), "1.0".to_string());
        params.insert("biz_content".into(), order.to_string());
        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        params.insert("sign".into(), sign);
        let v = self.do_get(params).await?;
        Ok(v)
    }

    pub async fn transfer(
        &self,
        biz_content: serde_json::Value,
    ) -> Result<serde_json::Value, PayError> {
        let mut params = BTreeMap::new();
        params.insert("app_id".into(), self.cfg.app_id.clone());
        params.insert(
            "method".into(),
            "alipay.fund.trans.toaccount.transfer".into(),
        );
        params.insert("format".into(), "json".into());
        params.insert("charset".into(), self.cfg.charset.clone());
        params.insert("sign_type".into(), self.cfg.sign_type.clone());
        params.insert(
            "timestamp".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        params.insert("version".into(), "1.0".to_string());
        params.insert("biz_content".into(), biz_content.to_string());
        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;
        params.insert("sign".into(), sign);
        let v = self.do_get(params).await?;
        Ok(v)
    }
}

impl AlipayClient {
    /// Verify incoming notify parameters map (from form decoding) and return structured data
    pub fn verify_notify(
        &self,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<crate::alipay::notify::AlipayNotifyData, crate::errors::PayError> {
        let notify = crate::alipay::notify::AlipayNotify::new(self.cfg.clone(), self.mode.clone());
        notify.verify_notify(params)
    }
}
