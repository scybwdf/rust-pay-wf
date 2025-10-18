use crate::alipay::{AlipayNotify, AlipayNotifyData};
use crate::config::{AlipayConfig, Mode};
use crate::errors::PayError;
use crate::utils::{get_cert_sn, get_root_cert_sn, rsa_sign_sha256_pem};
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
    pub fn new(cfg: Arc<AlipayConfig>, mode: Mode) -> Self {
        Self::with_mode(cfg, mode)
    }

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

    fn build_service_provider_params(&self, order: &mut serde_json::Value) {
        if let Mode::Service = self.mode {
            if let Some(provider_id) = &self.cfg.sys_service_provider_id {
                if !order.get("extend_params").is_some() {
                    order["extend_params"] = serde_json::json!({});
                }
                if let Some(obj) = order["extend_params"].as_object_mut() {
                    obj.insert(
                        "sys_service_provider_id".to_string(),
                        serde_json::Value::String(provider_id.clone()),
                    );
                }
            }
        }
    }

    fn build_common_params(
        &self,
        method: &str,
        order: &serde_json::Value,
    ) -> BTreeMap<String, String> {
        let mut params = BTreeMap::new();

        params.insert("app_id".into(), self.cfg.app_id.clone());
        params.insert("method".into(), method.to_string());
        params.insert("format".into(), "json".into());
        params.insert("charset".into(), self.cfg.charset.clone());
        params.insert("sign_type".into(), self.cfg.sign_type.clone());
        params.insert(
            "timestamp".into(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        params.insert("version".into(), "1.0".to_string());

        // 证书模式
        if self.cfg.app_cert_path.is_some() && self.cfg.alipay_root_cert_path.is_some() {
            if let Some(app_cert_path) = &self.cfg.app_cert_path {
                let app_sn = get_cert_sn(app_cert_path).unwrap_or_default();
                println!("app_cert_sn: {}", app_sn);
                if !app_sn.is_empty() {
                    params.insert("app_cert_sn".into(), app_sn);
                }
            }

            if let Some(root_cert_path) = &self.cfg.alipay_root_cert_path {
                let root_sn = get_root_cert_sn(root_cert_path).unwrap_or_default();
                println!("alipay_root_cert_sn: {}", root_sn);
                if !root_sn.is_empty() {
                    params.insert("alipay_root_cert_sn".into(), root_sn);
                }
            }
        }
        // 服务商参数
        if let Mode::Service = self.mode {
            if let Some(auth_token) = &self.cfg.app_auth_token {
                params.insert("app_auth_token".into(), auth_token.clone());
            }
        }

        if let Some(n) = order.get("notify_url").and_then(|v| v.as_str()) {
            params.insert("notify_url".into(), n.to_string());
        }

        if let Some(r) = order.get("return_url").and_then(|v| v.as_str()) {
            params.insert("return_url".into(), r.to_string());
        }

        params
    }

    async fn do_request(
        &self,
        params: BTreeMap<String, String>,
    ) -> Result<serde_json::Value, PayError> {
        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(e.to_string()))?;

        let mut params_with_sign = params;
        params_with_sign.insert("sign".into(), sign);

        let query = params_with_sign
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
            .map_err(PayError::Http)?
            .text()
            .await
            .map_err(PayError::Http)?;

        let v: serde_json::Value = serde_json::from_str(&resp).map_err(PayError::Json)?;

        if let Some(err) = v.get("error_response") {
            return Err(PayError::from_alipay_response(err));
        }
        Ok(v)
    }

    pub async fn app(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);
        let mut params = self.build_common_params("alipay.trade.app.pay", &order);
        params.insert("biz_content".into(), order.to_string());

        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(e.to_string()))?;
        params.insert("sign".into(), sign);

        let order_str = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(serde_json::json!({ "order_string": order_str }))
    }

    pub async fn scan(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);
        let mut params = self.build_common_params("alipay.trade.precreate", &order);
        params.insert("biz_content".into(), order.to_string());
        self.do_request(params).await
    }

    /// ✅ H5 支付（手机浏览器）
    pub async fn h5(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);
        let mut params = self.build_common_params("alipay.trade.wap.pay", &order);
        params.insert("biz_content".into(), order.to_string());

        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(e.to_string()))?;
        params.insert("sign".into(), sign);

        // 拼接跳转链接
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}?{}", self.gateway, query);

        Ok(serde_json::json!({ "pay_url": url }))
    }

    /// PC 网页支付
    pub async fn page(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);
        let mut params = self.build_common_params("alipay.trade.page.pay", &order);
        params.insert("biz_content".into(), order.to_string());

        let sign_src = Self::build_sign_string(&params);
        let sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
            .map_err(|e| PayError::Crypto(e.to_string()))?;
        params.insert("sign".into(), sign);

        // 返回 form 表单字符串（前端可直接渲染提交）
        let form_html = format!(
            r#"<form id="alipaysubmit" name="alipaysubmit" action="{}" method="GET">
{}<input type="submit" value="Pay with Alipay" style="display:none"></form>
<script>document.forms['alipaysubmit'].submit();</script>"#,
            self.gateway,
            params
                .iter()
                .map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}"/>"#, k, v))
                .collect::<Vec<_>>()
                .join("\n")
        );

        Ok(serde_json::json!({ "form_html": form_html }))
    }

    /// 小程序支付（创建订单后由前端拉起）
    pub async fn mini_program(
        &self,
        mut order: serde_json::Value,
    ) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);
        let mut params = self.build_common_params("alipay.trade.create", &order);
        params.insert("biz_content".into(), order.to_string());

        let resp = self.do_request(params).await?;

        if let Some(result) = resp.get("alipay_trade_create_response") {
            if result.get("code").and_then(|v| v.as_str()) == Some("10000") {
                let trade_no = result
                    .get("trade_no")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                return Ok(serde_json::json!({
                    "trade_no": trade_no,
                    "out_trade_no": order.get("out_trade_no").and_then(|v| v.as_str()).unwrap_or_default(),
                    "msg": "ok"
                }));
            } else {
                return Err(PayError::from_alipay_response(result));
            }
        }
        Err(PayError::Crypto("invalid alipay response".into()))
    }

    pub fn verify_notify(
        &self,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<AlipayNotifyData, PayError> {
        /*        let alipay_public_key = if let Some(cert_path) = &self.cfg.alipay_cert_path {
            let data = std::fs::read(cert_path).map_err(|e| PayError::Crypto(e.to_string()))?;
            let cert = openssl::x509::X509::from_pem(&data)
                .map_err(|e| PayError::Crypto(e.to_string()))?;
            let pubkey = cert.public_key().map_err(|e| PayError::Crypto(e.to_string()))?;
            String::from_utf8(pubkey.public_key_to_pem().map_err(|e| PayError::Crypto(e.to_string()))?)
                .map_err(|e| PayError::Crypto(e.to_string()))?
        } else {
            self.cfg.alipay_public_key.clone().ok_or_else(|| PayError::Crypto("missing alipay_public_key".into()))?
        };*/

        let notify = AlipayNotify::new(self.cfg.clone());
        notify.verify_notify(params)
    }
}
