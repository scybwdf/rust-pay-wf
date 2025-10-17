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
    pub fn new(cfg: Arc<AlipayConfig>, mode: Mode) -> Self {
        Self::with_mode(cfg, mode)
    }

    pub fn with_mode(cfg: Arc<AlipayConfig>, mode: Mode) -> Self {
        let gateway = match mode {
            Mode::Sandbox => "https://openapi.alipaydev.com/gateway.do".to_string(),
            _ => cfg.gateway.clone(),
        };

        // 验证服务商模式配置
        if let Mode::Service = mode {
            if cfg.app_auth_token.is_none() && cfg.sys_service_provider_id.is_none() {
                eprintln!("警告: 服务商模式下建议提供 app_auth_token 或 sys_service_provider_id");
            }
        }

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
            // 添加返佣服务商ID到extend_params
            if let Some(provider_id) = &self.cfg.sys_service_provider_id {
                if !order.get("extend_params").is_some() {
                    order["extend_params"] = serde_json::json!({});
                }
                if let Some(extend_params) = order.get_mut("extend_params") {
                    if let Some(obj) = extend_params.as_object_mut() {
                        obj.insert("sys_service_provider_id".to_string(),
                                   serde_json::Value::String(provider_id.clone()));
                    }
                }
            }
        }
    }

    fn build_common_params(&self, method: &str, order: &serde_json::Value) -> BTreeMap<String, String> {
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

        // 服务商模式：添加app_auth_token到公共参数
        if let Mode::Service = self.mode {
            if let Some(auth_token) = &self.cfg.app_auth_token {
                params.insert("app_auth_token".into(), auth_token.clone());
            }
        }

        // 通知URL处理
        if let Some(n) = order.get("notify_url").and_then(|v| v.as_str()) {
            params.insert("notify_url".into(), n.to_string());
        }

        // 返回URL处理
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
            .map_err(|e| PayError::Crypto(format!("{}", e)))?;

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
            .map_err(|e| PayError::Http(e))?
            .text()
            .await
            .map_err(|e| PayError::Http(e))?;

        let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| PayError::Json(e))?;

        // 检查支付宝返回的错误
        if let Some(error) = v.get("error_response") {
            return Err(PayError::from_alipay_response(error));
        }

        Ok(v)
    }

    // APP支付
    pub async fn app(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);

        let mut params = self.build_common_params("alipay.trade.app.pay", &order);
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

    // 手机网站支付
    pub fn wap(&self, mut order: serde_json::Value) -> Result<String, PayError> {
        self.build_service_provider_params(&mut order);

        let mut params = self.build_common_params("alipay.trade.wap.pay", &order);
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

    // 电脑网站支付
    pub fn page(&self, mut order: serde_json::Value) -> Result<String, PayError> {
        self.build_service_provider_params(&mut order);

        let mut params = self.build_common_params("alipay.trade.page.pay", &order);
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

    // 扫码支付
    pub async fn scan(&self, mut order: serde_json::Value) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut order);

        let mut params = self.build_common_params("alipay.trade.precreate", &order);
        params.insert("biz_content".into(), order.to_string());

        self.do_request(params).await
    }

    // 单笔转账
    pub async fn transfer(
        &self,
        mut biz_content: serde_json::Value,
    ) -> Result<serde_json::Value, PayError> {
        self.build_service_provider_params(&mut biz_content);

        let mut params = self.build_common_params("alipay.fund.trans.toaccount.transfer", &biz_content);
        params.insert("biz_content".into(), biz_content.to_string());

        self.do_request(params).await
    }

    // 交易查询
    pub async fn trade_query(
        &self,
        out_trade_no: Option<&str>,
        trade_no: Option<&str>,
    ) -> Result<serde_json::Value, PayError> {
        let mut biz_content = serde_json::Map::new();

        if let Some(ono) = out_trade_no {
            biz_content.insert("out_trade_no".to_string(), serde_json::Value::String(ono.to_string()));
        }
        if let Some(tno) = trade_no {
            biz_content.insert("trade_no".to_string(), serde_json::Value::String(tno.to_string()));
        }

        let mut params = self.build_common_params("alipay.trade.query", &serde_json::Value::Null);
        params.insert("biz_content".into(), serde_json::Value::Object(biz_content).to_string());

        self.do_request(params).await
    }

    // 交易退款
    pub async fn trade_refund(
        &self,
        out_trade_no: &str,
        refund_amount: &str,
        out_request_no: Option<&str>,
    ) -> Result<serde_json::Value, PayError> {
        let mut biz_content = serde_json::json!({
            "out_trade_no": out_trade_no,
            "refund_amount": refund_amount,
            "out_request_no": out_request_no.unwrap_or(&format!("R{}", chrono::Local::now().timestamp_millis()))
        });

        self.build_service_provider_params(&mut biz_content);

        let mut params = self.build_common_params("alipay.trade.refund", &biz_content);
        params.insert("biz_content".into(), biz_content.to_string());

        self.do_request(params).await
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
