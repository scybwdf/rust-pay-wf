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
    max_retries: usize,
}

impl WechatClient {
    pub fn with_mode(cfg: Arc<WechatConfig>, mode: Mode) -> Self {
        let http = Client::builder()
            .user_agent("rust_pay_wf")
            .build()
            .expect("client");
        let certs = Arc::new(PlatformCerts::new(cfg.clone()));

        // 根据模式设置基础URL
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
            max_retries: 3,
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    // 服务商模式下的URL路径不同
    fn get_service_url(&self, path: &str) -> String {
        if let Mode::Service = self.mode {
            // 服务商模式URL前缀为/partner
            if path.contains("/v3/pay/transactions/") {
                let path=path.replace("/v3/pay/transactions/", "/v3/pay/partner/transactions/");
                return self.endpoint(&path);
            }
            return self.endpoint(path);
        } else {
            self.endpoint(path)
        }
    }

    // 构建服务商模式参数
    fn build_service_params(&self, mut params: Value) -> Value {
        if let Mode::Service = self.mode {
            // 添加服务商模式必需参数
            if !params.get("sp_appid").is_some() {
                if let Some(sp_appid) = &self.cfg.sp_appid {
                    params["sp_appid"] = json!(sp_appid.clone());
                } else if let Some(appid) = &self.cfg.appid_mp {
                    params["sp_appid"] = json!(appid.clone());
                }
            }

            if !params.get("sp_mchid").is_some() {
                params["sp_mchid"] = json!(self.cfg.mchid.clone());
            }

            if !params.get("sub_mchid").is_some() {
                if let Some(sub_mchid) = &self.cfg.sub_mchid {
                    params["sub_mchid"] = json!(sub_mchid.clone());
                }
            }

            // 处理payer字段
            if let Some(payer) = params.get_mut("payer") {
                if let Value::Object(payer_obj) = payer {
                    // 服务商模式下使用sub_openid而不是openid
                    if let Some(openid) = payer_obj.remove("openid") {
                        payer_obj.insert("sub_openid".to_string(), openid);
                    }
                }
            }
        }
        params
    }

    pub async fn mp(&self, mut order: Value) -> Result<Value, PayError> {
        // 设置appid
        if !order.get("appid").is_some() && !order.get("sp_appid").is_some() {
            if let Some(appid) = &self.cfg.appid_mp {
                if let Mode::Service = self.mode {
                    order["sp_appid"] = json!(appid.clone());
                } else {
                    order["appid"] = json!(appid.clone());
                }
            }
        }

        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 构建请求体
        let mut body = json!({
            "description": order.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            "out_trade_no": order.get("out_trade_no").and_then(|v| v.as_str()).unwrap_or(""),
            "notify_url": order.get("notify_url").and_then(|v| v.as_str()).unwrap_or(""),
            "amount": order.get("amount").cloned().unwrap_or(json!({"total":1})),
        });

        // 根据模式添加不同的商户ID
        if let Mode::Service = self.mode {
            body["sp_mchid"] = json!(self.cfg.mchid.clone());
            if let Some(sub_mchid) = order.get("sub_mchid") {
                body["sub_mchid"] = sub_mchid.clone();
            }
        } else {
            body["mchid"] = json!(self.cfg.mchid.clone());
        }

        // 添加payer信息
        if let Some(payer) = order.get("payer") {
            body["payer"] = payer.clone();
        }

        // 添加场景信息
        if let Some(scene_info) = order.get("scene_info") {
            body["scene_info"] = scene_info.clone();
        }

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/jsapi");
        let resp = self.sign_and_post("POST", &url, &body).await?;

        if let Some(prepay_id) = resp.get("prepay_id").and_then(|v| v.as_str()) {
            let time_stamp = now_ts();
            let nonce_str = gen_nonce(32);
            let package = format!("prepay_id={}", prepay_id);

            // 根据模式确定appid
            let appid = if let Mode::Service = self.mode {
                resp.get("sp_appid").and_then(|v| v.as_str()).unwrap_or("")
            } else {
                resp.get("appid").and_then(|v| v.as_str()).unwrap_or("")
            };

            let sign_src = format!(
                "{}\n{}\n{}\n{}\n",
                appid,
                time_stamp,
                nonce_str,
                package
            );

            let pay_sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;

            return Ok(
                json!({
                    "appId": appid,
                    "timeStamp": time_stamp,
                    "nonceStr": nonce_str,
                    "package": package,
                    "signType": "RSA",
                    "paySign": pay_sign
                }),
            );
        }
        Ok(resp)
    }

    pub async fn mini(&self, mut order: Value) -> Result<Value, PayError> {
        // 设置appid
        if !order.get("appid").is_some() && !order.get("sp_appid").is_some() {
            if let Some(appid) = &self.cfg.appid_mini {
                if let Mode::Service = self.mode {
                    order["sp_appid"] = json!(appid.clone());
                } else {
                    order["appid"] = json!(appid.clone());
                }
            }
        }

        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/jsapi");
        let resp = self.sign_and_post("POST", &url, &order).await?;

        if let Some(prepay_id) = resp.get("prepay_id").and_then(|v| v.as_str()) {
            let time_stamp = now_ts();
            let nonce_str = gen_nonce(32);
            let package = format!("prepay_id={}", prepay_id);

            // 根据模式确定appid
            let appid = if let Mode::Service = self.mode {
                resp.get("sp_appid").and_then(|v| v.as_str()).unwrap_or("")
            } else {
                resp.get("appid").and_then(|v| v.as_str()).unwrap_or("")
            };

            let sign_src = format!(
                "{}\n{}\n{}\n{}\n",
                appid,
                time_stamp,
                nonce_str,
                package
            );

            let pay_sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;

            return Ok(
                json!({
                    "appId": appid,
                    "timeStamp": time_stamp,
                    "nonceStr": nonce_str,
                    "package": package,
                    "signType": "RSA",
                    "paySign": pay_sign
                }),
            );
        }
        Ok(resp)
    }

    pub async fn h5(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/h5");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn app(&self, mut order: Value) -> Result<Value, PayError> {
        // 设置appid
        if !order.get("appid").is_some() && !order.get("sp_appid").is_some() {
            if let Some(appid) = &self.cfg.appid_app {
                if let Mode::Service = self.mode {
                    order["sp_appid"] = json!(appid.clone());
                } else {
                    order["appid"] = json!(appid.clone());
                }
            }
        }

        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/app");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn native(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/native");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn micropay(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/micropay");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn query(&self, mut params: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        params = self.build_service_params(params);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/pay/partner/transactions/id/{transaction_id}"
                .replace("{transaction_id}",
                         params.get("transaction_id")
                             .and_then(|v| v.as_str())
                             .unwrap_or("")
                )
        } else {
            "/v3/pay/transactions/id/{transaction_id}"
                .replace("{transaction_id}",
                         params.get("transaction_id")
                             .and_then(|v| v.as_str())
                             .unwrap_or("")
                )
        };

        let resp = self.sign_and_post("GET", &url, &params).await?;
        Ok(resp)
    }

    pub async fn close(&self, mut params: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        params = self.build_service_params(params);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/pay/partner/transactions/out-trade-no/{out_trade_no}/close"
                .replace("{out_trade_no}",
                         params.get("out_trade_no")
                             .and_then(|v| v.as_str())
                             .unwrap_or("")
                )
        } else {
            "/v3/pay/transactions/out-trade-no/{out_trade_no}/close"
                .replace("{out_trade_no}",
                         params.get("out_trade_no")
                             .and_then(|v| v.as_str())
                             .unwrap_or("")
                )
        };

        let resp = self.sign_and_post("POST", &url, &params).await?;
        Ok(resp)
    }

    pub async fn refund(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/refund/domestic/refunds"
        } else {
            "/v3/refund/domestic/refunds"
        };

        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn query_refund(&self, mut params: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        params = self.build_service_params(params);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/refund/domestic/refunds/{out_refund_no}"
                .replace("{out_refund_no}",
                         params.get("out_refund_no")
                             .and_then(|v| v.as_str())
                             .unwrap_or("")
                )
        } else {
            "/v3/refund/domestic/refunds/{out_refund_no}"
                .replace("{out_refund_no}",
                         params.get("out_refund_no")
                             .and_then(|v| v.as_str())
                             .unwrap_or("")
                )
        };

        let resp = self.sign_and_post("GET", &url, &params).await?;
        Ok(resp)
    }

    pub async fn transfer(&self, order: Value) -> Result<Value, PayError> {
        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/transfer/batches"
        } else {
            "/v3/transfer/batches"
        };

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

        // 服务商模式使用服务商商户号
        let mchid = self.cfg.mchid.clone();

        let auth = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{mchid}",nonce_str="{nonce}",timestamp="{ts}",serial_no="{serial}",signature="{sig}""#,
            mchid = mchid,
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
                .header("User-Agent", "rust_pay_wf");
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