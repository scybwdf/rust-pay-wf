use crate::config::{Mode, WechatConfig};
use crate::errors::PayError;
use crate::utils::{
    gen_nonce, now_ts,
    rsa_sign_sha256_pem,
};
use crate::wechat::certs::PlatformCerts;
use crate::wechat::notify::WechatNotify;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
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
                let path = path.replace("/v3/pay/transactions/", "/v3/pay/partner/transactions/");
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
            // 设置appid
            if !params.get("appid").is_some() && !params.get("sp_appid").is_some() {
                if let Some(appid) = &self.cfg.appid {
                    params["sp_appid"] = json!(appid.clone());
                }
            }
            // 添加服务商模式必需参数
            if !params.get("sp_appid").is_some() {
                if let Some(sp_appid) = &self.cfg.appid {
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
            let old_params = params.clone();
            // 处理payer字段
            if let Some(payer) = params.get_mut("payer") {
                if let Value::Object(payer_obj) = payer {
                    // 服务商模式下使用sub_openid而不是openid
                    if old_params.get("sub_appid").is_some() {
                        if let Some(openid) = payer_obj.remove("openid") {
                            payer_obj.insert("sub_openid".to_string(), openid);
                        }
                    } else {
                        if let Some(openid) = payer_obj.remove("openid") {
                            payer_obj.insert("sp_openid".to_string(), openid);
                        }
                    }
                }
            }
        } else {
            params["mchid"] = json!(self.cfg.mchid.clone());
            params["appid"] = json!(self.cfg.appid.clone());
        }
        if !params.get("notify_url").is_some() {
            if let Some(notify_url) = &self.cfg.notify_url {
                params["notify_url"] = json!(notify_url.clone());
            }
        }
        params
    }

    pub async fn mp(&self, mut order: Value) -> Result<Value, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_appid").is_some() {
                if let Some(appid) = &self.cfg.appid_mp {
                    order["sub_appid"] = json!(appid.clone());
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
                order.get("sp_appid").and_then(|v| v.as_str()).unwrap_or("")
            } else {
                order.get("appid").and_then(|v| v.as_str()).unwrap_or("")
            };

            let sign_src = format!("{}\n{}\n{}\n{}\n", appid, time_stamp, nonce_str, package);

            let pay_sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;

            return Ok(json!({
                "appId": appid,
                "timeStamp": time_stamp,
                "nonceStr": nonce_str,
                "package": package,
                "signType": "RSA",
                "paySign": pay_sign
            }));
        }
        Ok(resp)
    }

    pub async fn miniapp(&self, mut order: Value) -> Result<Value, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_appid").is_some() {
                if let Some(appid) = &self.cfg.appid_mini {
                    order["sub_appid"] = json!(appid.clone());
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
                order.get("sp_appid").and_then(|v| v.as_str()).unwrap_or("")
            } else {
                order.get("appid").and_then(|v| v.as_str()).unwrap_or("")
            };

            let sign_src = format!("{}\n{}\n{}\n{}\n", appid, time_stamp, nonce_str, package);

            let pay_sign = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_src)
                .map_err(|e| PayError::Crypto(format!("{}", e)))?;

            return Ok(json!({
                "appId": appid,
                "timeStamp": time_stamp,
                "nonceStr": nonce_str,
                "package": package,
                "signType": "RSA",
                "paySign": pay_sign
            }));
        }
        Ok(resp)
    }

    pub async fn h5(&self, mut order: Value) -> Result<Value, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_appid").is_some() {
                if let Some(appid) = &self.cfg.appid_mini {
                    order["sub_appid"] = json!(appid.clone());
                }
            }
        }
        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = self.get_service_url("/v3/pay/transactions/h5");
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn app(&self, mut order: Value) -> Result<Value, PayError> {
        if let Mode::Service = self.mode {
            if !order.get("sub_appid").is_some() {
                if let Some(appid) = &self.cfg.appid_app {
                    order["sub_appid"] = json!(appid.clone());
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
            "/v3/pay/partner/transactions/id/{transaction_id}".replace(
                "{transaction_id}",
                params
                    .get("transaction_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
        } else {
            "/v3/pay/transactions/id/{transaction_id}".replace(
                "{transaction_id}",
                params
                    .get("transaction_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
        };
        let url = self.endpoint(&url);
        let resp = self.sign_and_post("GET", &url, &params).await?;
        Ok(resp)
    }

    pub async fn close(&self, mut params: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        params = self.build_service_params(params);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/pay/partner/transactions/out-trade-no/{out_trade_no}/close".replace(
                "{out_trade_no}",
                params
                    .get("out_trade_no")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
        } else {
            "/v3/pay/transactions/out-trade-no/{out_trade_no}/close".replace(
                "{out_trade_no}",
                params
                    .get("out_trade_no")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
        };
        let url = self.endpoint(&url);
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
        let url = self.endpoint(&url);
        if let Some(obj) = order.as_object_mut() {
            obj.remove("sub_appid");
            obj.remove("sp_mchid");
            obj.remove("sp_appid");
        }
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    pub async fn query_refund(&self, mut params: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        params = self.build_service_params(params);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/refund/domestic/refunds/{out_refund_no}".replace(
                "{out_refund_no}",
                params
                    .get("out_refund_no")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
        } else {
            "/v3/refund/domestic/refunds/{out_refund_no}".replace(
                "{out_refund_no}",
                params
                    .get("out_refund_no")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )
        };
        let url = self.endpoint(&url);
        if let Some(obj) = params.as_object_mut() {
            obj.remove("sub_appid");
            obj.remove("sp_mchid");
            obj.remove("sp_appid");
        }
        let resp = self.sign_and_post("GET", &url, &params).await?;
        Ok(resp)
    }

    pub async fn transfer(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 使用服务商模式URL
        let url = if let Mode::Service = self.mode {
            "/v3/transfer/batches"
        } else {
            "/v3/transfer/batches"
        };
        let url = self.endpoint(&url);
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
        tracing::info!(
            "sign_and_post: method={}, url={}, body={}",
            method, url, body_str
        );
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
            .map_err(|e| PayError::Other(format!("HTTP request failed:{}", e)))?;
        Ok(v)
    }

    /// 处理回调
    pub async fn handle_notify(
        &self,
        headers: HashMap<String, String>,
        body_str: &str,
    ) -> Result<Value, PayError> {
        let notify = WechatNotify::new(self.cfg.clone(), self.certs.clone());
        notify.verify_and_decrypt(&headers, body_str).await
    }

    /// 添加分账接收方
    /// 文档：https://pay.weixin.qq.com/doc/v3/partner/4012477758 [citation:1]
    /// 文档：https://pay.weixin.qq.com/doc/v3/merchant/4012528995 [citation:4]
    pub async fn add_profitsharing_receiver(&self, mut order: Value) -> Result<Value, PayError> {
        // 1. 验证必要参数 - 使用 get() 而不是 get_mut()
        let receiver_type = order
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PayError::Other("Missing required field: 'type'".into()))?
            .to_string(); // 转换为 String，获取所有权

        let account = order
            .get("account")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PayError::Other("Missing required field: 'account'".into()))?
            .to_string(); // 转换为 String，获取所有权

        // 2. 记录请求参数
        tracing::info!(
            "添加分账接收方 - 类型: {}, 账号: {}",
            receiver_type, account
        );

        // 3. 构建符合服务商模式的参数
        order = self.build_service_params(order);

        // 4. 获取URL
        let url = self.get_service_url("/v3/profitsharing/receivers/add");

        // 5. 处理接收方名称加密（如果需要）
        // 注意：传递 receiver_type 的引用，而不是 String
        let wechatpay_serial = self
            .process_receiver_name_encryption(
                &receiver_type, // 传递引用
                &mut order,
            )
            .await?;

        // 6. 发送请求
        self.send_profitsharing_request("POST", &url, &order, wechatpay_serial)
            .await
    }

    /// 请求分账
    /// 文档：https://pay.weixin.qq.com/doc/v3/partner/4012087888 [citation:2]
    pub async fn profitsharing(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建服务商参数
        order = self.build_service_params(order);

        let url = self.get_service_url("/v3/profitsharing/orders");

        // 发送请求
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    /// 查询分账结果
    pub async fn query_profitsharing(
        &self,
        out_order_no: &str,
        transaction_id: Option<&str>,
    ) -> Result<Value, PayError> {
        let old_url = format!("/v3/profitsharing/orders/{}", out_order_no);
        let mut full_url = self.get_service_url(&*old_url);

        if let Some(tid) = transaction_id {
            full_url = format!("{}?transaction_id={}", full_url, tid);
        }
        // 发送GET请求
        let resp = self.sign_and_post("GET", &full_url, &json!({})).await?;
        Ok(resp)
    }

    /// 解冻剩余资金（完结分账）
    /// 文档：https://pay.weixin.qq.com/doc/v3/partner/4012466860 [citation:3]
    pub async fn unfreeze_profitsharing(&self, mut order: Value) -> Result<Value, PayError> {
        // 构建服务商参数
        order = self.build_service_params(order);
        let url = self.get_service_url("/v3/profitsharing/orders/unfreeze");
        // 发送请求
        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    /// 请求分账回退（用于退款场景）
    pub async fn profitsharing_return(&self, mut order: Value) -> Result<Value, PayError> {
        order = self.build_service_params(order);

        let url = self.get_service_url("/v3/profitsharing/return-orders");

        let resp = self.sign_and_post("POST", &url, &order).await?;
        Ok(resp)
    }

    /// 处理接收方名称加密
    async fn process_receiver_name_encryption(
        &self,
        receiver_type: &str,
        order: &mut Value,
    ) -> Result<Option<String>, PayError> {
        // 判断是否需要加密名称
        let need_encryption = matches!(receiver_type, "MERCHANT_ID")
            || (order.get("name").is_some()
                && matches!(receiver_type, "PERSONAL_OPENID" | "PERSONAL_SUB_OPENID"));

        if !need_encryption {
            return Ok(None);
        }

        // 关键修复：先将 name 值提取出来，再修改 order
        let name_str = if let Some(name_value) = order.get("name") {
            name_value
                .as_str()
                .ok_or_else(|| PayError::Other("'name' must be a string".into()))?
        } else {
            return Err(PayError::Other(
                "'name' field is required for this receiver type".into(),
            ));
        };

        // 获取平台证书信息
        let (cert_sn, public_key_pem) = self
            .get_platform_certificate_info()
            .await
            .map_err(|e| PayError::Other(format!("Failed to get platform certificate: {}", e)))?;

        tracing::info!("🔐 使用平台证书加密名称 - 序列号: {}", cert_sn);
        tracing::info!("📝 原始名称: {}", name_str);

        // 加密名称
        let encrypted_name =
            crate::utils::rsa_encrypt_oaep_with_public_key_pem(&public_key_pem, name_str)
                .map_err(|e| PayError::Crypto(format!("Failed to encrypt receiver name: {}", e)))?;

        tracing::info!("🔒 加密后名称(Base64): {}", encrypted_name);

        // 现在安全地修改 order
        if let Some(name_field) = order.get_mut("name") {
            *name_field = json!(encrypted_name);
        }

        Ok(Some(cert_sn))
    }

    async fn get_platform_certificate_info(&self) -> Result<(String, String), PayError> {
        let mut certs = self.certs.get_first_cert();

        // 2️⃣ 如果没有，就尝试 refresh 一次再取
        if certs.is_none() {
            if let Err(e) = self.certs.refresh().await {
                return Err(PayError::Crypto(format!("refresh certs failed: {}", e)));
            }
            certs = self.certs.get_first_cert();
        }
        // 3️⃣ 还是没有，就报错
        let (cert_sn,pub_pem) = certs.ok_or_else(|| {
            PayError::Other(format!("platform cert {} not found after refresh", "none"))
        })?;
        if pub_pem.is_empty() {
            return Err(PayError::Other(
                "wechat notify platform public key empty".to_string(),
            ));
        }

        Ok((cert_sn, pub_pem))
    }

    /// 发送分账请求（完整实现）
    async fn send_profitsharing_request(
        &self,
        method: &str,
        url: &str,
        body: &Value,
        wechatpay_serial: Option<String>,
    ) -> Result<Value, PayError> {
        // 1. 准备请求体和路径
        let body_str = body.to_string();
        let parsed_url =
            Url::parse(url).map_err(|e| PayError::Other(format!("Failed to parse URL: {}", e)))?;

        let path_and_query = if let Some(query) = parsed_url.query() {
            format!("{}?{}", parsed_url.path(), query)
        } else {
            parsed_url.path().to_string()
        };

        // 2. 生成签名所需参数
        let timestamp = now_ts();
        let nonce = gen_nonce(32);

        // 3. 生成待签名字符串（关键步骤）
        let sign_str = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            method, path_and_query, timestamp, nonce, body_str
        );


        // 4. 使用商户私钥进行签名（注意：这里是签名，不是加密）
        let signature = rsa_sign_sha256_pem(&self.cfg.private_key_pem, &sign_str)
            .map_err(|e| PayError::Crypto(format!("Failed to sign request: {}", e)))?;

        // 5. 构建Authorization头
        let auth_header = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}""#,
            self.cfg.mchid, nonce, timestamp, self.cfg.serial_no, signature
        );

        // 6. 构建HTTP请求
        let client = &self.http;
        let mut request_builder = match method {
            "GET" => client.get(url),
            "POST" => client.post(url),
            _ => {
                return Err(PayError::Other(format!(
                    "Unsupported HTTP method: {}",
                    method
                )))
            }
        };

        // 7. 设置请求头
        request_builder = request_builder
            .header("Authorization", auth_header)
            .header("Accept", "application/json")
            .header("User-Agent", "rust_pay_wf")
            .header("Content-Type", "application/json");

        // 8. 添加Wechatpay-Serial头（如果提供了证书序列号）
        if let Some(serial) = wechatpay_serial {
            request_builder = request_builder.header("Wechatpay-Serial", serial.clone());
            tracing::info!("已设置Wechatpay-Serial头: {}", serial);
        }

        // 9. 设置请求体（POST请求）
        if method == "POST" {
            request_builder = request_builder.body(body_str.clone());
            tracing::info!("请求体: {}", body_str);
        }

        // 10. 发送请求
        let response = request_builder
            .send()
            .await
            .map_err(|e| PayError::Other(format!("HTTP request failed: {}", e)))?;

        let status_code = response.status();
        let response_text = response
            .text()
            .await
            .map_err(|e| PayError::Other(format!("Failed to read response: {}", e)))?;

        tracing::info!("响应状态: {}, 响应体: {}", status_code, response_text);

        // 11. 处理响应
        if !status_code.is_success() {
            let error_summary = if !response_text.is_empty() {
                format!("HTTP {} - {}", status_code, response_text)
            } else {
                format!("HTTP {}", status_code)
            };

            return Err(PayError::Other(format!(
                "Request failed: {}",
                error_summary
            )));
        }

        // 12. 解析JSON响应
        serde_json::from_str(&response_text)
            .map_err(|e| PayError::Other(format!("Failed to parse JSON response: {}", e)))
    }
}
