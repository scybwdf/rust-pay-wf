use crate::config::{AlipayConfig};
use crate::errors::PayError;
use crate::utils::{rsa_verify_sha256_pem};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct AlipayNotifyData {
    pub app_id: String,
    pub out_trade_no: String,
    pub trade_no: String,
    pub trade_status: String,
    pub total_amount: String,
    pub seller_id: Option<String>,
    pub others: HashMap<String, String>,
}

pub struct AlipayNotify {
    cfg: Arc<AlipayConfig>,
}

impl AlipayNotify {
    pub fn new(cfg: Arc<AlipayConfig>) -> Self {
        Self { cfg }
    }

    /// Verify Alipay notify parameters
    pub fn verify_notify(
        &self,
        params: &HashMap<String, String>,
    ) -> Result<AlipayNotifyData, PayError> {
        // ---- Step 1. 提取 sign 和 sign_type ----
        let sign = params
            .get("sign")
            .ok_or_else(|| PayError::Other("missing sign".to_string()))?;
       // let sign_type = params.get("sign_type").cloned().unwrap_or_default();

        // ---- Step 2. 构造待签名字符串 ----
        let mut kv: Vec<(&String, &String)> = params
            .iter()
            .filter(|&(k, _)| k != "sign" && k != "sign_type")
            .collect();
        kv.sort_by(|a, b| a.0.cmp(b.0));
        let content = kv
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        // ---- Step 3. 选择验签公钥 ----
        let mut pubkey_pem = String::new();

        // 1) 证书模式优先（推荐生产使用）
        if let Some(cert_path) = &self.cfg.alipay_cert_path {
            if let Ok(pem) = fs::read_to_string(cert_path) {
                pubkey_pem = pem;
            }
        }
        // 2) 如果没配置证书，则使用公钥字符串模式
        if pubkey_pem.is_empty() {
            pubkey_pem = self.cfg.alipay_public_key.clone().unwrap_or_default();
        }

        if pubkey_pem.is_empty() {
            return Err(PayError::Other("missing alipay public key".into()));
        }

        // ---- Step 4. 验签 ----
        let verified = rsa_verify_sha256_pem(&pubkey_pem, &content, sign)
            .map_err(|e| PayError::Crypto(format!("rsa verify error: {}", e)))?;
        if !verified {
            return Err(PayError::Other("alipay notify signature invalid".into()));
        }

        // ---- Step 5. 核心字段解析 ----
        let app_id = params.get("app_id").cloned().unwrap_or_default();
        let out_trade_no = params.get("out_trade_no").cloned().unwrap_or_default();
        let trade_no = params.get("trade_no").cloned().unwrap_or_default();
        let trade_status = params.get("trade_status").cloned().unwrap_or_default();
        let total_amount = params.get("total_amount").cloned().unwrap_or_default();
        let seller_id = params.get("seller_id").cloned();

        // ---- Step 6. 检查交易状态 ----
        if trade_status != "TRADE_SUCCESS" && trade_status != "TRADE_FINISHED" {
            return Err(PayError::Other(format!(
                "trade_status not success: {}",
                trade_status
            )));
        }

        // ---- Step 7. 服务商模式检查 ----
 /*       if let Mode::Service = self.cfg.mode {
            if let Some(cfg_pid) = &self.cfg.sub_merchant_id {
                if let Some(notify_pid) = params.get("sub_merchant_id") {
                    if notify_pid != cfg_pid {
                        return Err(PayError::Other(format!(
                            "sub_merchant_id mismatch: notify={}, cfg={}",
                            notify_pid, cfg_pid
                        )));
                    }
                }
            }
        }*/

        // ---- Step 8. 收集剩余字段 ----
        let mut others = HashMap::new();
        for (k, v) in params {
            if k != "sign" && k != "sign_type" {
                others.insert(k.clone(), v.clone());
            }
        }

        Ok(AlipayNotifyData {
            app_id,
            out_trade_no,
            trade_no,
            trade_status,
            total_amount,
            seller_id,
            others,
        })
    }

    /// 成功响应内容
    pub fn success_response(&self) -> &'static str {
        "success"
    }
}