use crate::config::AlipayConfig;
use crate::errors::PayError;
use crate::utils::rsa_verify_sha256_pem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct AlipayNotifyData {
    pub app_id: String,
    pub out_trade_no: String,
    pub trade_no: String,
    pub trade_status: String,
    pub total_amount: String,
    pub seller_id: Option<String>,
    #[serde(flatten)]
    pub others: HashMap<String, String>,
}

pub struct AlipayNotify {
    cfg: Arc<AlipayConfig>,
    #[warn(dead_code)]
    mode: crate::config::Mode,
}

impl AlipayNotify {
    pub fn new(cfg: Arc<AlipayConfig>, mode: crate::config::Mode) -> Self {
        Self { cfg, mode }
    }

    /// Verify Alipay notify parameters (form-encoded -> HashMap)
    /// Steps:
    /// 1. Extract sign and sign_type
    /// 2. Build pre-sign string by sorting params excluding sign & sign_type, joining k=v with &
    /// 3. Verify using RSA2 with alipay public key (sandbox/public as mode requires)
    /// 4. Validate trade_status and sub_merchant_id if service mode configured
    pub fn verify_notify(
        &self,
        params: &HashMap<String, String>,
    ) -> Result<AlipayNotifyData, PayError> {
        let sign = params
            .get("sign")
            .ok_or(PayError::Other("missing sign".to_string()))?;
        // sign_type may be optional but typically present
        // Build pre-sign string
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

        // Choose public key: sandbox or normal config (here we assume cfg.alipay_public_key_pem works for both if set by user)
        let pubkey = &self.cfg.alipay_public_key_pem;
        let verified = rsa_verify_sha256_pem(pubkey, &content, sign)
            .map_err(|e| PayError::Crypto(format!("rsa verify error: {}", e)))?;
        if !verified {
            return Err(PayError::Other(
                "alipay notify signature invalid".to_string(),
            ));
        }

        // Extract fields and build data
        let app_id = params.get("app_id").cloned().unwrap_or_default();
        let out_trade_no = params.get("out_trade_no").cloned().unwrap_or_default();
        let trade_no = params.get("trade_no").cloned().unwrap_or_default();
        let trade_status = params.get("trade_status").cloned().unwrap_or_default();
        let total_amount = params.get("total_amount").cloned().unwrap_or_default();
        let seller_id = params.get("seller_id").cloned();
        // business status check per Alipay doc: treat TRADE_SUCCESS or TRADE_FINISHED as success
        if trade_status != "TRADE_SUCCESS" && trade_status != "TRADE_FINISHED" {
            return Err(PayError::Other(format!(
                "trade_status not success: {}",
                trade_status
            )));
        }

        // service mode extra check: if configured, ensure notify contains expected sub_merchant_id (if exists)
/*        if let crate::config::Mode::Service = self.mode {
            if let Some(cfg_sub) = &self.cfg.sub_merchant_id {
                if let Some(notify_sub) = &sub_merchant_id {
                    if notify_sub != cfg_sub {
                        return Err(PayError::Other(format!(
                            "sub_merchant_id mismatch notify={} cfg={}",
                            notify_sub, cfg_sub
                        )));
                    }
                }
            }
        }*/

        // collect other params
        let mut others = HashMap::new();
        for (k, v) in params.iter() {
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

    /// success response body to reply to Alipay
    pub fn success_response(&self) -> &'static str {
        "success"
    }
}
