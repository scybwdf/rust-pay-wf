use crate::config::UnionpayConfig;
use serde_json::Value;
use std::sync::Arc;
pub struct UnionClient {
    cfg: Arc<UnionpayConfig>,
}
impl UnionClient {
    pub fn new(cfg: Arc<UnionpayConfig>) -> Self {
        Self { cfg }
    }
    pub async fn web(&self, _order: Value) -> anyhow::Result<Value> {
        let _cfg = self.cfg.clone();
        Ok(serde_json::json!({"message":"unionpay web form stub"}))
    }
    pub async fn wap(&self, _order: Value) -> anyhow::Result<Value> {
        Ok(serde_json::json!({"message":"unionpay wap form stub"}))
    }
    pub async fn app(&self, _order: Value) -> anyhow::Result<Value> {
        Ok(serde_json::json!({"message":"unionpay app form stub"}))
    }
    pub async fn qrcode(&self, _order: Value) -> anyhow::Result<Value> {
        Ok(serde_json::json!({"message":"unionpay qrcode stub"}))
    }
    pub async fn b2b(&self, _order: Value) -> anyhow::Result<Value> {
        Ok(serde_json::json!({"message":"unionpay b2b stub"}))
    }
}
