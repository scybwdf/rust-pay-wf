use std::sync::Arc;
#[derive(Clone)]
pub enum Mode {
    Normal,
    Service,
    Sandbox,
}
#[derive(Clone)]
pub struct WechatConfig {
    pub mchid: String,
    pub serial_no: String,
    pub private_key_pem: String,
    pub api_v3_key: String,
    pub platform_public_key_pem: String,
    pub appid_mp: Option<String>,
    pub appid_mini: Option<String>,
    pub appid_app: Option<String>,
    
    pub sp_appid: Option<String>,
    pub sub_mchid: Option<String>,
    pub sub_appid: Option<String>,
}
#[derive(Clone)]
pub struct AlipayConfig {
    pub app_id: String,
    pub gateway: String,
    pub private_key_pem: String,
    pub alipay_public_key_pem: String,
    pub charset: String,
    pub sign_type: String,
    pub sub_merchant_id: Option<String>,
}
#[derive(Clone)]
pub struct UnionpayConfig {
    pub mer_id: String,
}
#[derive(Clone)]
pub struct PayConfig {
    pub mode: Mode,
    pub wechat: Option<Arc<WechatConfig>>,
    pub alipay: Option<Arc<AlipayConfig>>,
    pub unionpay: Option<Arc<UnionpayConfig>>,
}
