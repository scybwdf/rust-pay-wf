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
    pub appid: Option<String>,//主商户appid，服务号
    pub serial_no: String,
    pub private_key_pem: String,
    pub api_v3_key: String,
    pub platform_public_key_pem: String,
    pub appid_mp: Option<String>,
    pub appid_mini: Option<String>,
    pub appid_app: Option<String>,
    pub sub_mchid: Option<String>,
    pub notify_url: Option<String>,
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
    pub notify_url: Option<String>,
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
