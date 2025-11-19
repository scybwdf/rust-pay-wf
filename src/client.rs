use crate::config::{AlipayConfigOverride, PayConfig, WechatConfigOverride};
use once_cell::sync::OnceCell;
use std::sync::Arc;
static CONFIG: OnceCell<Arc<PayConfig>> = OnceCell::new();
pub struct Pay;
impl Pay {
    pub fn config(cfg: PayConfig) {
        let _ = CONFIG.set(Arc::new(cfg));
    }
    fn cfg() -> Arc<PayConfig> {
        CONFIG.get().expect("config not initialized").clone()
    }
    pub fn is_config() -> bool {
        CONFIG.get().is_some()
    }
    pub fn wechat(over_config: Option<WechatConfigOverride>) -> crate::wechat::client::WechatClient {
        let cfg = Self::cfg();
        let wx = cfg.wechat.clone().expect("wechat config missing");
        let mut final_config = (*wx).clone();  // 显式克隆内部数据

        if let Some(over_config) = over_config {
            // 应用覆盖配置
            if let Some(sub_mchid) = over_config.sub_mchid {
                if !sub_mchid.is_empty() {
                    final_config.sub_mchid = Some(sub_mchid);
                }
            }
        }
        let final_wx_config = Arc::new(final_config);
        crate::wechat::client::WechatClient::with_mode(final_wx_config, cfg.mode.clone())
    }
    pub fn alipay(over_config: Option<AlipayConfigOverride>) -> crate::alipay::client::AlipayClient {
        let cfg = Self::cfg();
        let ali = cfg.alipay.clone().expect("alipay config missing");
        let mut final_config = (*ali).clone();  // 显式克隆内部数据
        if let Some(over_config) = over_config {
            // 应用覆盖配置
            if let Some(app_auth_token) = over_config.app_auth_token {
                if !app_auth_token.is_empty() {
                    final_config.app_auth_token = Some(app_auth_token);
                }
            }
        }
        let final_ali_config = Arc::new(final_config);
        crate::alipay::client::AlipayClient::with_mode(final_ali_config, cfg.mode.clone())
    }
    pub fn unionpay() -> crate::unionpay::client::UnionClient {
        let cfg = Self::cfg();
        let up = cfg.unionpay.clone().expect("unionpay config missing");
        crate::unionpay::client::UnionClient::new(up)
    }
}
