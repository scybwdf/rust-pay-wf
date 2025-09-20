use crate::config::PayConfig;
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
    pub fn wechat() -> crate::wechat::client::WechatClient {
        let cfg = Self::cfg();
        let wx = cfg.wechat.clone().expect("wechat config missing");
        crate::wechat::client::WechatClient::with_mode(wx, cfg.mode.clone())
    }
    pub fn alipay() -> crate::alipay::client::AlipayClient {
        let cfg = Self::cfg();
        let ali = cfg.alipay.clone().expect("alipay config missing");
        crate::alipay::client::AlipayClient::with_mode(ali, cfg.mode.clone())
    }
    pub fn unionpay() -> crate::unionpay::client::UnionClient {
        let cfg = Self::cfg();
        let up = cfg.unionpay.clone().expect("unionpay config missing");
        crate::unionpay::client::UnionClient::new(up)
    }
}
