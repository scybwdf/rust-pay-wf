use serde_json::json;
use std::sync::Arc;
use rust_pay_wf::config::{
    AlipayConfig, Mode, PayConfig, UnionpayConfig, WechatConfig,
};
use rust_pay_wf::Pay;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let wx = Arc::new(WechatConfig {
        mchid: "your_mchid".into(),
        serial_no: "your_serial".into(),
        private_key_pem: include_str!("../certs/wechat_apiclient_key.pem").to_string(),
        api_v3_key: "32_byte_api_v3_key_here___________".into(),
        platform_public_key_pem: include_str!("../certs/wechat_platform_pub.pem").to_string(),
        appid_mp: Some("wx_mp_appid".into()),
        appid_mini: Some("wx_miniprogram_appid".into()),
        appid_app: Some("wx_app_appid".into()),
        sub_mchid: Some("your_sub_mchid".into()),
        sub_appid: Some("your_sub_appid".into()),
    });
    let ali = Arc::new(AlipayConfig {
        app_id: "your_alipay_appid".into(),
        gateway: "https://openapi.alipay.com/gateway.do".into(),
        private_key_pem: include_str!("../certs/alipay_private.pem").to_string(),
        alipay_public_key_pem: include_str!("../certs/alipay_public.pem").to_string(),
        charset: "utf-8".into(),
        sign_type: "RSA2".into(),
        sub_merchant_id: Some("your_sub_merchant_id".into()),
    });
    let cfg = PayConfig {
        mode: Mode::Service,
        wechat: Some(wx),
        alipay: Some(ali),
        unionpay: None,
    };
    Pay::config(cfg);

    let order = json!({ "out_trade_no": format!("{}", chrono::Utc::now().timestamp()), "description": "subject-测试", "amount": { "total": 1 }, "payer": { "openid": "onkVf1FjWS5SBxxxxxxxx" }, "notify_url": "https://example.com/notify/wechat" });
    let res = Pay::wechat().mp(order).await?;
    println!("wechat mp res: {:?}", res);

    let mini_order = json!({ "out_trade_no": format!("{}-mini", chrono::Utc::now().timestamp()), "description": "mini-测试", "amount": { "total": 1 }, "payer": { "openid": "omy_openid" }, "notify_url": "https://example.com/notify/wechat" });
    let res_m = Pay::wechat().mini(mini_order).await?;
    println!("wechat mini res: {:?}", res_m);

    let h5_order = json!({ "out_trade_no": format!("{}-h5", chrono::Utc::now().timestamp()), "description": "h5-测试", "amount": { "total": 1 }, "scene_info": { "payer_client_ip": "1.2.3.4", "h5_info": { "type": "Wap" } }, "notify_url": "https://example.com/notify/wechat" });
    let res_h5 = Pay::wechat().h5(h5_order).await?;
    println!("wechat h5 res: {:?}", res_h5);

    let app_order = json!({ "out_trade_no": format!("{}-app", chrono::Utc::now().timestamp()), "description": "app-测试", "amount": { "total": 1 }, "notify_url": "https://example.com/notify/wechat" });
    let res_app = Pay::wechat().app(app_order).await?;
    println!("wechat app res: {:?}", res_app);

    let ali_order = json!({ "out_trade_no": format!("{}", chrono::Utc::now().timestamp()), "subject": "测试商品", "total_amount": "0.01", "notify_url": "https://example.com/notify/alipay" });
    let ali_res = Pay::alipay().app(ali_order).await?;
    println!("alipay app res: {:?}", ali_res);

    Ok(())
}
