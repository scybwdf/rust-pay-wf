use axum::{body::Bytes, extract::Form, http::HeaderMap, routing::post, Json, Router};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use rust_pay_wf::{Pay, PayError};
use rust_pay_wf::alipay::AlipayNotify;
use rust_pay_wf::config::{AlipayConfig, Mode, PayConfig, WechatConfig};

// Example for handling Alipay notify: Axum Form extractor will parse application/x-www-form-urlencoded into a map
#[derive(serde::Deserialize)]
struct AlipayForm(std::collections::HashMap<String, String>);

async fn notify_alipay(Form(map): Form<std::collections::HashMap<String, String>>) -> String {
    let wx = Arc::new(WechatConfig {
        mchid: "your_mchid".into(),
        serial_no: "your_serial".into(),
        sp_appid: Some("wx_sp_appid".into()),
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

    // Use Pay::alipay().verify_notify
    match Pay::alipay().verify_notify(&map) {
        Ok(data) => {
            println!("alipay notify verified: {:?}", data);
            // business validation e.g. check order amount/out_trade_no...
            // reply success
          /* AlipayNotify::new(
                Pay::alipay().cfg.clone(),
                Pay::alipay().mode.clone(),
            )
            .success_response()
            .to_string()*/
        }
        Err(e) => {
            eprintln!("alipay notify verify failed: {:?}", e);
            "failure".to_string()
        }
    }
}

async fn notify_wechat(headers: HeaderMap, body: Bytes) -> Json<serde_json::Value> {
    let body_str = std::str::from_utf8(&body).unwrap_or("");
    let mut hm = std::collections::HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            hm.insert(k.as_str().to_string(), s.to_string());
        }
    }
    Json(json!({"received": body_str, "headers": hm}))
}

#[tokio::main]
async fn main() {
    // Note: examples assume Pay::config was called in another context.
    let app = Router::new()
        .route("/notify/alipay", post(notify_alipay))
        .route("/notify/wechat", post(notify_wechat));
    println!("Server running on 0.0.0.0:8080");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
