//! Native 下单演示：创建一笔扫码支付订单并打印 `code_url`。
//!
//! 真实调用微信 API，需要完整商户凭证。凭证缺失时会打印设置指引并退出。
//!
//! 运行：`cargo run --example payment_native`

#[path = "common/mod.rs"]
mod common;

use wxpay_rs::WxPayClient;
use wxpay_rs::services::payments::jsapi::Amount;
use wxpay_rs::services::payments::native::NativeRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(config) = common::load_config()? else {
        return Ok(());
    };
    let client = WxPayClient::new(config).await?;

    let request = NativeRequest {
        appid: client.config().app_id.clone(),
        mchid: client.config().merchant_id.clone(),
        description: "Native 示例订单".to_string(),
        out_trade_no: format!("native_{}", chrono::Utc::now().timestamp_millis()),
        amount: Some(Amount {
            total: 1, // 单位：分（0.01 元）
            currency: Some("CNY".to_string()),
        }),
        notify_url: Some(common::opt_env(
            "WXPAY_NOTIFY_URL",
            "https://example.com/wxpay/notify",
        )),
    };

    println!("发起 Native 下单：{}", request.out_trade_no);
    let resp = client.native().create_order(&request).await?;
    println!("✓ 下单成功");
    println!("code_url : {}", resp.code_url);
    println!("用该 code_url 生成二维码后即可被微信扫码支付。");
    Ok(())
}
