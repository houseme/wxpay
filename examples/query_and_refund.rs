//! 查单 + 退款演示：按商户订单号查询订单状态，再对该订单发起退款。
//!
//! 真实调用微信 API，需要完整商户凭证。凭证缺失时会打印设置指引并退出。
//! 可用 `WXPAY_OUT_TRADE_NO` 环境变量覆盖待查询的订单号。
//!
//! 运行：`cargo run --example query_and_refund`

#[path = "common/mod.rs"]
mod common;

use wxpay_rs::WxPayClient;
use wxpay_rs::services::refund::{RefundAmount, RefundRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(config) = common::load_config()? else {
        return Ok(());
    };
    let client = WxPayClient::new(config).await?;

    let out_trade_no = common::opt_env("WXPAY_OUT_TRADE_NO", "out_demo_001");

    // 1) 查单。
    println!("查询订单：{out_trade_no}");
    let tx = client.query_order_by_out_trade_no(&out_trade_no).await?;
    println!(
        "✓ 交易状态：{}（{}），微信订单号：{}",
        tx.trade_state,
        tx.trade_state_desc.as_deref().unwrap_or(""),
        tx.transaction_id.as_deref().unwrap_or("尚未支付")
    );

    // 仅对已支付的查询结果退款，并以查询到的原订单金额作为 total。
    if tx.trade_state != "SUCCESS" {
        println!("订单尚未支付成功，跳过退款");
        return Ok(());
    }
    let transaction_id = tx.transaction_id.ok_or("已支付订单缺少 transaction_id")?;
    let total = tx.amount.ok_or("查询结果缺少原订单金额")?.total;
    let refund_amount = 1; // 示例部分退款 0.01 元。
    let request = RefundRequest {
        transaction_id: Some(transaction_id),
        out_trade_no: None,
        out_refund_no: format!("refund_{}", chrono::Utc::now().timestamp_millis()),
        reason: Some("示例退款".to_string()),
        amount: RefundAmount {
            refund: refund_amount,
            total,
            currency: "CNY".to_string(),
        },
        notify_url: Some(common::opt_env(
            "WXPAY_REFUND_NOTIFY_URL",
            "https://example.com/wxpay/refund-notify",
        )),
    };

    println!("发起退款：{}", request.out_refund_no);
    let refund = client.refund().create_refund(&request).await?;
    println!(
        "✓ 退款已受理：refund_id={}, status={}",
        refund.refund_id, refund.status
    );
    Ok(())
}
