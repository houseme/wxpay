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
        tx.transaction_id
    );

    // 2) 退款。仅当存在 transaction_id 时才有意义。
    let refund_amount = 1; // 退款金额（分），演示退全款 0.01 元。
    let request = RefundRequest {
        transaction_id: Some(tx.transaction_id.clone()),
        out_trade_no: Some(out_trade_no.clone()),
        out_refund_no: format!("refund_{}", chrono::Utc::now().timestamp_millis()),
        reason: Some("示例退款".to_string()),
        amount: RefundAmount {
            refund: refund_amount,
            total: refund_amount,
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
