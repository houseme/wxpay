//! 商家转账 + 分账演示：发起一笔批量转账，再创建一笔分账单。
//!
//! 真实调用微信 API，需要完整商户凭证。凭证缺失时会打印设置指引并退出。
//! 收款方 openid 可用 `WXPAY_PAYEE_OPENID` 环境变量覆盖。
//!
//! 运行：`cargo run --example transfer_and_profit_sharing`

#[path = "common/mod.rs"]
mod common;

use wxpay_rs::WxPayClient;
use wxpay_rs::services::profit_sharing::{ProfitSharingRequest, Receiver};
use wxpay_rs::services::transfer::{TransferDetail, TransferRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(config) = common::load_config()? else {
        return Ok(());
    };
    let client = WxPayClient::new(config).await?;

    let payee_openid = common::opt_env("WXPAY_PAYEE_OPENID", "oUpF8uMuAJO_M2pxb1Q9zNjWeS6o");
    let ts = chrono::Utc::now().timestamp_millis();

    // 1) 商家转账（批量转账到零钱）。
    let transfer = TransferRequest {
        appid: client.config().app_id.clone(),
        out_batch_no: format!("batch_{ts}"),
        batch_name: "示例转账批次".to_string(),
        batch_remark: "示例批次备注".to_string(),
        transfer_detail_list: vec![TransferDetail {
            out_detail_no: format!("detail_{ts}"),
            transfer_amount: 100, // 单位：分（1 元）
            transfer_remark: "示例转账".to_string(),
            openid: payee_openid.clone(),
            user_name: None,
        }],
        total_amount: 100,
        total_num: 1,
    };

    println!("发起批量转账：{}", transfer.out_batch_no);
    let resp = client.transfer().create_transfer(&transfer).await?;
    println!(
        "✓ 转账已受理：batch_id={}, status={}",
        resp.batch_id, resp.batch_status
    );

    // 2) 分账（基于一笔已成功的交易）。此处 transaction_id 仅为演示占位。
    let profit = ProfitSharingRequest {
        transaction_id: common::opt_env("WXPAY_TRANSACTION_ID", "4200000000000000000"),
        out_order_no: format!("ps_{ts}"),
        receivers: vec![Receiver {
            receiver_type: "MERCHANT_ID".to_string(),
            account: client.config().merchant_id.clone(),
            amount: 10, // 分账金额（分）
            description: "示例分账".to_string(),
            name: None,
        }],
        description: "示例分账单".to_string(),
    };

    println!("发起分账：{}", profit.out_order_no);
    let ps = client.profit_sharing().create_order(&profit).await?;
    println!(
        "✓ 分账已受理：order_id={}, status={}",
        ps.order_id, ps.status
    );
    Ok(())
}
