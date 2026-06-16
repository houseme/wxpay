//! 请求签名演示：手工构造微信支付 APIv3 签名消息并生成 Authorization 头。
//!
//! 不发起真实请求，仅演示“签名”这一步——这也是 SDK [`ServiceTransport`] 在每次请求前内部完成的工作。
//! 需要商户私钥，凭证缺失时会打印设置指引并退出。
//!
//! 运行：`cargo run --example signing_demo`
//!
//! `common/mod.rs` 通过相对路径引入，作为示例间的共享加载逻辑。

#[path = "common/mod.rs"]
mod common;

use wxpay_rs::auth::{Sha256RsaSigner, Signer};
use wxpay_rs::utils::{nonce::generate_nonce, timestamp::get_timestamp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(config) = common::load_config()? else {
        return Ok(());
    };

    // 1) 用一个代表性请求演示签名规范串（与微信 APIv3 一致，行尾均含 \n）。
    let method = "GET";
    // 规范 URL：去除 host 与 query 前缀 '?'，仅保留路径与查询串。
    let canonical_url = "/v3/pay/transactions/out-trade-no/out_demo_001?mchid=1900000109";
    let timestamp = get_timestamp().to_string();
    let nonce = generate_nonce();
    let body = ""; // GET 请求体为空。

    let sign_message = format!("{method}\n{canonical_url}\n{timestamp}\n{nonce}\n{body}\n");
    println!("=== 待签名规范串 ===\n{sign_message}");

    // 2) 用商户私钥做 SHA256-RSA 签名，输出 Base64。
    let signer = Sha256RsaSigner::new(
        &config.merchant_id,
        &config.private_key,
        &config.cert_serial_number,
    )?;
    let signature = signer.sign(&sign_message).await?;
    println!("=== 签名（Base64）===\n{signature}\n");

    // 3) 组装 Authorization 头（这是 SDK 实际发送给微信的鉴权头）。
    let authorization = format!(
        "WECHATPAY2-SHA256-RSA2048 \
         mchid=\"{mchid}\",\
         nonce_str=\"{nonce}\",\
         timestamp=\"{timestamp}\",\
         serial_no=\"{serial}\",\
         signature=\"{signature}\"",
        mchid = config.merchant_id,
        serial = config.cert_serial_number,
    );
    println!("=== Authorization 头 ===\n{authorization}\n");

    println!("✓ signing_demo 完成（未发起真实请求）。");
    Ok(())
}
