//! 平台证书下载演示：拉取微信支付平台证书列表。
//!
//! 真实调用微信 API，需要完整商户凭证。凭证缺失时会打印设置指引并退出。
//! 下载到的平台证书用于“响应验签”；正式环境应定期轮换。
//!
//! 运行：`cargo run --example cert_download_demo`

#[path = "common/mod.rs"]
mod common;

use wxpay_rs::WxPayClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(config) = common::load_config()? else {
        return Ok(());
    };
    let client = WxPayClient::new(config).await?;

    println!("拉取微信支付平台证书列表…");
    let certs = client.certificates().get_certificates().await?;

    if certs.is_empty() {
        println!("（当前未返回任何平台证书）");
        return Ok(());
    }

    for (idx, cert) in certs.iter().enumerate() {
        println!(
            "[{idx}] serial_no={}\n    生效：{}\n    过期：{}",
            cert.serial_no, cert.effective_time, cert.expire_time
        );
    }

    println!(
        "\n✓ 共 {} 张平台证书。请妥善保存序列号，用于响应验签。",
        certs.len()
    );
    Ok(())
}
