//! 平台证书元数据查询演示：拉取序列号和有效期。
//!
//! 真实调用微信 API，需要完整商户凭证。凭证缺失时会打印设置指引并退出。
//! 序列号和有效期不包含公钥，不能单独用于验签。
//! 完整证书需通过已认证的 CertDownloader 下载、解密并更新到证书管理器。
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
        "\n✓ 查询到 {} 张平台证书的元数据。验签需完整平台证书或平台公钥，不能只保存序列号。",
        certs.len()
    );
    Ok(())
}
