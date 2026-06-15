//! 证书下载器模块
//!
//! 提供从微信支付 API 下载平台证书的功能。

use std::sync::Arc;
use async_trait::async_trait;

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::cert::CertManager;
use crate::utils::nonce::generate_nonce;
use crate::utils::timestamp::get_timestamp;

/// 证书下载器 trait
///
/// 定义了下载平台证书的接口。
#[async_trait]
pub trait CertificateDownloader: Send + Sync {
    /// 下载平台证书
    ///
    /// # 返回
    ///
    /// 返回下载的证书列表（序列号 -> DER 格式）
    async fn download(&self) -> WxPayResult<Vec<(String, Vec<u8>)>>;
}

/// 微信支付证书下载器
///
/// 从微信支付 API 下载平台证书。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::cert::CertDownloader;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let downloader = CertDownloader::new(
///     "https://api.mch.weixin.qq.com",
///     "1900000109",
///     signer,
///     http_client,
///     cert_manager,
/// );
///
/// let certificates = tokio::runtime::Runtime::new()?.block_on(downloader.download())?;
/// # Ok(())
/// # }
/// ```
pub struct CertDownloader {
    /// API 基础 URL
    base_url: String,

    /// 商户号
    merchant_id: String,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 证书管理器
    cert_manager: Arc<CertManager>,
}

impl CertDownloader {
    /// 创建新的证书下载器
    ///
    /// # 参数
    ///
    /// * `base_url` - API 基础 URL
    /// * `merchant_id` - 商户号
    /// * `signer` - 签名器
    /// * `http_client` - HTTP 客户端
    /// * `cert_manager` - 证书管理器
    ///
    /// # 返回
    ///
    /// 返回证书下载器实例
    pub fn new(
        base_url: impl Into<String>,
        merchant_id: impl Into<String>,
        signer: Arc<dyn Signer>,
        http_client: Arc<dyn HttpClient>,
        cert_manager: Arc<CertManager>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            merchant_id: merchant_id.into(),
            signer,
            http_client,
            cert_manager,
        }
    }

    /// 构建下载证书的请求 URL
    fn build_url(&self) -> String {
        format!("{}/v3/certificates", self.base_url)
    }

    /// 构建请求头
    async fn build_headers(&self) -> WxPayResult<Vec<(String, String)>> {
        let timestamp = get_timestamp();
        let nonce = generate_nonce();
        let url = "/v3/certificates";
        let body = "";

        // 构建签名消息
        let message = format!("GET\n{}\n{}\n{}\n{}\n", url, timestamp, nonce, body);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        // 构建 Authorization header
        let authorization = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}"#,
            self.merchant_id, nonce, timestamp, self.signer.cert_serial_number(), signature
        );

        Ok(vec![
            ("Authorization".to_string(), authorization),
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "wxpay-rs/0.1.0".to_string()),
        ])
    }
}

#[async_trait]
impl CertificateDownloader for CertDownloader {
    async fn download(&self) -> WxPayResult<Vec<(String, Vec<u8>)>> {
        let url = self.build_url();
        let headers = self.build_headers().await?;

        // 发送请求
        let response = self.http_client.get(&url, headers).await?;

        // 检查响应状态
        if !response.is_success() {
            return Err(WxPayError::CertificateDownloadError(format!(
                "下载证书失败，HTTP 状态码: {}",
                response.status
            )));
        }

        // 解析响应
        let body = &response.body;
        let certificates: serde_json::Value = serde_json::from_str(body)?;

        let mut result = Vec::new();

        if let Some(certs) = certificates.as_array() {
            for cert in certs {
                if let (Some(serial), Some(cert_data)) = (
                    cert.get("serial_no").and_then(|s| s.as_str()),
                    cert.get("certificate").and_then(|c| c.as_str()),
                ) {
                    // 解码证书数据
                    use base64::Engine;
                    let cert_der = base64::engine::general_purpose::STANDARD
                        .decode(cert_data)
                        .map_err(|e| {
                            WxPayError::CertificateParseError(format!(
                                "证书 Base64 解码失败: {}",
                                e
                            ))
                        })?;

                    // 添加到证书管理器
                    self.cert_manager
                        .add_certificate(serial.to_string(), cert_der.clone())
                        .await?;

                    result.push((serial.to_string(), cert_der));
                }
            }
        }

        Ok(result)
    }
}

impl std::fmt::Debug for CertDownloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertDownloader")
            .field("base_url", &self.base_url)
            .field("merchant_id", &self.merchant_id)
            .finish()
    }
}

/// 证书自动刷新器
///
/// 定期刷新平台证书。
pub struct CertRefresher {
    /// 证书下载器
    downloader: Arc<CertDownloader>,

    /// 刷新间隔（秒）
    interval: u64,
}

impl CertRefresher {
    /// 创建新的证书刷新器
    ///
    /// # 参数
    ///
    /// * `downloader` - 证书下载器
    /// * `interval` - 刷新间隔（秒）
    ///
    /// # 返回
    ///
    /// 返回证书刷新器实例
    pub fn new(downloader: Arc<CertDownloader>, interval: u64) -> Self {
        Self { downloader, interval }
    }

    /// 启动自动刷新
    ///
    /// 在后台任务中定期刷新证书。
    pub fn start_auto_refresh(&self) {
        let downloader = self.downloader.clone();
        let interval = self.interval;

        tokio::spawn(async move {
            loop {
                // 等待指定间隔
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

                // 下载证书
                match downloader.download().await {
                    Ok(certificates) => {
                        tracing::info!("成功刷新 {} 个证书", certificates.len());
                    }
                    Err(e) => {
                        tracing::error!("刷新证书失败: {}", e);
                    }
                }
            }
        });
    }
}

impl std::fmt::Debug for CertRefresher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertRefresher")
            .field("interval", &self.interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_downloader_build_url() {
        // 这个测试需要实际的依赖，跳过
    }
}
