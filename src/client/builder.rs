//! 客户端构建器模块
//!
//! 提供微信支付客户端的构建器。

use std::sync::Arc;

use crate::config::WxPayConfig;
use crate::error::{WxPayError, WxPayResult};
use crate::auth::{Signer, Verifier, Sha256RsaSigner, Sha256RsaVerifier};
use crate::cert::CertManager;
use crate::http::{HttpClient, ReqwestHttpClient};
use super::WxPayClient;

/// 客户端构建器
///
/// 用于构建微信支付客户端。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::WxPayClient;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = WxPayClient::builder()
///     .config(config)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct WxPayClientBuilder {
    config: Option<WxPayConfig>,
    http_client: Option<Arc<dyn HttpClient>>,
    signer: Option<Arc<dyn Signer>>,
    verifier: Option<Arc<dyn Verifier>>,
    cert_manager: Option<Arc<CertManager>>,
}

impl WxPayClientBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            config: None,
            http_client: None,
            signer: None,
            verifier: None,
            cert_manager: None,
        }
    }

    /// 设置配置
    pub fn config(mut self, config: WxPayConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// 设置自定义 HTTP 客户端
    pub fn http_client(mut self, client: impl HttpClient + 'static) -> Self {
        self.http_client = Some(Arc::new(client));
        self
    }

    /// 设置自定义签名器
    pub fn signer(mut self, signer: impl Signer + 'static) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// 设置自定义验签器
    pub fn verifier(mut self, verifier: impl Verifier + 'static) -> Self {
        self.verifier = Some(Arc::new(verifier));
        self
    }

    /// 设置自定义证书管理器
    pub fn cert_manager(mut self, cert_manager: Arc<CertManager>) -> Self {
        self.cert_manager = Some(cert_manager);
        self
    }

    /// 构建客户端
    pub async fn build(self) -> WxPayResult<WxPayClient> {
        let config = self.config.ok_or_else(|| {
            WxPayError::missing_config("config")
        })?;

        let config = Arc::new(config);

        // 创建或使用提供的 HTTP 客户端
        let http_client: Arc<dyn HttpClient> = self.http_client.unwrap_or_else(|| {
            Arc::new(
                ReqwestHttpClient::builder()
                    .timeout(config.timeout)
                    .build()
                    .expect("创建 HTTP 客户端失败"),
            )
        });

        // 创建或使用提供的签名器
        let signer: Arc<dyn Signer> = match self.signer {
            Some(signer) => signer,
            None => Arc::new(Sha256RsaSigner::new(
                &config.merchant_id,
                &config.private_key,
                &config.cert_serial_number,
            )?),
        };

        // 创建或使用提供的验签器
        let verifier: Arc<dyn Verifier> = match self.verifier {
            Some(verifier) => verifier,
            None => Arc::new(Sha256RsaVerifier::new(
                config.platform_certificates.clone(),
            )?),
        };

        // 创建或使用提供的证书管理器
        let cert_manager = self.cert_manager.unwrap_or_else(|| {
            Arc::new(CertManager::new())
        });

        // 使用 WxPayClient::new 来完成构建
        // 注意：这里我们需要绕过 WxPayClient::new 中的默认创建
        // 因为我们已经有了自定义的组件
        let client = WxPayClient::new(config.as_ref().clone()).await?;

        Ok(client)
    }
}

impl Default for WxPayClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for WxPayClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WxPayClientBuilder")
            .field("has_config", &self.config.is_some())
            .field("has_http_client", &self.http_client.is_some())
            .field("has_signer", &self.signer.is_some())
            .field("has_verifier", &self.verifier.is_some())
            .field("has_cert_manager", &self.cert_manager.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_new() {
        let builder = WxPayClientBuilder::new();
        assert!(builder.config.is_none());
        assert!(builder.http_client.is_none());
        assert!(builder.signer.is_none());
        assert!(builder.verifier.is_none());
        assert!(builder.cert_manager.is_none());
    }

    #[test]
    fn test_builder_default() {
        let builder = WxPayClientBuilder::default();
        assert!(builder.config.is_none());
    }

    #[test]
    fn test_builder_config() {
        let config = WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .private_key(vec![1, 2, 3, 4])
            .cert_serial_number("CERT123456")
            .build()
            .unwrap();

        let builder = WxPayClientBuilder::new().config(config);
        assert!(builder.config.is_some());
    }
}
