//! 客户端构建器模块
//!
//! 提供微信支付客户端的构建器。

use std::sync::Arc;

use super::WxPayClient;
use crate::auth::{Sha256RsaSigner, Sha256RsaVerifier, Signer, Verifier};
use crate::cert::CertManager;
use crate::config::WxPayConfig;
use crate::error::{WxPayError, WxPayResult};
use crate::http::{HttpClient, ReqwestHttpClient};
use crate::services::transport::TransportObserver;

/// 客户端构建器
///
/// 用于构建微信支付客户端。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::{WxPayClient, WxPayConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = WxPayConfig::builder()
///         .app_id("wx88888888")
///         .merchant_id("1900000109")
///         .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
///         .private_key_from_file("path/to/private_key.pem")
///         .cert_serial_number("CERT123456")
///         .build()?;
///
///     let _client = WxPayClient::builder()
///         .config(config)
///         .build()
///         .await?;
///     Ok(())
/// }
/// ```
pub struct WxPayClientBuilder {
    config: Option<WxPayConfig>,
    http_client: Option<Arc<dyn HttpClient>>,
    signer: Option<Arc<dyn Signer>>,
    verifier: Option<Arc<dyn Verifier>>,
    cert_manager: Option<Arc<CertManager>>,
    transport_observer: Option<Arc<dyn TransportObserver>>,
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
            transport_observer: None,
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

    /// 设置传输观测回调（可用于 Prometheus/OpenTelemetry/告警网关）
    pub fn transport_observer(mut self, observer: impl TransportObserver + 'static) -> Self {
        self.transport_observer = Some(Arc::new(observer));
        self
    }

    /// 构建客户端
    pub async fn build(self) -> WxPayResult<WxPayClient> {
        let config = self
            .config
            .ok_or_else(|| WxPayError::missing_config("config"))?;
        let config = Arc::new(config);

        // 创建或使用提供的 HTTP 客户端
        let http_client: Arc<dyn HttpClient> = match self.http_client {
            Some(client) => client,
            None => Arc::new(
                ReqwestHttpClient::builder()
                    .timeout(config.timeout)
                    .max_retries(config.max_retries)
                    .build()?,
            ),
        };

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
        let cert_manager = self
            .cert_manager
            .unwrap_or_else(|| Arc::new(CertManager::new()));

        WxPayClient::new_with_components(
            (*config).clone(),
            http_client,
            signer,
            verifier,
            cert_manager,
            self.transport_observer,
        )
        .await
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
            .field("has_transport_observer", &self.transport_observer.is_some())
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
