//! 客户端模块
//!
//! 提供微信支付客户端的统一入口。

pub mod builder;

pub use builder::WxPayClientBuilder;

use std::sync::Arc;

use crate::config::WxPayConfig;
use crate::error::{WxPayError, WxPayResult};
use crate::auth::{Signer, Verifier, Sha256RsaSigner, Sha256RsaVerifier, Credentials};
use crate::cert::CertManager;
use crate::http::{HttpClient, ReqwestHttpClient};
use crate::services::payments::{JsapiService, NativeService, H5Service, AppService};
use crate::services::refund::RefundService;
use crate::services::transfer::TransferService;
use crate::services::profit_sharing::ProfitSharingService;
use crate::services::certificate::CertificateService;
use crate::notify::NotifyHandler;

/// 微信支付客户端
///
/// 这是 SDK 的主入口，提供了访问所有微信支付 API 的方法。
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
///         .private_key_from_file("path/to/private_key.pem")?
///         .cert_serial_number("CERT123456")
///         .build()?;
///
///     let client = WxPayClient::new(config).await?;
///
///     // 使用 JSAPI 服务
///     let jsapi = client.jsapi();
///
///     Ok(())
/// }
/// ```
pub struct WxPayClient {
    /// 配置信息
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 凭证管理器
    credentials: Arc<Credentials>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 验签器
    verifier: Arc<dyn Verifier>,

    /// 证书管理器
    cert_manager: Arc<CertManager>,

    /// 服务注册表
    services: ServiceRegistry,
}

/// 服务注册表
struct ServiceRegistry {
    jsapi: Arc<JsapiService>,
    native: Arc<NativeService>,
    h5: Arc<H5Service>,
    app: Arc<AppService>,
    refund: Arc<RefundService>,
    transfer: Arc<TransferService>,
    profitsharing: Arc<ProfitSharingService>,
    certificates: Arc<CertificateService>,
}

impl WxPayClient {
    /// 创建新的微信支付客户端
    ///
    /// # 参数
    ///
    /// * `config` - 配置信息
    ///
    /// # 返回
    ///
    /// 返回客户端实例
    pub async fn new(config: WxPayConfig) -> WxPayResult<Self> {
        let config = Arc::new(config);

        // 创建 HTTP 客户端
        let http_client: Arc<dyn HttpClient> = Arc::new(
            ReqwestHttpClient::builder()
                .timeout(config.timeout)
                .build()?,
        );

        // 创建凭证管理器
        let credentials = Arc::new(Credentials::from_config(&config));

        // 创建签名器
        let signer: Arc<dyn Signer> = Arc::new(Sha256RsaSigner::new(
            &config.merchant_id,
            &config.private_key,
            &config.cert_serial_number,
        )?);

        // 创建验签器
        let verifier: Arc<dyn Verifier> = Arc::new(Sha256RsaVerifier::new(
            config.platform_certificates.clone(),
        )?);

        // 创建证书管理器
        let cert_manager = Arc::new(CertManager::new());

        // 创建服务
        let services = ServiceRegistry {
            jsapi: Arc::new(JsapiService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            native: Arc::new(NativeService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            h5: Arc::new(H5Service::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            app: Arc::new(AppService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            refund: Arc::new(RefundService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            transfer: Arc::new(TransferService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            profitsharing: Arc::new(ProfitSharingService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
            certificates: Arc::new(CertificateService::new(
                config.clone(),
                http_client.clone(),
                signer.clone(),
            )),
        };

        Ok(Self {
            config,
            http_client,
            credentials,
            signer,
            verifier,
            cert_manager,
            services,
        })
    }

    /// 创建客户端构建器
    pub fn builder() -> WxPayClientBuilder {
        WxPayClientBuilder::new()
    }

    /// 获取配置信息
    pub fn config(&self) -> &WxPayConfig {
        &self.config
    }

    /// 获取凭证管理器
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// 获取签名器
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    /// 获取验签器
    pub fn verifier(&self) -> &dyn Verifier {
        self.verifier.as_ref()
    }

    /// 获取证书管理器
    pub fn cert_manager(&self) -> &CertManager {
        &self.cert_manager
    }

    /// 获取 JSAPI 服务
    pub fn jsapi(&self) -> &JsapiService {
        &self.services.jsapi
    }

    /// 获取 Native 服务
    pub fn native(&self) -> &NativeService {
        &self.services.native
    }

    /// 获取 H5 服务
    pub fn h5(&self) -> &H5Service {
        &self.services.h5
    }

    /// 获取 APP 服务
    pub fn app(&self) -> &AppService {
        &self.services.app
    }

    /// 获取退款服务
    pub fn refund(&self) -> &RefundService {
        &self.services.refund
    }

    /// 获取转账服务
    pub fn transfer(&self) -> &TransferService {
        &self.services.transfer
    }

    /// 获取分账服务
    pub fn profit_sharing(&self) -> &ProfitSharingService {
        &self.services.profitsharing
    }

    /// 获取证书服务
    pub fn certificates(&self) -> &CertificateService {
        &self.services.certificates
    }

    /// 创建通知处理器
    pub fn notify_handler(&self) -> WxPayResult<NotifyHandler> {
        let config = crate::config::NotifyConfig::builder()
            .api_v3_key(&self.config.api_v3_key)
            .cert_serial_number(&self.config.cert_serial_number)
            .platform_certificate(
                self.config
                    .platform_certificates
                    .first()
                    .cloned()
                    .unwrap_or_default(),
            )
            .build()?;

        NotifyHandler::new(config, self.verifier.clone())
    }
}

impl std::fmt::Debug for WxPayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WxPayClient")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> WxPayConfig {
        WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .private_key(vec![1, 2, 3, 4])
            .cert_serial_number("CERT123456")
            .build()
            .unwrap()
    }

    #[test]
    fn test_config() {
        let config = create_test_config();
        assert_eq!(config.app_id, "wx88888888");
        assert_eq!(config.merchant_id, "1900000109");
    }
}
