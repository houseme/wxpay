//! 客户端模块
//!
//! 提供微信支付客户端的统一入口。

pub mod builder;

pub use builder::WxPayClientBuilder;

use std::sync::Arc;

use crate::auth::{Credentials, Sha256RsaSigner, Sha256RsaVerifier, Signer, Verifier};
use crate::cert::CertManager;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, ReqwestHttpClient};
use crate::notify::NotifyHandler;
use crate::services::certificate::CertificateService;
use crate::services::payments::{AppService, H5Service, JsapiService, NativeService};
use crate::services::profit_sharing::{
    ProfitSharingFinishRequest, ProfitSharingFinishResponse, ProfitSharingRequest,
    ProfitSharingResponse, ProfitSharingService, QueryProfitSharingRequest,
};
use crate::services::query::{QueryService, Transaction};
use crate::services::refund::{RefundResponse, RefundService};
use crate::services::transfer::{TransferRequest, TransferResponse, TransferService};
use crate::services::transport::TransportObserver;

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
///         .private_key_from_file("path/to/private_key.pem")
///         .cert_serial_number("CERT123456")
///         .build()?;
///
///     let client = WxPayClient::new(config).await?;
///
///     // 使用 JSAPI 服务
///     let jsapi = client.jsapi();
///     let _ = jsapi;
///
///     Ok(())
/// }
/// ```
pub struct WxPayClient {
    /// 配置信息
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    #[allow(dead_code)]
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
    query: Arc<QueryService>,
}

impl WxPayClient {
    fn create_services(
        config: &Arc<WxPayConfig>,
        http_client: &Arc<dyn HttpClient>,
        signer: &Arc<dyn Signer>,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> ServiceRegistry {
        ServiceRegistry {
            jsapi: Arc::new(JsapiService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            native: Arc::new(NativeService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            h5: Arc::new(H5Service::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            app: Arc::new(AppService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            refund: Arc::new(RefundService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            transfer: Arc::new(TransferService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            profitsharing: Arc::new(ProfitSharingService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            certificates: Arc::new(CertificateService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer.clone(),
            )),
            query: Arc::new(QueryService::new_with_observer(
                config.clone(),
                http_client.clone(),
                signer.clone(),
                transport_observer,
            )),
        }
    }

    pub(crate) async fn new_with_components(
        config: WxPayConfig,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        verifier: Arc<dyn Verifier>,
        cert_manager: Arc<CertManager>,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> WxPayResult<Self> {
        let config = Arc::new(config);
        let credentials = Arc::new(Credentials::from_config(&config));
        let services = Self::create_services(&config, &http_client, &signer, transport_observer);

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
        let http_client: Arc<dyn HttpClient> = Arc::new(
            ReqwestHttpClient::builder()
                .timeout(config.timeout)
                .max_retries(config.max_retries)
                .build()?,
        );
        let signer: Arc<dyn Signer> = Arc::new(Sha256RsaSigner::new(
            &config.merchant_id,
            &config.private_key,
            &config.cert_serial_number,
        )?);
        let verifier: Arc<dyn Verifier> = Arc::new(Sha256RsaVerifier::new(
            config.platform_certificates.clone(),
        )?);
        let cert_manager = Arc::new(CertManager::new());

        Self::new_with_components(
            (*config).clone(),
            http_client,
            signer,
            verifier,
            cert_manager,
            None,
        )
        .await
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

    /// 获取退款服务（兼容 `wechatpay-go` 的 `refunddomestic` 命名）
    pub fn refunddomestic(&self) -> &RefundService {
        self.refund()
    }

    /// 获取转账服务
    pub fn transfer(&self) -> &TransferService {
        &self.services.transfer
    }

    /// 获取转账服务（兼容 `wechatpay-go` 的 `transferbatch` 命名）
    pub fn transferbatch(&self) -> &TransferService {
        self.transfer()
    }

    /// 获取分账服务
    pub fn profit_sharing(&self) -> &ProfitSharingService {
        &self.services.profitsharing
    }

    /// 获取分账服务（兼容 `wechatpay-go` 的 `profitsharing` 命名）
    pub fn profitsharing(&self) -> &ProfitSharingService {
        self.profit_sharing()
    }

    /// 获取证书服务
    pub fn certificates(&self) -> &CertificateService {
        &self.services.certificates
    }

    /// 获取查询服务
    pub fn query(&self) -> &QueryService {
        &self.services.query
    }

    /// 通过商户订单号查询订单（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn query_order_by_out_trade_no(
        &self,
        out_trade_no: &str,
    ) -> WxPayResult<Transaction> {
        self.query().query_order_by_out_trade_no(out_trade_no).await
    }

    /// 通过微信支付订单号查询订单（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn query_order_by_id(&self, transaction_id: &str) -> WxPayResult<Transaction> {
        self.query().query_order_by_id(transaction_id).await
    }

    /// 按商户退款单号查询退款（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn query_by_out_refund_no(&self, out_refund_no: &str) -> WxPayResult<RefundResponse> {
        self.refunddomestic()
            .query_by_out_refund_no(out_refund_no)
            .await
    }

    /// 发起批量转账（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn initiate_batch_transfer(
        &self,
        request: &TransferRequest,
    ) -> WxPayResult<TransferResponse> {
        self.transferbatch().initiate_batch_transfer(request).await
    }

    /// 按商户批次单号查询转账批次（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn get_transfer_batch_by_out_batch_no(
        &self,
        out_batch_no: &str,
    ) -> WxPayResult<TransferResponse> {
        self.transferbatch()
            .get_transfer_batch_by_out_batch_no(out_batch_no)
            .await
    }

    /// 创建分账单（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn create_profit_sharing_order(
        &self,
        request: &ProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        self.profitsharing().create_order(request).await
    }

    /// 查询分账单（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn query_profit_sharing_order(
        &self,
        request: &QueryProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        self.profitsharing().query_order(request).await
    }

    /// 完成分账单（兼容 `wechatpay-go` 风格快捷入口）
    pub async fn finish_profit_sharing_order(
        &self,
        request: &ProfitSharingFinishRequest,
    ) -> WxPayResult<ProfitSharingFinishResponse> {
        self.profitsharing().finish_order(request).await
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
