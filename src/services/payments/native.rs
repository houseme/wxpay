//! Native 支付服务模块
//!
//! 提供微信支付 Native 支付功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::payments::jsapi::Amount;
use crate::services::transport::{ServiceTransport, TransportObserver};

/// Native 支付请求
#[derive(Debug, Clone, Serialize)]
pub struct NativeRequest {
    /// 应用 ID
    pub appid: String,

    /// 商户号
    pub mchid: String,

    /// 商品描述
    pub description: String,

    /// 商户订单号
    pub out_trade_no: String,

    /// 订单金额
    pub amount: Option<Amount>,

    /// 通知地址
    pub notify_url: Option<String>,
}

/// Native 支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct NativeResponse {
    /// 二维码链接
    pub code_url: String,
}

/// Native 支付服务
///
/// 提供微信支付 Native 支付的创建、查询等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use std::sync::Arc;
///
/// use wxpay_rs::{
///     auth::{Signer, Sha256RsaSigner},
///     config::WxPayConfig,
///     http::ReqwestHttpClient,
///     services::NativeService,
/// };
/// use wxpay_rs::services::payments::jsapi::Amount;
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
///     let http_client = Arc::new(ReqwestHttpClient::builder().build()?);
///     let signer: Arc<dyn Signer> = Arc::new(Sha256RsaSigner::new(
///         "1900000109",
///         b"PRIVATE KEY",
///         "CERT123456",
///     )?);
///     let service = NativeService::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::payments::native::NativeRequest {
///         appid: "wx88888888".to_string(),
///         mchid: "1900000109".to_string(),
///         description: "测试商品".to_string(),
///         out_trade_no: "test_trade_no_123".to_string(),
///         amount: Some(Amount {
///             total: 100,
///             currency: Some("CNY".to_string()),
///         }),
///         notify_url: None,
///     };
///     let response = service.create_order(&request).await?;
///     let _ = response;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct NativeService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl NativeService {
    /// 创建新的 Native 服务
    pub fn new(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self::new_with_observer(config.clone(), http_client.clone(), signer.clone(), None)
    }

    pub fn new_with_observer(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        transport_observer: Option<Arc<dyn TransportObserver>>,
    ) -> Self {
        Self {
            config: config.clone(),
            http_client: http_client.clone(),
            signer: signer.clone(),
            transport: ServiceTransport::new_with_observer(
                config,
                http_client,
                signer,
                transport_observer,
            ),
        }
    }

    /// 创建 Native 订单
    pub async fn create_order(&self, request: &NativeRequest) -> WxPayResult<NativeResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/pay/transactions/native",
                Some(&body),
                "payments.native.create_order",
            )
            .await
    }

    /// 预下单（兼容文档风格）
    pub async fn prepay(&self, request: &NativeRequest) -> WxPayResult<NativeResponse> {
        self.create_order(request).await
    }
}

impl std::fmt::Debug for NativeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_request_serialization() {
        let request = NativeRequest {
            appid: "wx88888888".to_string(),
            mchid: "1900000109".to_string(),
            description: "测试商品".to_string(),
            out_trade_no: "test_trade_no_123".to_string(),
            amount: Some(Amount {
                total: 100,
                currency: Some("CNY".to_string()),
            }),
            notify_url: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wx88888888"));
        assert!(json.contains("1900000109"));
    }

    #[test]
    fn test_native_response_deserialization() {
        let json = r#"{"code_url":"weixin://wxpay/bizpayurl?pr=xxxxx"}"#;
        let response: NativeResponse = serde_json::from_str(json).unwrap();
        assert!(response.code_url.starts_with("weixin://wxpay/bizpayurl"));
    }
}
