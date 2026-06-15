//! APP 支付服务模块
//!
//! 提供微信支付 APP 支付功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::payments::jsapi::Amount;
use crate::services::transport::{ServiceTransport, TransportObserver};

/// APP 支付请求
#[derive(Debug, Clone, Serialize)]
pub struct AppRequest {
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

/// APP 支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct AppResponse {
    /// 预支付交易会话标识
    pub prepay_id: String,
}

/// APP 支付参数
///
/// 用于客户端调用微信支付 SDK 时的参数。
#[derive(Debug, Clone, Serialize)]
pub struct AppPayParams {
    /// 应用 ID
    pub appid: String,

    /// 商户号
    pub partnerid: String,

    /// 预支付交易会话标识
    pub prepayid: String,

    /// 扩展字段
    pub package: String,

    /// 随机字符串
    pub noncestr: String,

    /// 时间戳
    pub timestamp: String,

    /// 签名
    pub sign: String,
}

/// APP 支付服务
///
/// 提供微信支付 APP 支付的创建、查询等功能。
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
///     services::AppService,
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
///     let service = AppService::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::payments::app::AppRequest {
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
pub struct AppService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl AppService {
    /// 创建新的 APP 服务
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

    /// 创建 APP 订单
    pub async fn create_order(&self, request: &AppRequest) -> WxPayResult<AppResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/pay/transactions/app",
                Some(&body),
                "payments.app.create_order",
            )
            .await
    }

    /// 预下单（兼容文档风格）
    pub async fn prepay(&self, request: &AppRequest) -> WxPayResult<AppResponse> {
        self.create_order(request).await
    }

    /// 生成 APP 支付参数
    ///
    /// # 参数
    ///
    /// * `prepay_id` - 预支付交易会话标识
    ///
    /// # 返回
    ///
    /// 返回 APP 支付参数
    pub async fn generate_pay_params(&self, prepay_id: &str) -> WxPayResult<AppPayParams> {
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();

        // 构建签名消息
        let message = format!("{}\n{}\nprepay_id={}\n", timestamp, nonce, prepay_id);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        Ok(AppPayParams {
            appid: self.config.app_id.clone(),
            partnerid: self.config.merchant_id.clone(),
            prepayid: prepay_id.to_string(),
            package: "Sign=WXPay".to_string(),
            noncestr: nonce,
            timestamp: timestamp.to_string(),
            sign: signature,
        })
    }
}

impl std::fmt::Debug for AppService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_request_serialization() {
        let request = AppRequest {
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
    fn test_app_response_deserialization() {
        let json = r#"{"prepay_id":"wx201410272009395522657a690ac89ed300"}"#;
        let response: AppResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.prepay_id, "wx201410272009395522657a690ac89ed300");
    }
}
