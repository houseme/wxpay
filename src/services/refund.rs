//! 退款服务模块
//!
//! 提供微信支付退款功能。

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::error::WxPayResult;
use crate::http::{HttpClient, HttpMethod};
use crate::services::transport::{ServiceTransport, TransportObserver};

/// 退款请求
#[derive(Debug, Clone, Serialize)]
pub struct RefundRequest {
    /// 微信支付订单号
    pub transaction_id: Option<String>,

    /// 商户订单号
    pub out_trade_no: Option<String>,

    /// 商户退款单号
    pub out_refund_no: String,

    /// 退款原因
    pub reason: Option<String>,

    /// 退款金额
    pub amount: RefundAmount,

    /// 退款结果通知地址
    pub notify_url: Option<String>,
}

/// 退款金额
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundAmount {
    /// 退款金额（分）
    pub refund: u64,

    /// 原订单金额（分）
    pub total: u64,

    /// 退款币种
    pub currency: String,
}

/// 退款响应
#[derive(Debug, Clone, Deserialize)]
pub struct RefundResponse {
    /// 微信退款单号
    pub refund_id: String,

    /// 商户退款单号
    pub out_refund_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户订单号
    pub out_trade_no: String,

    /// 退款状态
    pub status: String,

    /// 退款金额
    pub amount: Option<RefundAmount>,
}

/// 查询退款请求
#[derive(Debug, Clone, Serialize)]
pub struct QueryRefundRequest {
    pub out_refund_no: String,
}

/// 退款服务
///
/// 提供微信支付退款的创建、查询等功能。
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
///     services::RefundService,
/// };
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
///     let service = RefundService::new(Arc::new(config), http_client, signer);
///
///     let request = wxpay_rs::services::refund::RefundRequest {
///         transaction_id: Some("1217752501201407033233368018".to_string()),
///         out_trade_no: None,
///         out_refund_no: "1217752501201407033233368018".to_string(),
///         reason: Some("商品已售完".to_string()),
///         amount: wxpay_rs::services::refund::RefundAmount {
///             refund: 100,
///             total: 100,
///             currency: "CNY".to_string(),
///         },
///         notify_url: None,
///     };
///     let response = service.create_refund(&request).await?;
///     let _ = response;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct RefundService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl RefundService {
    /// 创建新的退款服务
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

    /// 创建退款
    pub async fn create_refund(&self, request: &RefundRequest) -> WxPayResult<RefundResponse> {
        let body = serde_json::to_string(request)?;

        self.transport
            .request(
                HttpMethod::Post,
                "/v3/refund/domestic/refunds",
                Some(&body),
                "refund.create_refund",
            )
            .await
    }

    /// 申请退款（文档风格）
    pub async fn create(&self, request: &RefundRequest) -> WxPayResult<RefundResponse> {
        self.create_refund(request).await
    }

    /// 查询退款
    pub async fn query_refund(&self, out_refund_no: &str) -> WxPayResult<RefundResponse> {
        let path = format!("/v3/refund/domestic/refunds/{}", out_refund_no);
        self.transport
            .request(HttpMethod::Get, &path, None, "refund.query_refund")
            .await
    }

    /// 查询退款（文档风格）
    pub async fn query(&self, request: &QueryRefundRequest) -> WxPayResult<RefundResponse> {
        self.query_refund(&request.out_refund_no).await
    }

    /// 按商户退款单号查询（兼容 `wechatpay-go` 风格）
    pub async fn query_by_out_refund_no(&self, out_refund_no: &str) -> WxPayResult<RefundResponse> {
        self.query_refund(out_refund_no).await
    }
}

impl std::fmt::Debug for RefundService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefundService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refund_request_serialization() {
        let request = RefundRequest {
            transaction_id: Some("1217752501201407033233368018".to_string()),
            out_trade_no: None,
            out_refund_no: "1217752501201407033233368018".to_string(),
            reason: Some("商品已售完".to_string()),
            amount: RefundAmount {
                refund: 100,
                total: 100,
                currency: "CNY".to_string(),
            },
            notify_url: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("1217752501201407033233368018"));
        assert!(json.contains("商品已售完"));
    }

    #[test]
    fn test_refund_response_deserialization() {
        let json = r#"{
            "refund_id": "50000000382019052709732678869",
            "out_refund_no": "1217752501201407033233368018",
            "transaction_id": "1217752501201407033233368018",
            "out_trade_no": "1217752501201407033233368018",
            "status": "SUCCESS"
        }"#;
        let response: RefundResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "SUCCESS");
        assert_eq!(response.refund_id, "50000000382019052709732678869");
    }
}
