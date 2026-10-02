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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,

    /// 商户订单号
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_trade_no: Option<String>,

    /// 商户退款单号
    pub out_refund_no: String,

    /// 退款原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// 退款金额
    pub amount: RefundAmount,

    /// 退款结果通知地址
    #[serde(skip_serializing_if = "Option::is_none")]
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

impl RefundRequest {
    /// Validate required order identity and amount before a network request.
    pub fn validate(&self) -> WxPayResult<()> {
        let (id, field) = match (&self.transaction_id, &self.out_trade_no) {
            (Some(id), None) => (id, "transaction_id"),
            (None, Some(id)) => (id, "out_trade_no"),
            _ => {
                return Err(crate::error::WxPayError::invalid_parameter(
                    "exactly one of transaction_id and out_trade_no is required",
                ));
            }
        };
        super::require_text(id, field)?;
        super::require_identifier(&self.out_refund_no, "out_refund_no")?;
        if self.amount.refund == 0
            || self.amount.refund > self.amount.total
            || self.amount.currency != "CNY"
        {
            return Err(crate::error::WxPayError::invalid_parameter(
                "refund must be positive, not exceed total, and use CNY",
            ));
        }
        if self.out_refund_no.len() > 64 || self.reason.as_ref().is_some_and(|s| s.len() > 80) {
            return Err(crate::error::WxPayError::invalid_parameter(
                "refund identifier or reason exceeds the documented length",
            ));
        }
        if let Some(url) = &self.notify_url {
            super::validate_notify_url(url)?;
        }
        Ok(())
    }
}

/// Optional refund funding and item parameters.
#[derive(Debug, Clone, Default)]
pub struct RefundOptions {
    /// AVAILABLE (legacy settlement) or UNSETTLED (eligible deposits).
    pub funds_account: Option<String>,
    /// Funding accounts; their sum must equal the refund amount.
    pub from: Option<Vec<RefundFunding>>,
    /// Items matching those supplied at payment creation.
    pub goods_detail: Option<Vec<RefundGoodsDetail>>,
}

/// An account contributing funds to a refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundFunding {
    /// AVAILABLE or UNAVAILABLE.
    pub account: String,
    /// Amount in cents.
    pub amount: u64,
}

/// Item information for a targeted goods refund.
#[derive(Debug, Clone, Serialize)]
pub struct RefundGoodsDetail {
    /// Merchant item identifier supplied at payment creation.
    pub merchant_goods_id: String,
    /// Optional WeChat item identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wechatpay_goods_id: Option<String>,
    /// Optional item name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goods_name: Option<String>,
    /// Unit price in cents.
    pub unit_price: u64,
    /// Refund amount for this item in cents.
    pub refund_amount: u64,
    /// Refunded quantity.
    pub refund_quantity: u64,
}

impl RefundOptions {
    fn validate(&self, refund: u64) -> WxPayResult<()> {
        use crate::error::WxPayError;
        if self
            .funds_account
            .as_deref()
            .is_some_and(|v| !matches!(v, "AVAILABLE" | "UNSETTLED"))
        {
            return Err(WxPayError::invalid_parameter("unsupported funds_account"));
        }
        if let Some(from) = &self.from {
            let mut accounts = std::collections::HashSet::new();
            let mut total = 0_u64;
            for item in from {
                if !matches!(item.account.as_str(), "AVAILABLE" | "UNAVAILABLE")
                    || !accounts.insert(&item.account)
                {
                    return Err(WxPayError::invalid_parameter(
                        "invalid or duplicate refund funding account",
                    ));
                }
                total = total.checked_add(item.amount).ok_or_else(|| {
                    WxPayError::invalid_parameter("refund funding total overflow")
                })?;
            }
            if total != refund {
                return Err(WxPayError::invalid_parameter(
                    "funding amounts must sum to refund",
                ));
            }
        }
        if let Some(goods) = &self.goods_detail {
            if goods.is_empty() {
                return Err(WxPayError::invalid_parameter(
                    "goods_detail cannot be empty",
                ));
            }
            for item in goods {
                super::require_text(&item.merchant_goods_id, "merchant_goods_id")?;
                if item.refund_quantity == 0
                    || item.refund_amount == 0
                    || item.refund_amount > refund
                {
                    return Err(WxPayError::invalid_parameter(
                        "invalid goods refund quantity or amount",
                    ));
                }
            }
        }
        Ok(())
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub(crate) fn from_transport(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
        transport: ServiceTransport,
    ) -> Self {
        Self {
            config,
            http_client,
            signer,
            transport,
        }
    }

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
        self.create_refund_with_options(request, &RefundOptions::default())
            .await
    }

    /// Create a refund with optional funding and item details.
    pub async fn create_refund_with_options(
        &self,
        request: &RefundRequest,
        options: &RefundOptions,
    ) -> WxPayResult<RefundResponse> {
        request.validate()?;
        options.validate(request.amount.refund)?;
        let mut body = serde_json::to_value(request)?;
        if let Some(account) = &options.funds_account {
            body["funds_account"] = account.clone().into();
        }
        if let Some(from) = &options.from {
            body["amount"]["from"] = serde_json::to_value(from)?;
        }
        if let Some(goods) = &options.goods_detail {
            body["goods_detail"] = serde_json::to_value(goods)?;
        }
        let body = serde_json::to_string(&body)?;

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
        super::require_identifier(out_refund_no, "out_refund_no")?;
        let path = format!(
            "/v3/refund/domestic/refunds/{}",
            super::encode_component(out_refund_no)
        );
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

    #[test]
    fn test_go_style_refund_alias_signature_exists() {
        let _ = RefundService::query_by_out_refund_no;
    }
}
