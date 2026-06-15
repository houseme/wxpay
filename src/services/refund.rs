//! 退款服务模块
//!
//! 提供微信支付退款功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;

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

/// 退款服务
///
/// 提供微信支付退款的创建、查询等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::services::RefundService;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = RefundService::new(config, http_client, signer);
///
/// let request = RefundRequest {
///     transaction_id: Some("1217752501201407033233368018".to_string()),
///     out_trade_no: None,
///     out_refund_no: "1217752501201407033233368018".to_string(),
///     reason: Some("商品已售完".to_string()),
///     amount: RefundAmount {
///         refund: 100,
///         total: 100,
///         currency: "CNY".to_string(),
///     },
///     notify_url: None,
/// };
///
/// let response = tokio::runtime::Runtime::new()?.block_on(service.create_refund(&request))?;
/// # Ok(())
/// # }
/// ```
pub struct RefundService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl RefundService {
    /// 创建新的退款服务
    pub fn new(
        config: Arc<WxPayConfig>,
        http_client: Arc<dyn HttpClient>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self {
            config,
            http_client,
            signer,
        }
    }

    /// 创建退款
    pub async fn create_refund(&self, request: &RefundRequest) -> WxPayResult<RefundResponse> {
        let url = format!("{}/v3/refund/domestic/refunds", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/refund/domestic/refunds\n{}\n{}\n{}\n", timestamp, nonce, body);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        // 构建请求头
        let authorization = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}"#,
            self.config.merchant_id, nonce, timestamp, self.config.cert_serial_number, signature
        );

        let headers = vec![
            ("Authorization".to_string(), authorization),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "wxpay-rs/0.1.0".to_string()),
        ];

        // 发送请求
        let response = self.http_client.post(&url, headers, &body).await?;

        // 检查响应状态
        if !response.is_success() {
            let error: serde_json::Value = serde_json::from_str(&response.body)?;
            let code = error.get("code").and_then(|c| c.as_str()).unwrap_or("UNKNOWN");
            let message = error.get("message").and_then(|m| m.as_str()).unwrap_or("未知错误");
            return Err(WxPayError::api(code, message));
        }

        // 解析响应
        let refund_response: RefundResponse = serde_json::from_str(&response.body)?;

        Ok(refund_response)
    }

    /// 查询退款
    pub async fn query_refund(&self, out_refund_no: &str) -> WxPayResult<RefundResponse> {
        let url = format!(
            "{}/v3/refund/domestic/refunds/{}",
            self.config.base_url(),
            out_refund_no
        );

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let path = format!("/v3/refund/domestic/refunds/{}", out_refund_no);
        let message = format!("GET\n{}\n{}\n{}\n\n", path, timestamp, nonce);

        // 生成签名
        let signature = self.signer.sign(&message).await?;

        // 构建请求头
        let authorization = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}"#,
            self.config.merchant_id, nonce, timestamp, self.config.cert_serial_number, signature
        );

        let headers = vec![
            ("Authorization".to_string(), authorization),
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "wxpay-rs/0.1.0".to_string()),
        ];

        // 发送请求
        let response = self.http_client.get(&url, headers).await?;

        // 检查响应状态
        if !response.is_success() {
            let error: serde_json::Value = serde_json::from_str(&response.body)?;
            let code = error.get("code").and_then(|c| c.as_str()).unwrap_or("UNKNOWN");
            let message = error.get("message").and_then(|m| m.as_str()).unwrap_or("未知错误");
            return Err(WxPayError::api(code, message));
        }

        // 解析响应
        let refund_response: RefundResponse = serde_json::from_str(&response.body)?;

        Ok(refund_response)
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
