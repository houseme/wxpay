//! 分账服务模块
//!
//! 提供微信支付分账功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;

/// 分账请求
#[derive(Debug, Clone, Serialize)]
pub struct ProfitSharingRequest {
    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 分账接收方列表
    pub receivers: Vec<Receiver>,

    /// 分账说明
    pub description: String,
}

/// 分账接收方
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receiver {
    /// 接收方类型
    #[serde(rename = "type")]
    pub receiver_type: String,

    /// 接收方账号
    pub account: String,

    /// 分账金额（分）
    pub amount: u64,

    /// 分账描述
    pub description: String,

    /// 接收方名称
    pub name: Option<String>,
}

/// 分账响应
#[derive(Debug, Clone, Deserialize)]
pub struct ProfitSharingResponse {
    /// 微信分账单号
    pub order_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 分账单状态
    pub status: String,
}

/// 分账完结请求
#[derive(Debug, Clone, Serialize)]
pub struct ProfitSharingFinishRequest {
    /// 微信支付订单号
    pub transaction_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 分账完结描述
    pub description: String,
}

/// 分账完结响应
#[derive(Debug, Clone, Deserialize)]
pub struct ProfitSharingFinishResponse {
    /// 微信分账单号
    pub order_id: String,

    /// 商户分账单号
    pub out_order_no: String,

    /// 微信支付订单号
    pub transaction_id: String,

    /// 分账单状态
    pub status: String,
}

/// 分账服务
///
/// 提供微信支付分账的创建、查询、完结等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::services::ProfitSharingService;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = ProfitSharingService::new(config, http_client, signer);
///
/// let request = ProfitSharingRequest {
///     transaction_id: "1217752501201407033233368018".to_string(),
///     out_order_no: "P20150806125346".to_string(),
///     receivers: vec![Receiver {
///         receiver_type: "MERCHANT_ID".to_string(),
///         account: "1900000109".to_string(),
///         amount: 100,
///         description: "分账".to_string(),
///         name: None,
///     }],
///     description: "分账".to_string(),
/// };
///
/// let response = tokio::runtime::Runtime::new()?.block_on(service.create_profit_sharing(&request))?;
/// # Ok(())
/// # }
/// ```
pub struct ProfitSharingService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl ProfitSharingService {
    /// 创建新的分账服务
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

    /// 创建分账
    pub async fn create_profit_sharing(
        &self,
        request: &ProfitSharingRequest,
    ) -> WxPayResult<ProfitSharingResponse> {
        let url = format!("{}/v3/profitsharing/orders", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/profitsharing/orders\n{}\n{}\n{}\n", timestamp, nonce, body);

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
        let profit_sharing_response: ProfitSharingResponse = serde_json::from_str(&response.body)?;

        Ok(profit_sharing_response)
    }

    /// 查询分账
    pub async fn query_profit_sharing(
        &self,
        transaction_id: &str,
        out_order_no: &str,
    ) -> WxPayResult<ProfitSharingResponse> {
        let url = format!(
            "{}/v3/profitsharing/orders/{}?transaction_id={}",
            self.config.base_url(),
            out_order_no,
            transaction_id
        );

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let path = format!(
            "/v3/profitsharing/orders/{}?transaction_id={}",
            out_order_no, transaction_id
        );
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
        let profit_sharing_response: ProfitSharingResponse = serde_json::from_str(&response.body)?;

        Ok(profit_sharing_response)
    }

    /// 完成分账
    pub async fn finish_profit_sharing(
        &self,
        request: &ProfitSharingFinishRequest,
    ) -> WxPayResult<ProfitSharingFinishResponse> {
        let url = format!("{}/v3/profitsharing/finish", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/profitsharing/finish\n{}\n{}\n{}\n", timestamp, nonce, body);

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
        let finish_response: ProfitSharingFinishResponse = serde_json::from_str(&response.body)?;

        Ok(finish_response)
    }
}

impl std::fmt::Debug for ProfitSharingService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfitSharingService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profit_sharing_request_serialization() {
        let request = ProfitSharingRequest {
            transaction_id: "1217752501201407033233368018".to_string(),
            out_order_no: "P20150806125346".to_string(),
            receivers: vec![Receiver {
                receiver_type: "MERCHANT_ID".to_string(),
                account: "1900000109".to_string(),
                amount: 100,
                description: "分账".to_string(),
                name: None,
            }],
            description: "分账".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("1217752501201407033233368018"));
        assert!(json.contains("P20150806125346"));
    }

    #[test]
    fn test_profit_sharing_response_deserialization() {
        let json = r#"{
            "order_id": "6110000071100999991182020050700019480101",
            "out_order_no": "P20150806125346",
            "transaction_id": "1217752501201407033233368018",
            "status": "FINISHED"
        }"#;
        let response: ProfitSharingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "FINISHED");
        assert_eq!(response.order_id, "6110000071100999991182020050700019480101");
    }
}
