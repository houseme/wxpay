//! 转账服务模块
//!
//! 提供微信支付转账功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;

/// 转账请求
#[derive(Debug, Clone, Serialize)]
pub struct TransferRequest {
    /// 商户号
    pub appid: String,

    /// 商户订单号
    pub out_batch_no: String,

    /// 批次名称
    pub batch_name: String,

    /// 批次备注
    pub batch_remark: String,

    /// 转账明细
    pub transfer_detail_list: Vec<TransferDetail>,

    /// 转账总金额（分）
    pub total_amount: u64,

    /// 转账总笔数
    pub total_num: u64,
}

/// 转账明细
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDetail {
    /// 商户明细 ID
    pub out_detail_no: String,

    /// 转账金额（分）
    pub transfer_amount: u64,

    /// 转账备注
    pub transfer_remark: String,

    /// 用户标识
    pub openid: String,

    /// 用户名
    pub user_name: Option<String>,
}

/// 转账响应
#[derive(Debug, Clone, Deserialize)]
pub struct TransferResponse {
    /// 微信批次单号
    pub batch_id: String,

    /// 商户批次单号
    pub out_batch_no: String,

    /// 批次状态
    pub batch_status: String,
}

/// 转账服务
///
/// 提供微信支付转账的创建、查询等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::services::TransferService;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = TransferService::new(config, http_client, signer);
///
/// let request = TransferRequest {
///     appid: "wx88888888".to_string(),
///     out_batch_no: "batch_001".to_string(),
///     batch_name: "测试转账".to_string(),
///     batch_remark: "测试".to_string(),
///     transfer_detail_list: vec![TransferDetail {
///         out_detail_no: "detail_001".to_string(),
///         transfer_amount: 100,
///         transfer_remark: "转账".to_string(),
///         openid: "test_openid".to_string(),
///         user_name: None,
///     }],
///     total_amount: 100,
///     total_num: 1,
/// };
///
/// let response = tokio::runtime::Runtime::new()?.block_on(service.create_transfer(&request))?;
/// # Ok(())
/// # }
/// ```
pub struct TransferService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl TransferService {
    /// 创建新的转账服务
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

    /// 创建转账
    pub async fn create_transfer(&self, request: &TransferRequest) -> WxPayResult<TransferResponse> {
        let url = format!("{}/v3/transfer/batches", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/transfer/batches\n{}\n{}\n{}\n", timestamp, nonce, body);

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
        let transfer_response: TransferResponse = serde_json::from_str(&response.body)?;

        Ok(transfer_response)
    }

    /// 查询转账批次
    pub async fn query_transfer_batch(&self, batch_id: &str) -> WxPayResult<TransferResponse> {
        let url = format!(
            "{}/v3/transfer/batches/{}",
            self.config.base_url(),
            batch_id
        );

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let path = format!("/v3/transfer/batches/{}", batch_id);
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
        let transfer_response: TransferResponse = serde_json::from_str(&response.body)?;

        Ok(transfer_response)
    }
}

impl std::fmt::Debug for TransferService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_request_serialization() {
        let request = TransferRequest {
            appid: "wx88888888".to_string(),
            out_batch_no: "batch_001".to_string(),
            batch_name: "测试转账".to_string(),
            batch_remark: "测试".to_string(),
            transfer_detail_list: vec![TransferDetail {
                out_detail_no: "detail_001".to_string(),
                transfer_amount: 100,
                transfer_remark: "转账".to_string(),
                openid: "test_openid".to_string(),
                user_name: None,
            }],
            total_amount: 100,
            total_num: 1,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("batch_001"));
        assert!(json.contains("测试转账"));
    }

    #[test]
    fn test_transfer_response_deserialization() {
        let json = r#"{
            "batch_id": "1030000071100999991182020050700019480101",
            "out_batch_no": "batch_001",
            "batch_status": "ACCEPT"
        }"#;
        let response: TransferResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.batch_status, "ACCEPT");
        assert_eq!(response.batch_id, "1030000071100999991182020050700019480101");
    }
}
