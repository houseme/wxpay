//! Native 支付服务模块
//!
//! 提供微信支付 Native 支付功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::services::payments::jsapi::{Amount, JsapiRequest};

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
/// use wxpay_rs::services::NativeService;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = NativeService::new(config, http_client, signer);
///
/// let request = NativeRequest {
///     appid: "wx88888888".to_string(),
///     mchid: "1900000109".to_string(),
///     description: "测试商品".to_string(),
///     out_trade_no: "test_trade_no_123".to_string(),
///     amount: Some(Amount {
///         total: 100,
///         currency: Some("CNY".to_string()),
///     }),
///     notify_url: None,
/// };
///
/// let response = tokio::runtime::Runtime::new()?.block_on(service.create_order(&request))?;
/// # Ok(())
/// # }
/// ```
pub struct NativeService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl NativeService {
    /// 创建新的 Native 服务
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

    /// 创建 Native 订单
    pub async fn create_order(&self, request: &NativeRequest) -> WxPayResult<NativeResponse> {
        let url = format!("{}/v3/pay/transactions/native", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/pay/transactions/native\n{}\n{}\n{}\n", timestamp, nonce, body);

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
        let native_response: NativeResponse = serde_json::from_str(&response.body)?;

        Ok(native_response)
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
