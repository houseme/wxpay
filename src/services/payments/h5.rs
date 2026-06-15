//! H5 支付服务模块
//!
//! 提供微信支付 H5 支付功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::services::payments::jsapi::{Amount, JsapiRequest};

/// H5 支付请求
#[derive(Debug, Clone, Serialize)]
pub struct H5Request {
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

    /// 场景信息
    pub scene_info: Option<SceneInfo>,
}

/// 场景信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SceneInfo {
    /// 用户终端 IP
    pub payer_client_ip: Option<String>,

    /// 商户端设备号
    pub device_id: Option<String>,

    /// H5 场景信息
    pub h5_info: Option<H5Info>,
}

/// H5 场景信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H5Info {
    /// 场景类型
    pub r#type: String,
}

/// H5 支付响应
#[derive(Debug, Clone, Deserialize)]
pub struct H5Response {
    /// 支付跳转链接
    pub h5_url: String,
}

/// H5 支付服务
///
/// 提供微信支付 H5 支付的创建、查询等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::services::H5Service;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = H5Service::new(config, http_client, signer);
///
/// let request = H5Request {
///     appid: "wx88888888".to_string(),
///     mchid: "1900000109".to_string(),
///     description: "测试商品".to_string(),
///     out_trade_no: "test_trade_no_123".to_string(),
///     amount: Some(Amount {
///         total: 100,
///         currency: Some("CNY".to_string()),
///     }),
///     notify_url: None,
///     scene_info: None,
/// };
///
/// let response = tokio::runtime::Runtime::new()?.block_on(service.create_order(&request))?;
/// # Ok(())
/// # }
/// ```
pub struct H5Service {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl H5Service {
    /// 创建新的 H5 服务
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

    /// 创建 H5 订单
    pub async fn create_order(&self, request: &H5Request) -> WxPayResult<H5Response> {
        let url = format!("{}/v3/pay/transactions/h5", self.config.base_url());

        // 序列化请求体
        let body = serde_json::to_string(request)?;

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("POST\n/v3/pay/transactions/h5\n{}\n{}\n{}\n", timestamp, nonce, body);

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
        let h5_response: H5Response = serde_json::from_str(&response.body)?;

        Ok(h5_response)
    }
}

impl std::fmt::Debug for H5Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H5Service").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h5_request_serialization() {
        let request = H5Request {
            appid: "wx88888888".to_string(),
            mchid: "1900000109".to_string(),
            description: "测试商品".to_string(),
            out_trade_no: "test_trade_no_123".to_string(),
            amount: Some(Amount {
                total: 100,
                currency: Some("CNY".to_string()),
            }),
            notify_url: None,
            scene_info: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wx88888888"));
        assert!(json.contains("1900000109"));
    }

    #[test]
    fn test_h5_response_deserialization() {
        let json = r#"{"h5_url":"https://wx.tenpay.com/cgi-bin/mmpayweb-bin/checkmweb?prepay_id=wx201410272009395522657a690ac89ed300"}"#;
        let response: H5Response = serde_json::from_str(json).unwrap();
        assert!(response.h5_url.starts_with("https://wx.tenpay.com"));
    }
}
