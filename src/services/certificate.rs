//! 证书服务模块
//!
//! 提供微信支付证书管理功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::auth::Signer;
use crate::config::WxPayConfig;

/// 证书信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// 证书序列号
    pub serial_no: String,

    /// 证书有效期开始时间
    pub effective_time: String,

    /// 证书有效期结束时间
    pub expire_time: String,
}

/// 证书服务
///
/// 提供微信支付证书的查询、下载等功能。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::services::CertificateService;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let service = CertificateService::new(config, http_client, signer);
///
/// let certificates = tokio::runtime::Runtime::new()?.block_on(service.get_certificates())?;
/// # Ok(())
/// # }
/// ```
pub struct CertificateService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,
}

impl CertificateService {
    /// 创建新的证书服务
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

    /// 获取证书列表
    pub async fn get_certificates(&self) -> WxPayResult<Vec<CertificateInfo>> {
        let url = format!("{}/v3/certificates", self.config.base_url());

        // 构建签名消息
        let timestamp = crate::utils::timestamp::get_timestamp();
        let nonce = crate::utils::nonce::generate_nonce();
        let message = format!("GET\n/v3/certificates\n{}\n{}\n\n", timestamp, nonce);

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
        let certificates: Vec<CertificateInfo> = serde_json::from_str(&response.body)?;

        Ok(certificates)
    }
}

impl std::fmt::Debug for CertificateService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateService").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_info_serialization() {
        let cert_info = CertificateInfo {
            serial_no: "CERT123456".to_string(),
            effective_time: "2024-01-01T00:00:00+08:00".to_string(),
            expire_time: "2025-01-01T00:00:00+08:00".to_string(),
        };

        let json = serde_json::to_string(&cert_info).unwrap();
        assert!(json.contains("CERT123456"));
        assert!(json.contains("2024-01-01T00:00:00+08:00"));
    }

    #[test]
    fn test_certificate_info_deserialization() {
        let json = r#"{
            "serial_no": "CERT123456",
            "effective_time": "2024-01-01T00:00:00+08:00",
            "expire_time": "2025-01-01T00:00:00+08:00"
        }"#;
        let cert_info: CertificateInfo = serde_json::from_str(json).unwrap();
        assert_eq!(cert_info.serial_no, "CERT123456");
    }
}
