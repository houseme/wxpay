//! 证书服务模块
//!
//! 提供微信支付证书管理功能。

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{WxPayError, WxPayResult};
use crate::http::{HttpClient, HttpMethod};
use crate::auth::Signer;
use crate::config::WxPayConfig;
use crate::services::transport::{ServiceTransport, TransportObserver};

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
/// use std::sync::Arc;
///
/// use wxpay_rs::{
///     auth::{Signer, Sha256RsaSigner},
///     config::WxPayConfig,
///     http::ReqwestHttpClient,
///     services::CertificateService,
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
///
///     let service = CertificateService::new(Arc::new(config), http_client, signer);
///     let certificates = service.get_certificates().await?;
///     let _ = certificates;
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub struct CertificateService {
    /// 配置
    config: Arc<WxPayConfig>,

    /// HTTP 客户端
    http_client: Arc<dyn HttpClient>,

    /// 签名器
    signer: Arc<dyn Signer>,

    /// 统一请求执行器
    transport: ServiceTransport,
}

impl CertificateService {
    /// 创建新的证书服务
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

    /// 获取证书列表
    pub async fn get_certificates(&self) -> WxPayResult<Vec<CertificateInfo>> {
        let response_json: Value = self
            .transport
            .request(HttpMethod::Get, "/v3/certificates", None, "certificate.get_certificates")
            .await?;

        let certificate_items = response_json
            .get("data")
            .and_then(|v| v.as_array())
            .or_else(|| response_json.as_array())
            .ok_or_else(|| {
                WxPayError::CertificateParseError("证书接口响应缺少 data 字段".to_string())
            })?;

        let mut certificates = Vec::with_capacity(certificate_items.len());

        for item in certificate_items {
            let info: CertificateInfo = serde_json::from_value(item.clone())
                .map_err(|e| WxPayError::CertificateParseError(format!("证书信息解析失败：{}", e)))?;
            certificates.push(info);
        }

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
