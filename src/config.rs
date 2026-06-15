//! 微信支付配置模块
//!
//! 定义了微信支付 SDK 的配置结构体和构建器。

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{WxPayError, WxPayResult};

/// 微信支付 API 环境
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// 正式环境
    Production,
    /// 沙箱环境
    Sandbox,
}

impl Environment {
    /// 获取 API 基础 URL
    pub fn base_url(&self) -> &str {
        match self {
            Self::Production => "https://api.mch.weixin.qq.com",
            Self::Sandbox => "https://api.mch.weixin.qq.com",
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self::Production
    }
}

/// 微信支付配置
#[derive(Debug, Clone)]
pub struct WxPayConfig {
    /// 应用 ID
    pub app_id: String,

    /// 商户号
    pub merchant_id: String,

    /// API v3 密钥
    pub api_v3_key: String,

    /// 商户私钥（PEM 格式）
    pub private_key: Vec<u8>,

    /// 商户证书序列号
    pub cert_serial_number: String,

    /// 环境
    pub environment: Environment,

    /// 微信支付平台证书（可选，用于验签）
    pub platform_certificates: Vec<Vec<u8>>,

    /// HTTP 超时时间（秒）
    pub timeout: u64,

    /// 最大重试次数
    pub max_retries: u32,
}

/// 微信支付配置构建器
#[derive(Debug, Clone)]
pub struct WxPayConfigBuilder {
    app_id: Option<String>,
    merchant_id: Option<String>,
    api_v3_key: Option<String>,
    private_key: Option<Vec<u8>>,
    private_key_path: Option<PathBuf>,
    cert_serial_number: Option<String>,
    environment: Environment,
    platform_certificates: Vec<Vec<u8>>,
    timeout: u64,
    max_retries: u32,
}

impl WxPayConfigBuilder {
    /// 创建新的配置构建器
    pub fn new() -> Self {
        Self {
            app_id: None,
            merchant_id: None,
            api_v3_key: None,
            private_key: None,
            private_key_path: None,
            cert_serial_number: None,
            environment: Environment::default(),
            platform_certificates: Vec::new(),
            timeout: 30,
            max_retries: 3,
        }
    }

    /// 设置应用 ID
    pub fn app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = Some(app_id.into());
        self
    }

    /// 设置商户号
    pub fn merchant_id(mut self, merchant_id: impl Into<String>) -> Self {
        self.merchant_id = Some(merchant_id.into());
        self
    }

    /// 设置 API v3 密钥
    pub fn api_v3_key(mut self, api_v3_key: impl Into<String>) -> Self {
        self.api_v3_key = Some(api_v3_key.into());
        self
    }

    /// 设置商户私钥（PEM 格式字节）
    pub fn private_key(mut self, private_key: Vec<u8>) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// 从文件加载商户私钥
    pub fn private_key_from_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.private_key_path = Some(path.into());
        self
    }

    /// 设置商户证书序列号
    pub fn cert_serial_number(mut self, cert_serial_number: impl Into<String>) -> Self {
        self.cert_serial_number = Some(cert_serial_number.into());
        self
    }

    /// 设置环境
    pub fn environment(mut self, environment: Environment) -> Self {
        self.environment = environment;
        self
    }

    /// 添加微信支付平台证书
    pub fn platform_certificate(mut self, certificate: Vec<u8>) -> Self {
        self.platform_certificates.push(certificate);
        self
    }

    /// 设置 HTTP 超时时间（秒）
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置最大重试次数
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// 构建配置
    pub fn build(self) -> WxPayResult<WxPayConfig> {
        let app_id = self
            .app_id
            .ok_or_else(|| WxPayError::missing_config("app_id"))?;

        let merchant_id = self
            .merchant_id
            .ok_or_else(|| WxPayError::missing_config("merchant_id"))?;

        let api_v3_key = self
            .api_v3_key
            .ok_or_else(|| WxPayError::missing_config("api_v3_key"))?;

        // 验证 API v3 密钥长度
        if api_v3_key.len() != 32 {
            return Err(WxPayError::invalid_parameter(
                "api_v3_key 必须是 32 个字符",
            ));
        }

        let private_key = match (self.private_key, self.private_key_path) {
            (Some(key), _) => key,
            (None, Some(path)) => std::fs::read(&path).map_err(|e| {
                WxPayError::config(format!("读取私钥文件失败：{}", e))
            })?,
            (None, None) => return Err(WxPayError::missing_config("private_key")),
        };

        let cert_serial_number = self
            .cert_serial_number
            .ok_or_else(|| WxPayError::missing_config("cert_serial_number"))?;

        Ok(WxPayConfig {
            app_id,
            merchant_id,
            api_v3_key,
            private_key,
            cert_serial_number,
            environment: self.environment,
            platform_certificates: self.platform_certificates,
            timeout: self.timeout,
            max_retries: self.max_retries,
        })
    }
}

impl Default for WxPayConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WxPayConfig {
    /// 创建配置构建器
    pub fn builder() -> WxPayConfigBuilder {
        WxPayConfigBuilder::new()
    }

    /// 获取 API 基础 URL
    pub fn base_url(&self) -> &str {
        self.environment.base_url()
    }

    /// 获取商户私钥（PEM 格式）
    pub fn private_key_pem(&self) -> &[u8] {
        &self.private_key
    }
}

/// 微信支付通知配置
#[derive(Debug, Clone)]
pub struct NotifyConfig {
    /// API v3 密钥（用于解密通知数据）
    pub api_v3_key: String,

    /// 平台证书序列号
    pub cert_serial_number: String,

    /// 平台证书（用于验证通知签名）
    pub platform_certificate: Vec<u8>,
}

/// 微信支付通知配置构建器
#[derive(Debug, Clone)]
pub struct NotifyConfigBuilder {
    api_v3_key: Option<String>,
    cert_serial_number: Option<String>,
    platform_certificate: Option<Vec<u8>>,
}

impl NotifyConfigBuilder {
    /// 创建新的通知配置构建器
    pub fn new() -> Self {
        Self {
            api_v3_key: None,
            cert_serial_number: None,
            platform_certificate: None,
        }
    }

    /// 设置 API v3 密钥
    pub fn api_v3_key(mut self, api_v3_key: impl Into<String>) -> Self {
        self.api_v3_key = Some(api_v3_key.into());
        self
    }

    /// 设置平台证书序列号
    pub fn cert_serial_number(mut self, cert_serial_number: impl Into<String>) -> Self {
        self.cert_serial_number = Some(cert_serial_number.into());
        self
    }

    /// 设置平台证书
    pub fn platform_certificate(mut self, certificate: Vec<u8>) -> Self {
        self.platform_certificate = Some(certificate);
        self
    }

    /// 构建通知配置
    pub fn build(self) -> WxPayResult<NotifyConfig> {
        let api_v3_key = self
            .api_v3_key
            .ok_or_else(|| WxPayError::missing_config("api_v3_key"))?;

        let cert_serial_number = self
            .cert_serial_number
            .ok_or_else(|| WxPayError::missing_config("cert_serial_number"))?;

        let platform_certificate = self
            .platform_certificate
            .ok_or_else(|| WxPayError::missing_config("platform_certificate"))?;

        Ok(NotifyConfig {
            api_v3_key,
            cert_serial_number,
            platform_certificate,
        })
    }
}

impl Default for NotifyConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NotifyConfig {
    /// 创建通知配置构建器
    pub fn builder() -> NotifyConfigBuilder {
        NotifyConfigBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_success() {
        let config = WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456") // 32 chars
            .private_key(vec![1, 2, 3, 4])
            .cert_serial_number("CERT123456")
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.app_id, "wx88888888");
        assert_eq!(config.merchant_id, "1900000109");
        assert_eq!(config.timeout, 30);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_config_builder_missing_app_id() {
        let result = WxPayConfig::builder()
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .private_key(vec![1, 2, 3, 4])
            .cert_serial_number("CERT123456")
            .build();

        assert!(result.is_err());
        match result.unwrap_err() {
            WxPayError::MissingConfig { field } => assert_eq!(field, "app_id"),
            _ => panic!("Expected MissingConfig error"),
        }
    }

    #[test]
    fn test_config_builder_invalid_api_v3_key() {
        let result = WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("short_key") // Too short
            .private_key(vec![1, 2, 3, 4])
            .cert_serial_number("CERT123456")
            .build();

        assert!(result.is_err());
        match result.unwrap_err() {
            WxPayError::InvalidParameter(_) => {}
            _ => panic!("Expected InvalidParameter error"),
        }
    }

    #[test]
    fn test_environment_base_url() {
        assert_eq!(
            Environment::Production.base_url(),
            "https://api.mch.weixin.qq.com"
        );
        assert_eq!(
            Environment::Sandbox.base_url(),
            "https://api.mch.weixin.qq.com"
        );
    }

    #[test]
    fn test_notify_config_builder() {
        let config = NotifyConfig::builder()
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .cert_serial_number("CERT123456")
            .platform_certificate(vec![1, 2, 3, 4])
            .build();

        assert!(config.is_ok());
    }
}
