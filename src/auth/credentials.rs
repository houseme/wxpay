//! 凭证管理模块
//!
//! 提供微信支付凭证的管理功能。

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::WxPayConfig;

/// 微信支付凭证
///
/// 封装了商户号、应用 ID 等凭证信息。
#[derive(Debug, Clone)]
pub struct Credentials {
    /// 应用 ID
    app_id: String,

    /// 商户号
    merchant_id: String,

    /// API v3 密钥
    api_v3_key: String,

    /// 证书序列号
    cert_serial_number: String,
}

impl Credentials {
    /// 从配置创建凭证
    pub fn from_config(config: &WxPayConfig) -> Self {
        Self {
            app_id: config.app_id.clone(),
            merchant_id: config.merchant_id.clone(),
            api_v3_key: config.api_v3_key.clone(),
            cert_serial_number: config.cert_serial_number.clone(),
        }
    }

    /// 获取应用 ID
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// 获取商户号
    pub fn merchant_id(&self) -> &str {
        &self.merchant_id
    }

    /// 获取 API v3 密钥
    pub fn api_v3_key(&self) -> &str {
        &self.api_v3_key
    }

    /// 获取证书序列号
    pub fn cert_serial_number(&self) -> &str {
        &self.cert_serial_number
    }
}

/// 凭证提供者
///
/// 提供动态获取凭证的能力，支持凭证刷新。
#[derive(Debug)]
pub struct CredentialProvider {
    /// 凭证
    credentials: Arc<RwLock<Credentials>>,
}

impl CredentialProvider {
    /// 创建新的凭证提供者
    pub fn new(config: &WxPayConfig) -> Self {
        let credentials = Credentials::from_config(config);
        Self {
            credentials: Arc::new(RwLock::new(credentials)),
        }
    }

    /// 获取凭证
    pub async fn get_credentials(&self) -> Credentials {
        self.credentials.read().await.clone()
    }

    /// 更新凭证
    pub async fn update_credentials(&self, credentials: Credentials) {
        let mut current = self.credentials.write().await;
        *current = credentials;
    }
}

impl Clone for CredentialProvider {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> WxPayConfig {
        WxPayConfig::builder()
            .app_id("wx88888888")
            .merchant_id("1900000109")
            .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
            .private_key(vec![1, 2, 3, 4])
            .cert_serial_number("CERT123456")
            .build()
            .unwrap()
    }

    #[test]
    fn test_credentials_from_config() {
        let config = create_test_config();
        let credentials = Credentials::from_config(&config);

        assert_eq!(credentials.app_id(), "wx88888888");
        assert_eq!(credentials.merchant_id(), "1900000109");
        assert_eq!(credentials.api_v3_key(), "abcdefghijklmnopqrstuvwxyz123456");
        assert_eq!(credentials.cert_serial_number(), "CERT123456");
    }

    #[tokio::test]
    async fn test_credential_provider() {
        let config = create_test_config();
        let provider = CredentialProvider::new(&config);

        let credentials = provider.get_credentials().await;
        assert_eq!(credentials.app_id(), "wx88888888");
    }

    #[tokio::test]
    async fn test_credential_provider_update() {
        let config = create_test_config();
        let provider = CredentialProvider::new(&config);

        let new_credentials = Credentials {
            app_id: "wx99999999".to_string(),
            merchant_id: "1900000209".to_string(),
            api_v3_key: "abcdefghijklmnopqrstuvwxyz123456".to_string(),
            cert_serial_number: "CERT999999".to_string(),
        };

        provider.update_credentials(new_credentials).await;

        let credentials = provider.get_credentials().await;
        assert_eq!(credentials.app_id(), "wx99999999");
        assert_eq!(credentials.merchant_id(), "1900000209");
    }
}
