//! 证书管理器模块
//!
//! 提供微信支付平台证书的管理功能。

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x509_cert::Certificate;

use crate::error::{WxPayError, WxPayResult};

/// 证书条目：解析后的证书与原始 DER 数据合并存储，
/// 单锁读取，避免双锁间的不一致与额外加锁开销。
#[derive(Clone)]
struct CertEntry {
    cert: Certificate,
    der: Vec<u8>,
}

/// 证书管理器
///
/// 管理微信支付平台证书，支持证书的存储、查询和自动刷新。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::cert::CertManager;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let manager = CertManager::new();
///
///     // 添加证书
///     let cert_der = std::fs::read("path/to/platform_cert.der")?;
///     manager.add_certificate("CERT123456".to_string(), cert_der).await?;
///
///     // 查询证书
///     let cert = manager.get_certificate("CERT123456").await;
///     let _ = cert;
///     Ok(())
/// }
/// ```
pub struct CertManager {
    /// 证书存储（序列号 -> 条目）
    certificates: Arc<RwLock<HashMap<String, CertEntry>>>,
}

impl CertManager {
    /// 创建新的证书管理器
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 添加证书
    ///
    /// # 参数
    ///
    /// * `serial_number` - 证书序列号
    /// * `cert_der` - 证书（DER 格式）
    ///
    /// # 返回
    ///
    /// 返回添加结果
    pub async fn add_certificate(
        &self,
        serial_number: String,
        cert_der: Vec<u8>,
    ) -> WxPayResult<()> {
        use der::Decode;

        let cert = Certificate::from_der(&cert_der)
            .map_err(|e| WxPayError::CertificateParseError(format!("证书解析失败：{}", e)))?;

        self.certificates.write().await.insert(
            serial_number,
            CertEntry {
                cert,
                der: cert_der,
            },
        );

        Ok(())
    }

    /// 获取证书
    ///
    /// # 参数
    ///
    /// * `serial_number` - 证书序列号
    ///
    /// # 返回
    ///
    /// 返回证书的克隆
    pub async fn get_certificate(&self, serial_number: &str) -> Option<Certificate> {
        self.certificates
            .read()
            .await
            .get(serial_number)
            .map(|entry| entry.cert.clone())
    }

    /// 获取证书原始数据
    ///
    /// # 参数
    ///
    /// * `serial_number` - 证书序列号
    ///
    /// # 返回
    ///
    /// 返回证书 DER 格式数据的克隆
    pub async fn get_certificate_data(&self, serial_number: &str) -> Option<Vec<u8>> {
        self.certificates
            .read()
            .await
            .get(serial_number)
            .map(|entry| entry.der.clone())
    }

    /// 获取所有证书序列号
    ///
    /// # 返回
    ///
    /// 返回所有证书序列号的列表
    pub async fn get_serial_numbers(&self) -> Vec<String> {
        self.certificates.read().await.keys().cloned().collect()
    }

    /// 移除证书
    ///
    /// # 参数
    ///
    /// * `serial_number` - 证书序列号
    ///
    /// # 返回
    ///
    /// 返回移除结果
    pub async fn remove_certificate(&self, serial_number: &str) -> WxPayResult<()> {
        self.certificates.write().await.remove(serial_number);
        Ok(())
    }

    /// 清空所有证书
    pub async fn clear(&self) {
        self.certificates.write().await.clear();
    }

    /// 获取证书数量
    pub async fn count(&self) -> usize {
        self.certificates.read().await.len()
    }

    /// 检查证书是否存在
    pub async fn has_certificate(&self, serial_number: &str) -> bool {
        self.certificates.read().await.contains_key(serial_number)
    }
}

impl Default for CertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertManager")
            .field("certificates", &"<certificates>")
            .finish()
    }
}

impl Clone for CertManager {
    fn clone(&self) -> Self {
        Self {
            certificates: self.certificates.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cert_manager_new() {
        let manager = CertManager::new();
        assert_eq!(manager.count().await, 0);
    }

    #[tokio::test]
    async fn test_cert_manager_has_certificate() {
        let manager = CertManager::new();
        assert!(!manager.has_certificate("CERT123456").await);
    }

    #[tokio::test]
    async fn test_cert_manager_get_serial_numbers() {
        let manager = CertManager::new();
        let serial_numbers = manager.get_serial_numbers().await;
        assert!(serial_numbers.is_empty());
    }
}
