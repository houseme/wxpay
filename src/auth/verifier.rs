//! 验签器模块
//!
//! 提供响应签名验证功能。

use async_trait::async_trait;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{RsaPublicKey, Pkcs1v15Sign};
use sha2::{Sha256, Digest};
use x509_cert::Certificate;
use base64::Engine;

use crate::error::{WxPayError, WxPayResult};

/// 验签器 trait
///
/// 定义了验证响应签名的接口。
#[async_trait]
pub trait Verifier: Send + Sync {
    /// 验证签名
    ///
    /// # 参数
    ///
    /// * `message` - 原始消息
    /// * `signature` - Base64 编码的签名
    ///
    /// # 返回
    ///
    /// 验证成功返回 Ok(true)，失败返回错误
    async fn verify(&self, message: &str, signature: &str) -> WxPayResult<bool>;

    /// 验证签名（使用指定证书序列号）
    ///
    /// # 参数
    ///
    /// * `message` - 原始消息
    /// * `signature` - Base64 编码的签名
    /// * `serial_number` - 证书序列号
    ///
    /// # 返回
    ///
    /// 验证成功返回 Ok(true)，失败返回错误
    async fn verify_with_serial(
        &self,
        message: &str,
        signature: &str,
        serial_number: &str,
    ) -> WxPayResult<bool>;
}

/// SHA256-RSA 验签器
///
/// 使用 SHA256WithRSA 算法验证响应签名。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::auth::Sha256RsaVerifier;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cert_pem = std::fs::read_to_string("path/to/platform_cert.pem")?;
/// let verifier = Sha256RsaVerifier::new(vec![cert_pem.as_bytes().to_vec()])?;
///
/// let result = tokio::runtime::Runtime::new()?.block_on(
///     verifier.verify("test message", "dGVzdF9zaWduYXR1cmU=")
/// )?;
/// # Ok(())
/// # }
/// ```
pub struct Sha256RsaVerifier {
    /// 证书列表（序列号 -> 公钥）
    certificates: Vec<(String, RsaPublicKey)>,
}

impl Sha256RsaVerifier {
    /// 创建新的 SHA256-RSA 验签器
    ///
    /// # 参数
    ///
    /// * `certificates` - 证书列表（PEM 格式）
    ///
    /// # 返回
    ///
    /// 返回验签器实例
    pub fn new(certificates: Vec<Vec<u8>>) -> WxPayResult<Self> {
        let mut parsed_certs = Vec::new();

        for cert_der in certificates {
            let cert = Self::parse_certificate(&cert_der)?;
            let serial_number = Self::extract_serial_number(&cert)?;
            let public_key = Self::extract_public_key(&cert)?;
            parsed_certs.push((serial_number, public_key));
        }

        Ok(Self {
            certificates: parsed_certs,
        })
    }

    /// 解析证书
    fn parse_certificate(der: &[u8]) -> WxPayResult<Certificate> {
        use der::Decode;
        Certificate::from_der(der).map_err(|e| {
            WxPayError::CertificateParseError(format!("证书解析失败：{}", e))
        })
    }

    /// 提取证书序列号
    fn extract_serial_number(cert: &Certificate) -> WxPayResult<String> {
        // 使用证书的序列号
        let serial = &cert.tbs_certificate.serial_number;
        let bytes = serial.as_bytes();
        Ok(hex::encode(bytes))
    }

    /// 提取公钥
    fn extract_public_key(cert: &Certificate) -> WxPayResult<RsaPublicKey> {
        // 从证书中提取公钥
        use spki::OwnedToRef;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let spki_ref = spki.to_ref();
        let public_key = RsaPublicKey::try_from(spki_ref).map_err(|e| {
            WxPayError::CertificateParseError(format!("提取公钥失败：{}", e))
        })?;
        Ok(public_key)
    }

    /// 构建验签消息
    ///
    /// 微信支付 API v3 验签格式：
    /// TIMESTAMP\nNONCE_STR\nBODY\n
    pub fn build_verify_message(timestamp: i64, nonce: &str, body: &str) -> String {
        format!("{}\n{}\n{}\n", timestamp, nonce, body)
    }

    /// 使用公钥验证签名
    fn verify_signature(
        public_key: &RsaPublicKey,
        message: &str,
        signature: &str,
    ) -> WxPayResult<bool> {
        // 计算 SHA256 哈希
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        // Base64 解码签名
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|e| WxPayError::InvalidSignatureFormat(format!("Base64 解码失败：{}", e)))?;

        // 验证签名
        match public_key.verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &hash,
            &signature_bytes,
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[async_trait]
impl Verifier for Sha256RsaVerifier {
    async fn verify(&self, message: &str, signature: &str) -> WxPayResult<bool> {
        // 使用第一个证书验证
        let (_, public_key) = self.certificates.first().ok_or_else(|| {
            WxPayError::CertificateVerificationError("没有可用的证书".to_string())
        })?;

        Self::verify_signature(public_key, message, signature)
    }

    async fn verify_with_serial(
        &self,
        message: &str,
        signature: &str,
        serial_number: &str,
    ) -> WxPayResult<bool> {
        // 查找匹配的证书
        let (_, public_key) = self
            .certificates
            .iter()
            .find(|(serial, _)| serial == serial_number)
            .ok_or_else(|| {
                WxPayError::CertificateNotFound(serial_number.to_string())
            })?;

        Self::verify_signature(public_key, message, signature)
    }
}

impl std::fmt::Debug for Sha256RsaVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256RsaVerifier")
            .field("certificates_count", &self.certificates.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_verify_message() {
        let message = Sha256RsaVerifier::build_verify_message(
            1609459200,
            "test_nonce",
            r#"{"code":"SUCCESS"}"#,
        );

        assert!(message.starts_with("1609459200\n"));
        assert!(message.contains("test_nonce"));
        assert!(message.ends_with("\n"));
    }
}
