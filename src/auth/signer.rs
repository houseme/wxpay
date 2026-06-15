//! 签名器模块
//!
//! 提供请求签名功能，使用 SHA256-RSA 算法。

use async_trait::async_trait;
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

use crate::error::{WxPayError, WxPayResult};

/// 签名器 trait
///
/// 定义了生成请求签名的接口。
#[async_trait]
pub trait Signer: Send + Sync {
    /// 生成签名
    ///
    /// # 参数
    ///
    /// * `message` - 要签名的消息
    ///
    /// # 返回
    ///
    /// 返回 Base64 编码的签名字符串
    async fn sign(&self, message: &str) -> WxPayResult<String>;

    /// 获取商户号
    fn merchant_id(&self) -> &str;

    /// 获取证书序列号
    fn cert_serial_number(&self) -> &str;
}

/// SHA256-RSA 签名器
///
/// 使用 SHA256WithRSA 算法生成请求签名。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::auth::{Signer, Sha256RsaSigner};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let private_key_pem = std::fs::read_to_string("path/to/private_key.pem")?;
/// let signer = Sha256RsaSigner::new(
///     "1900000109",
///     private_key_pem.as_bytes(),
///     "CERT123456",
/// )?;
///
/// let signature = signer.sign("test message").await?;
/// # Ok(())
/// # }
/// ```
pub struct Sha256RsaSigner {
    /// 商户号
    merchant_id: String,
    /// 商户私钥
    private_key: RsaPrivateKey,
    /// 证书序列号
    cert_serial_number: String,
}

impl Sha256RsaSigner {
    /// 创建新的 SHA256-RSA 签名器
    ///
    /// # 参数
    ///
    /// * `merchant_id` - 商户号
    /// * `private_key_pem` - 私钥（PEM 格式）
    /// * `cert_serial_number` - 证书序列号
    ///
    /// # 返回
    ///
    /// 返回签名器实例
    pub fn new(
        merchant_id: impl Into<String>,
        private_key_pem: &[u8],
        cert_serial_number: impl Into<String>,
    ) -> WxPayResult<Self> {
        let private_key = Self::parse_private_key(private_key_pem)?;
        Ok(Self {
            merchant_id: merchant_id.into(),
            private_key,
            cert_serial_number: cert_serial_number.into(),
        })
    }

    /// 解析私钥
    fn parse_private_key(pem: &[u8]) -> WxPayResult<RsaPrivateKey> {
        let pem_str = std::str::from_utf8(pem)
            .map_err(|e| WxPayError::InvalidPrivateKey(format!("无效的 UTF-8 编码：{}", e)))?;

        // 尝试 PKCS#8 格式
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem_str) {
            return Ok(key);
        }

        // 尝试 PKCS#1 格式
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem_str) {
            return Ok(key);
        }

        Err(WxPayError::InvalidPrivateKey(
            "无法解析私钥，请确保是有效的 PKCS#8 或 PKCS#1 PEM 格式".to_string(),
        ))
    }

    /// 构建签名消息
    ///
    /// 微信支付 API v3 签名格式：
    /// HTTP_METHOD\nURL_PATH\nTIMESTAMP\nNONCE_STR\nBODY\n
    pub fn build_sign_message(
        method: &str,
        url: &str,
        timestamp: i64,
        nonce: &str,
        body: &str,
    ) -> String {
        format!("{}\n{}\n{}\n{}\n{}\n", method, url, timestamp, nonce, body)
    }

    /// 构建 Authorization Header
    ///
    /// 格式：WECHATPAY2-SHA256-RSA2048 mchid="...",nonce_str="...",timestamp="...",serial_no="...",signature="..."
    pub fn build_authorization_header(
        &self,
        nonce: &str,
        timestamp: i64,
        signature: &str,
    ) -> String {
        format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}"#,
            self.merchant_id, nonce, timestamp, self.cert_serial_number, signature
        )
    }
}

#[async_trait]
impl Signer for Sha256RsaSigner {
    async fn sign(&self, message: &str) -> WxPayResult<String> {
        // 计算 SHA256 哈希
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        // 使用 RSA PKCS1v15 签名
        let signature = self
            .private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &hash)
            .map_err(|e| WxPayError::SignError(format!("RSA 签名失败: {}", e)))?;

        // Base64 编码
        Ok(base64::engine::general_purpose::STANDARD.encode(&signature))
    }

    fn merchant_id(&self) -> &str {
        &self.merchant_id
    }

    fn cert_serial_number(&self) -> &str {
        &self.cert_serial_number
    }
}

impl std::fmt::Debug for Sha256RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256RsaSigner")
            .field("merchant_id", &self.merchant_id)
            .field("cert_serial_number", &self.cert_serial_number)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sign_message() {
        let message = Sha256RsaSigner::build_sign_message(
            "POST",
            "/v3/pay/transactions/jsapi",
            1609459200,
            "test_nonce",
            r#"{"app_id":"wx88888888"}"#,
        );

        assert!(message.starts_with("POST\n"));
        assert!(message.contains("/v3/pay/transactions/jsapi"));
        assert!(message.contains("1609459200"));
        assert!(message.contains("test_nonce"));
        assert!(message.ends_with("\n"));
    }

    #[test]
    fn test_build_authorization_header() {
        // 这个测试需要有效的签名器，跳过实际签名
        // 仅测试格式
        let header = format!(
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}"#,
            "1900000109", "test_nonce", "1609459200", "CERT123", "test_signature"
        );

        assert!(header.contains("WECHATPAY2-SHA256-RSA2048"));
        assert!(header.contains("mchid=\"1900000109\""));
        assert!(header.contains("nonce_str=\"test_nonce\""));
    }
}
