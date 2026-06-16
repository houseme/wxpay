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
        // 性能优化：预分配容量并就地格式化时间戳，避免 `format!` 的临时 String 分配。
        use std::fmt::Write;
        let mut s = String::with_capacity(
            method.len() + url.len() + nonce.len() + body.len() + /*timestamp*/ 20 + /*换行*/ 5,
        );
        let _ = write!(
            s,
            "{}\n{}\n{}\n{}\n{}\n",
            method, url, timestamp, nonce, body
        );
        s
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
        // 性能优化：预分配容量并就地格式化时间戳，避免 `format!` 的临时 String 分配。
        use std::fmt::Write;
        const PREFIX: &str = r#"WECHATPAY2-SHA256-RSA2048 mchid=""#;
        let mut s = String::with_capacity(
            PREFIX.len()
                + self.merchant_id.len()
                + nonce.len()
                + self.cert_serial_number.len()
                + signature.len()
                + /*固定分隔与引号*/ 64
                + /*timestamp*/ 20,
        );
        let _ = write!(
            s,
            r#"WECHATPAY2-SHA256-RSA2048 mchid="{}",nonce_str="{}",timestamp="{}",serial_no="{}",signature="{}""#,
            self.merchant_id, nonce, timestamp, self.cert_serial_number, signature
        );
        s
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
    use base64::Engine;

    /// 测试用 PKCS#8 私钥（PEM），2048-bit，与 auth/verifier 测试用证书配套。
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDQFwtb0xnMYumg\neu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz\n05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2\nL9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoe\naK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/r\nXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhf\nSes6QE3tAgMBAAECgf8ZVV+Mo6arELULVJaxcBj+WjW/epK3s4lhxSLDYx1LXKQo\nJa+FIw5dL3hBc5BwW7kUdHh33ikLGKdq3S4UjJlQ+XWNgYRpIDCCitpeRurF1G8i\npKp5m9u8Y29K7YhcnF/iVyuaDhuhFhh79avGDZjCpg/ni+6PKssc7llTYNy5MGya\nBNkxzXX2Oo5WI1IBOptOEUb6iWYz5FoAf91Ai0K8mFuB5tPCv67DqB2Rq4c6LMoX\nVzwzMZ64GhzYC6vyjltzMjtYTIDvheOZsOUgJe1pAaChwiGRDpmuf8/oybSQFFsy\n1PYF+TddnNk0NOQCPI0qXLHE2OXtdDAigPiA5v8CgYEA6/BnV4O/ZS34WvaGucPx\nQp9s59FolMyWtwELLxOZaO1LPAa9pdNC1+IfUl6zpeRu2z1kNG9f2TbgtTVrF7Lu\n5XvuhJ2OqnL8GgGYpS0vj2Sx5XRO8/pgxiAnpRy7Mkp1jA4+ZTpNQH3FoA6LZZfM\n1v/ijOH9NeHUWEw64OE/OoMCgYEA4ch19Yp73ijLvEUyAkqYrvPOkm7G02mlRD4T\nTUe2tGe8HUbOZGi5CphvItto9mssPDDsEVLilkrPDKlg3899L+ZLE8vHzw6QVoaK\n8LDQaapWbW3LazwLAna4kpNDd06h+Rx7j/n1lha6Vj/2dbEQhAAllos92B7SCNf8\nYIiXqs8CgYACC3tZztKB1fwpDantQj19DlSrTa1SXNORkni+V7Ukq6nTQ1uxbDtQ\nE62h0SBNd8VeMRIFQlHaWBdqeqQK+IoJgyF2FMd/wq9cqlbgV5vp6j2Ad5mXk7vy\n+6RcUfttXCfYpubziaXRwUVNNdMPdllYI6+a+Ppw1Rw6B68a89jQcQKBgFaW+JY4\njBTBdJE5wFocnb3LBxgln98IjzdCz0g+DpXVitF3jEP53a1wlH67wt9ubsKOyJpE\nPV4CRrHGa76p5oruOTDYYELKhRSJ+NMiHGvJxeelyfPQTTCes16TV7Zz066j+8dV\nx5fOE5xsX2r3gyv8mm3H7OnruAVoQAQNno0FAoGBAOvD07di46NEaY7OTGzt4JwE\nWa/0KzWvrQ6SCaHUnZ1yIqL6jEV7RCxKGr206cW9nlG2+n2QqAC8dinDrdLspLZG\noEqm/DoCUaghQOGnh7teguj3eqS+MHU5T/ugSJdJoMNtpQ/BlSnqkWLPoh+yrvh5\nmVKYyABhNkZONhC533bA\n-----END PRIVATE KEY-----\n";

    fn test_signer() -> Sha256RsaSigner {
        Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456")
            .expect("测试签名器应创建成功")
    }

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

        // 性能优化回归：与 format! 产物逐字节等价。
        assert_eq!(
            message,
            format!(
                "POST\n/v3/pay/transactions/jsapi\n1609459200\ntest_nonce\n{{\"app_id\":\"wx88888888\"}}\n"
            )
        );
    }

    #[test]
    fn test_build_authorization_header() {
        // 用真实签名器实例构建，验证格式正确性（商户号、序列号、时间戳、nonce、签名均嵌入）。
        let signer = test_signer();
        let header = signer.build_authorization_header("nonce_abc", 1700000000, "sig_xyz");

        assert!(header.starts_with("WECHATPAY2-SHA256-RSA2048 "));
        assert!(header.contains("mchid=\"1900000109\""));
        assert!(header.contains("nonce_str=\"nonce_abc\""));
        assert!(header.contains("timestamp=\"1700000000\""));
        assert!(header.contains("serial_no=\"CERT123456\""));
        assert!(header.contains("signature=\"sig_xyz\""));
    }

    #[tokio::test]
    async fn test_sign_is_deterministic_and_well_formed() {
        // PKCS1v15 + SHA256 是确定性签名：同一消息两次签名应完全一致。
        let signer = test_signer();
        let message = r#"{"app_id":"wx88888888","mchid":"1900000109"}"#;

        let sig_a = signer.sign(message).await.unwrap();
        let sig_b = signer.sign(message).await.unwrap();
        assert_eq!(sig_a, sig_b, "PKCS1v15 签名应为确定性的");

        // 2048-bit RSA 签名 = 256 字节 -> base64 长度 344（含可能的填充）。
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_a)
            .expect("签名应为合法 base64");
        assert_eq!(bytes.len(), 256, "2048 位密钥签名应为 256 字节");

        // 不同消息应产生不同签名。
        let sig_other = signer.sign("different message").await.unwrap();
        assert_ne!(sig_a, sig_other);
    }

    #[tokio::test]
    async fn test_signer_accessors() {
        let signer = test_signer();
        assert_eq!(signer.merchant_id(), "1900000109");
        assert_eq!(signer.cert_serial_number(), "CERT123456");
    }

    #[test]
    fn test_new_rejects_invalid_private_key() {
        let result = Sha256RsaSigner::new("mch", b"not a valid pem", "serial");
        assert!(matches!(result, Err(WxPayError::InvalidPrivateKey(_))));
    }

    #[test]
    fn test_new_rejects_non_utf8_key() {
        // 非 UTF-8 字节应被拒绝，而非 panic。
        let result = Sha256RsaSigner::new("mch", &[0xff, 0xfe, 0xfd], "serial");
        assert!(matches!(result, Err(WxPayError::InvalidPrivateKey(_))));
    }
}
