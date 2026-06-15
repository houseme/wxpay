//! 哈希工具模块
//!
//! 提供 SHA256 等哈希算法的工具函数。

use base64::Engine;
use sha2::{Digest, Sha256};

/// 计算 SHA256 哈希
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回
///
/// 返回 Base64 编码的哈希值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::crypto::hash::sha256_base64;
///
/// let hash = sha256_base64(b"Hello, World!");
/// assert!(!hash.is_empty());
/// ```
pub fn sha256_base64(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// 计算 SHA256 哈希（返回字节）
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回
///
/// 返回 32 字节的哈希值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::crypto::hash::sha256;
///
/// let hash = sha256(b"Hello, World!");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// 计算 SHA256 哈希（返回十六进制字符串）
///
/// # 参数
///
/// * `data` - 要计算哈希的数据
///
/// # 返回
///
/// 返回小写十六进制字符串
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::crypto::hash::sha256_hex;
///
/// let hash = sha256_hex(b"Hello, World!");
/// assert_eq!(hash.len(), 64);
/// ```
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// 计算 HMAC-SHA256
///
/// # 参数
///
/// * `key` - 密钥
/// * `data` - 要计算 MAC 的数据
///
/// # 返回
///
/// 返回 Base64 编码的 MAC 值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::crypto::hash::hmac_sha256_base64;
///
/// let mac = hmac_sha256_base64(b"secret_key", b"Hello, World!");
/// assert!(!mac.is_empty());
/// ```
pub fn hmac_sha256_base64(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 可以接受任意长度的密钥");
    mac.update(data);
    let result = mac.finalize();
    base64::engine::general_purpose::STANDARD.encode(result.into_bytes())
}

/// 计算 HMAC-SHA256（返回字节）
///
/// # 参数
///
/// * `key` - 密钥
/// * `data` - 要计算 MAC 的数据
///
/// # 返回
///
/// 返回 32 字节的 MAC 值
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::crypto::hash::hmac_sha256;
///
/// let mac = hmac_sha256(b"secret_key", b"Hello, World!");
/// assert_eq!(mac.len(), 32);
/// ```
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 可以接受任意长度的密钥");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// 计算 SHA256WithRSA 签名消息格式
///
/// 微信支付 API v3 签名消息格式：
/// HTTP_METHOD\nURL_PATH\nTIMESTAMP\nNONCE_STR\nBODY\n
///
/// # 参数
///
/// * `method` - HTTP 方法
/// * `url` - 请求 URL
/// * `timestamp` - 时间戳
/// * `nonce` - 随机字符串
/// * `body` - 请求体
///
/// # 返回
///
/// 返回签名消息字符串
pub fn build_sign_message(
    method: &str,
    url: &str,
    timestamp: i64,
    nonce: &str,
    body: &str,
) -> String {
    format!("{}\n{}\n{}\n{}\n{}\n", method, url, timestamp, nonce, body)
}

/// 计算 SHA256WithRSA 验签消息格式
///
/// 微信支付 API v3 验签消息格式：
/// TIMESTAMP\nNONCE_STR\nBODY\n
///
/// # 参数
///
/// * `timestamp` - 时间戳
/// * `nonce` - 随机字符串
/// * `body` - 响应体
///
/// # 返回
///
/// 返回验签消息字符串
pub fn build_verify_message(timestamp: i64, nonce: &str, body: &str) -> String {
    format!("{}\n{}\n{}\n", timestamp, nonce, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_base64() {
        let hash = sha256_base64(b"Hello, World!");
        assert!(!hash.is_empty());

        // 相同输入应该产生相同输出
        let hash2 = sha256_base64(b"Hello, World!");
        assert_eq!(hash, hash2);

        // 不同输入应该产生不同输出
        let hash3 = sha256_base64(b"Different input");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"Hello, World!");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"Hello, World!");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_sha256_base64() {
        let mac = hmac_sha256_base64(b"secret_key", b"Hello, World!");
        assert!(!mac.is_empty());

        // 相同输入应该产生相同输出
        let mac2 = hmac_sha256_base64(b"secret_key", b"Hello, World!");
        assert_eq!(mac, mac2);

        // 不同密钥应该产生不同输出
        let mac3 = hmac_sha256_base64(b"different_key", b"Hello, World!");
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_hmac_sha256() {
        let mac = hmac_sha256(b"secret_key", b"Hello, World!");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_build_sign_message() {
        let message = build_sign_message(
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
    fn test_build_verify_message() {
        let message = build_verify_message(1609459200, "test_nonce", r#"{"code":"SUCCESS"}"#);

        assert!(message.starts_with("1609459200\n"));
        assert!(message.contains("test_nonce"));
        assert!(message.ends_with("\n"));
    }
}
