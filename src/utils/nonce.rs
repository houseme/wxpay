//! 随机数生成工具
//!
//! 提供生成随机 Nonce 的功能，用于请求签名。

use rand::RngExt;
use uuid::Uuid;

/// 生成随机 Nonce 字符串
///
/// 使用 UUID v4 生成 32 位随机字符串，用于请求签名中的 nonce_str 字段。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::generate_nonce;
///
/// let nonce = generate_nonce();
/// assert_eq!(nonce.len(), 32);
/// ```
pub fn generate_nonce() -> String {
    Uuid::new_v4().to_string().replace('-', "")
}

/// 生成指定长度的随机字符串
///
/// 生成由数字和小写字母组成的随机字符串。
///
/// # 参数
///
/// * `length` - 生成字符串的长度
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::nonce::generate_random_string;
///
/// let s = generate_random_string(16);
/// assert_eq!(s.len(), 16);
/// ```
pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..chars.len());
            chars[idx]
        })
        .collect()
}

/// 生成指定长度的随机数字字符串
///
/// 生成由纯数字组成的随机字符串。
///
/// # 参数
///
/// * `length` - 生成字符串的长度
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::utils::nonce::generate_numeric_string;
///
/// let s = generate_numeric_string(6);
/// assert_eq!(s.len(), 6);
/// assert!(s.chars().all(|c| c.is_ascii_digit()));
/// ```
pub fn generate_numeric_string(length: usize) -> String {
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let digit = rng.random_range(0..10);
            char::from(b'0' + digit)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // 长度应该是 32
        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);

        // 应该是不同的值
        assert_ne!(nonce1, nonce2);

        // 应该只包含数字和小写字母
        assert!(nonce1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_random_string() {
        let s1 = generate_random_string(16);
        let s2 = generate_random_string(16);

        assert_eq!(s1.len(), 16);
        assert_eq!(s2.len(), 16);
        assert_ne!(s1, s2);

        // 应该只包含小写字母和数字
        assert!(s1.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_numeric_string() {
        let s = generate_numeric_string(6);

        assert_eq!(s.len(), 6);
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_uniqueness() {
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..100 {
            let nonce = generate_nonce();
            assert!(nonces.insert(nonce), "Duplicate nonce generated");
        }
    }
}
