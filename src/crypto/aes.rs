//! AES-256-GCM 加解密模块
//!
//! 提供 AES-256-GCM 加密和解密功能，用于通知数据的加解密。

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

use crate::error::{WxPayError, WxPayResult};

/// AES-256-GCM 加密器
///
/// 使用 AES-256-GCM 算法加密和解密通知数据。
///
/// # 示例
///
/// ```rust
/// use wxpay_rs::crypto::Aes256GcmCipher;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";
/// let cipher = Aes256GcmCipher::new(api_v3_key)?;
///
/// let plaintext = "sensitive_data";
/// let (nonce, ciphertext) = cipher.encrypt(plaintext)?;
///
/// let decrypted = cipher.decrypt(&nonce, &ciphertext)?;
/// assert_eq!(plaintext, decrypted);
/// # Ok(())
/// # }
/// ```
pub struct Aes256GcmCipher {
    /// AES-256-GCM 密钥
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// 创建新的 AES-256-GCM 加密器
    ///
    /// # 参数
    ///
    /// * `api_v3_key` - API v3 密钥（32 字节）
    ///
    /// # 返回
    ///
    /// 返回加密器实例
    pub fn new(api_v3_key: &str) -> WxPayResult<Self> {
        if api_v3_key.len() != 32 {
            return Err(WxPayError::InvalidKey(
                "API v3 密钥必须是 32 个字符".to_string(),
            ));
        }

        // 使用 SHA256 哈希生成 32 字节密钥
        let mut hasher = Sha256::new();
        hasher.update(api_v3_key.as_bytes());
        let key = hasher.finalize();

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WxPayError::InvalidKey(format!("创建 AES 密钥失败：{}", e)))?;

        Ok(Self { cipher })
    }

    /// 从原始密钥创建加密器
    ///
    /// # 参数
    ///
    /// * `key` - 32 字节密钥
    ///
    /// # 返回
    ///
    /// 返回加密器实例
    pub fn from_key(key: &[u8]) -> WxPayResult<Self> {
        if key.len() != 32 {
            return Err(WxPayError::InvalidKey("密钥必须是 32 字节".to_string()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| WxPayError::InvalidKey(format!("创建 AES 密钥失败：{}", e)))?;

        Ok(Self { cipher })
    }

    /// 加密数据
    ///
    /// # 参数
    ///
    /// * `plaintext` - 要加密的明文
    ///
    /// # 返回
    ///
    /// 返回 (nonce, ciphertext) 元组，都是 Base64 编码的字符串
    pub fn encrypt(&self, plaintext: &str) -> WxPayResult<(String, String)> {
        // 生成随机 nonce（12 字节）
        let mut rng = rand::rng();
        let mut nonce_bytes = [0_u8; 12];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| WxPayError::EncryptionError(format!("AES-256-GCM 加密失败：{}", e)))?;

        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);

        Ok((nonce_b64, ciphertext_b64))
    }

    /// 使用指定 nonce 加密数据
    ///
    /// # 参数
    ///
    /// * `plaintext` - 要加密的明文
    /// * `nonce` - 12 字节 nonce
    ///
    /// # 返回
    ///
    /// 返回 Base64 编码的密文
    pub fn encrypt_with_nonce(&self, plaintext: &str, nonce: &[u8]) -> WxPayResult<String> {
        if nonce.len() != 12 {
            return Err(WxPayError::InvalidParameter(
                "nonce 必须是 12 字节".to_string(),
            ));
        }

        let nonce_bytes: [u8; 12] = <[u8; 12]>::try_from(nonce)
            .map_err(|_| WxPayError::InvalidParameter("nonce 长度必须是 12 字节".to_string()))?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| WxPayError::EncryptionError(format!("AES-256-GCM 加密失败：{}", e)))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(&ciphertext))
    }

    /// 解密数据
    ///
    /// # 参数
    ///
    /// * `nonce` - Base64 编码的 nonce
    /// * `ciphertext` - Base64 编码的密文
    ///
    /// # 返回
    ///
    /// 返回解密后的明文
    pub fn decrypt(&self, nonce: &str, ciphertext: &str) -> WxPayResult<String> {
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(nonce)
            .map_err(|e| WxPayError::InvalidCiphertext(format!("nonce Base64 解码失败：{}", e)))?;

        let ciphertext_bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| WxPayError::InvalidCiphertext(format!("密文 Base64 解码失败：{}", e)))?;

        let nonce = {
            let nonce: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| {
                WxPayError::InvalidParameter("nonce 长度必须是 12 字节".to_string())
            })?;
            Nonce::from(nonce)
        };

        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext_bytes.as_ref())
            .map_err(|e| WxPayError::DecryptionError(format!("AES-256-GCM 解密失败：{}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| WxPayError::DecryptionError(format!("解密结果不是有效的 UTF-8: {}", e)))
    }

    /// 解密微信支付通知数据
    ///
    /// 微信支付通知的加密数据格式：
    /// {
    ///     "algorithm": "AEAD_AES_256_GCM",
    ///     "ciphertext": "base64_encoded_ciphertext",
    ///     "associated_data": "associated_data",
    ///     "nonce": "nonce"
    /// }
    ///
    /// # 参数
    ///
    /// * `nonce` - nonce 字符串
    /// * `ciphertext` - Base64 编码的密文
    /// * `associated_data` - 关联数据
    ///
    /// # 返回
    ///
    /// 返回解密后的明文
    pub fn decrypt_notification(
        &self,
        nonce: &str,
        ciphertext: &str,
        associated_data: &str,
    ) -> WxPayResult<String> {
        let nonce_bytes = nonce.as_bytes();
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| WxPayError::InvalidCiphertext(format!("密文 Base64 解码失败：{}", e)))?;

        let nonce = {
            let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
                WxPayError::InvalidParameter("nonce 长度必须是 12 字节".to_string())
            })?;
            Nonce::from(nonce)
        };

        // 使用 associated_data 作为附加认证数据
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: &ciphertext_bytes,
                    aad: associated_data.as_bytes(),
                },
            )
            .map_err(|e| WxPayError::DecryptionError(format!("AES-256-GCM 解密失败：{}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| WxPayError::DecryptionError(format!("解密结果不是有效的 UTF-8: {}", e)))
    }
}

impl std::fmt::Debug for Aes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmCipher").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";
        let cipher = Aes256GcmCipher::new(api_v3_key).unwrap();

        let plaintext = "Hello, WeChat Pay!";
        let (nonce, ciphertext) = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_encrypt_chinese() {
        let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";
        let cipher = Aes256GcmCipher::new(api_v3_key).unwrap();

        let plaintext = "微信支付测试";
        let (nonce, ciphertext) = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_encrypt_with_nonce() {
        let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";
        let cipher = Aes256GcmCipher::new(api_v3_key).unwrap();

        let nonce = b"testnonce123"; // 12 bytes
        let plaintext = "Hello, WeChat Pay!";
        let ciphertext = cipher.encrypt_with_nonce(plaintext, nonce).unwrap();

        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let decrypted = cipher.decrypt(&nonce_b64, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_decrypt_notification() {
        let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";
        let cipher = Aes256GcmCipher::new(api_v3_key).unwrap();

        let plaintext = r#"{"out_trade_no":"123456789"}"#;
        let associated_data = "notification";
        let nonce = "testnonce123";
        let nonce_bytes: [u8; 12] = nonce
            .as_bytes()
            .try_into()
            .expect("nonce length should be 12");
        let nonce_value = Nonce::from(nonce_bytes);

        let ciphertext = base64::engine::general_purpose::STANDARD.encode(
            cipher
                .cipher
                .encrypt(
                    &nonce_value,
                    aes_gcm::aead::Payload {
                        msg: plaintext.as_bytes(),
                        aad: associated_data.as_bytes(),
                    },
                )
                .expect("encrypt notification payload failed"),
        );

        // 解密通知
        let decrypted = cipher
            .decrypt_notification(nonce, &ciphertext, associated_data)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_invalid_key_length() {
        let result = Aes256GcmCipher::new("short_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_invalid_nonce_length() {
        let api_v3_key = "abcdefghijklmnopqrstuvwxyz123456";
        let cipher = Aes256GcmCipher::new(api_v3_key).unwrap();

        let result = cipher.encrypt_with_nonce("test", b"short");
        assert!(result.is_err());
    }
}
