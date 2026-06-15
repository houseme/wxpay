//! RSA-OAEP 加解密模块
//!
//! 提供 RSA-OAEP 加密和解密功能，用于敏感信息的加解密。

use base64::Engine;
use der::Encode;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::error::{WxPayError, WxPayResult};

/// RSA-OAEP 加密器
///
/// 使用 RSA-OAEP 算法加密敏感信息。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::crypto::RsaOaepCipher;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cert_pem = std::fs::read_to_string("path/to/platform_cert.pem")?;
/// let cipher = RsaOaepCipher::from_certificate(cert_pem.as_bytes())?;
///
/// let plaintext = "sensitive_data";
/// let encrypted = cipher.encrypt(plaintext)?;
/// # Ok(())
/// # }
/// ```
pub struct RsaOaepCipher {
    /// 公钥
    public_key: RsaPublicKey,
}

impl RsaOaepCipher {
    /// 从证书创建加密器
    ///
    /// # 参数
    ///
    /// * `cert_der` - 证书（DER 格式）
    ///
    /// # 返回
    ///
    /// 返回加密器实例
    pub fn from_certificate(cert_der: &[u8]) -> WxPayResult<Self> {
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(cert_der)
            .map_err(|e| WxPayError::CertificateParseError(format!("证书解析失败：{}", e)))?;

        let spki = cert.tbs_certificate().subject_public_key_info();
        let spki_der = spki
            .to_der()
            .map_err(|e| WxPayError::CertificateParseError(format!("提取证书 SPKI 失败：{}", e)))?;

        let public_key = RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|e| WxPayError::CertificateParseError(format!("提取公钥失败：{}", e)))?;

        Ok(Self { public_key })
    }

    /// 从公钥创建加密器
    ///
    /// # 参数
    ///
    /// * `public_key_pem` - 公钥（PEM 格式）
    ///
    /// # 返回
    ///
    /// 返回加密器实例
    pub fn from_public_key(public_key_pem: &[u8]) -> WxPayResult<Self> {
        let pem_str = std::str::from_utf8(public_key_pem)
            .map_err(|e| WxPayError::InvalidKey(format!("无效的 UTF-8 编码：{}", e)))?;

        // 尝试 PKCS#8 格式
        if let Ok(key) = RsaPublicKey::from_public_key_pem(pem_str) {
            return Ok(Self { public_key: key });
        }

        // 尝试 PKCS#1 格式
        if let Ok(key) = RsaPublicKey::from_pkcs1_pem(pem_str) {
            return Ok(Self { public_key: key });
        }

        Err(WxPayError::InvalidKey(
            "无法解析公钥，请确保是有效的 PKCS#8 或 PKCS#1 PEM 格式".to_string(),
        ))
    }

    /// 加密数据
    ///
    /// # 参数
    ///
    /// * `plaintext` - 要加密的明文
    ///
    /// # 返回
    ///
    /// 返回 Base64 编码的密文
    pub fn encrypt(&self, plaintext: &str) -> WxPayResult<String> {
        let mut rng = rand::rng();
        let padding = Oaep::<Sha256>::new();

        let ciphertext = self
            .public_key
            .encrypt(&mut rng, padding, plaintext.as_bytes())
            .map_err(|e| WxPayError::EncryptionError(format!("RSA-OAEP 加密失败：{}", e)))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(&ciphertext))
    }

    /// 加密数据（使用 PKCS1v15 填充）
    ///
    /// # 参数
    ///
    /// * `plaintext` - 要加密的明文
    ///
    /// # 返回
    ///
    /// 返回 Base64 编码的密文
    pub fn encrypt_pkcs1v15(&self, plaintext: &str) -> WxPayResult<String> {
        let mut rng = rand::rng();

        let ciphertext = self
            .public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes())
            .map_err(|e| WxPayError::EncryptionError(format!("RSA PKCS1v15 加密失败：{}", e)))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(&ciphertext))
    }
}

impl std::fmt::Debug for RsaOaepCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOaepCipher").finish()
    }
}

/// RSA-OAEP 解密器
///
/// 使用 RSA-OAEP 算法解密敏感信息。
///
/// # 示例
///
/// ```rust,no_run
/// use wxpay_rs::crypto::RsaOaepDecrypter;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let private_key_pem = std::fs::read_to_string("path/to/private_key.pem")?;
/// let decrypter = RsaOaepDecrypter::new(private_key_pem.as_bytes())?;
///
/// let encrypted = "base64_encoded_ciphertext";
/// let decrypted = decrypter.decrypt(encrypted)?;
/// # Ok(())
/// # }
/// ```
pub struct RsaOaepDecrypter {
    /// 私钥
    private_key: RsaPrivateKey,
}

impl RsaOaepDecrypter {
    /// 创建新的解密器
    ///
    /// # 参数
    ///
    /// * `private_key_pem` - 私钥（PEM 格式）
    ///
    /// # 返回
    ///
    /// 返回解密器实例
    pub fn new(private_key_pem: &[u8]) -> WxPayResult<Self> {
        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|e| WxPayError::InvalidPrivateKey(format!("无效的 UTF-8 编码：{}", e)))?;

        // 尝试 PKCS#8 格式
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem_str) {
            return Ok(Self { private_key: key });
        }

        // 尝试 PKCS#1 格式
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem_str) {
            return Ok(Self { private_key: key });
        }

        Err(WxPayError::InvalidPrivateKey(
            "无法解析私钥，请确保是有效的 PKCS#8 或 PKCS#1 PEM 格式".to_string(),
        ))
    }

    /// 解密数据
    ///
    /// # 参数
    ///
    /// * `ciphertext` - Base64 编码的密文
    ///
    /// # 返回
    ///
    /// 返回解密后的明文
    pub fn decrypt(&self, ciphertext: &str) -> WxPayResult<String> {
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| WxPayError::InvalidCiphertext(format!("Base64 解码失败：{}", e)))?;

        let padding = Oaep::<Sha256>::new();

        let plaintext = self
            .private_key
            .decrypt(padding, &ciphertext_bytes)
            .map_err(|e| WxPayError::DecryptionError(format!("RSA-OAEP 解密失败：{}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| WxPayError::DecryptionError(format!("解密结果不是有效的 UTF-8: {}", e)))
    }

    /// 解密数据（使用 PKCS1v15 填充）
    ///
    /// # 参数
    ///
    /// * `ciphertext` - Base64 编码的密文
    ///
    /// # 返回
    ///
    /// 返回解密后的明文
    pub fn decrypt_pkcs1v15(&self, ciphertext: &str) -> WxPayResult<String> {
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| WxPayError::InvalidCiphertext(format!("Base64 解码失败：{}", e)))?;

        let plaintext = self
            .private_key
            .decrypt(Pkcs1v15Encrypt, &ciphertext_bytes)
            .map_err(|e| WxPayError::DecryptionError(format!("RSA PKCS1v15 解密失败：{}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| WxPayError::DecryptionError(format!("解密结果不是有效的 UTF-8: {}", e)))
    }
}

impl std::fmt::Debug for RsaOaepDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOaepDecrypter").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::EncodePrivateKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use spki::EncodePublicKey;

    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = StdRng::seed_from_u64(42);
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_pem = private_key.to_pkcs8_pem(Default::default()).unwrap();
        let public_key_pem = public_key.to_public_key_pem(Default::default()).unwrap();

        (
            private_key_pem.as_bytes().to_vec(),
            public_key_pem.as_bytes().to_vec(),
        )
    }

    #[test]
    fn test_rsa_oaep_encrypt_decrypt() {
        let (private_key_pem, public_key_pem) = generate_test_keypair();

        let cipher = RsaOaepCipher::from_public_key(&public_key_pem).unwrap();
        let decrypter = RsaOaepDecrypter::new(&private_key_pem).unwrap();

        let plaintext = "Hello, WeChat Pay!";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = decrypter.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_rsa_pkcs1v15_encrypt_decrypt() {
        let (private_key_pem, public_key_pem) = generate_test_keypair();

        let cipher = RsaOaepCipher::from_public_key(&public_key_pem).unwrap();
        let decrypter = RsaOaepDecrypter::new(&private_key_pem).unwrap();

        let plaintext = "Hello, WeChat Pay!";
        let encrypted = cipher.encrypt_pkcs1v15(plaintext).unwrap();
        let decrypted = decrypter.decrypt_pkcs1v15(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_rsa_encrypt_chinese() {
        let (private_key_pem, public_key_pem) = generate_test_keypair();

        let cipher = RsaOaepCipher::from_public_key(&public_key_pem).unwrap();
        let decrypter = RsaOaepDecrypter::new(&private_key_pem).unwrap();

        let plaintext = "微信支付测试";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = decrypter.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
