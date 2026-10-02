//! RSA 加解密：微信支付敏感字段使用 OAEP-SHA1 / MGF1-SHA1。
//!
//! 请求签名仍使用 SHA256-RSA；OAEP 的摘要选择与签名算法无关。

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rsa::{
        KeyPair, OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OaepAlgorithm,
        OaepPrivateDecryptingKey, OaepPublicEncryptingKey, Pkcs1PrivateDecryptingKey,
        Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey, PublicKey,
    },
};
use base64::Engine;
use der::{Decode, DecodePem, Encode};

use crate::error::{WxPayError, WxPayResult};

/// 从 PEM 解析 PKCS#8 或 PKCS#1 私钥，临时 DER 在释放时清零。
pub(crate) fn parse_rsa_private_key(pem: &[u8]) -> WxPayResult<KeyPair> {
    let pem = std::str::from_utf8(pem)
        .map_err(|_| WxPayError::InvalidPrivateKey("私钥 PEM 不是 UTF-8".into()))?;
    let (label, document) = der::SecretDocument::from_pem(pem)
        .map_err(|_| WxPayError::InvalidPrivateKey("无法解析私钥 PEM".into()))?;
    let key = match label {
        "PRIVATE KEY" => KeyPair::from_pkcs8(document.as_bytes()),
        "RSA PRIVATE KEY" => KeyPair::from_der(document.as_bytes()),
        _ => {
            return Err(WxPayError::InvalidPrivateKey(
                "只支持未加密的 RSA PKCS#8 或 PKCS#1 私钥".into(),
            ));
        }
    };
    key.map_err(|_| WxPayError::InvalidPrivateKey("无效或不受支持的 RSA 私钥".into()))
}

/// RSA-OAEP 加密器，使用微信支付规定的 SHA1 和 MGF1-SHA1，标签为空。
///
/// 解析后的公钥可复用。请求携带的 `Wechatpay-Serial` 必须与此公钥配对。
///
/// ```rust,no_run
/// use wxpay_rs::crypto::RsaOaepCipher;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cert_pem = std::fs::read("path/to/platform_cert.pem")?;
/// let cipher = RsaOaepCipher::from_certificate(&cert_pem)?;
/// let encrypted = cipher.encrypt("收款人姓名")?;
/// # Ok(())
/// # }
/// ```
pub struct RsaOaepCipher {
    oaep_key: OaepPublicEncryptingKey,
    pkcs1_key: Pkcs1PublicEncryptingKey,
}

impl RsaOaepCipher {
    /// 从 X.509 证书（PEM 或 DER）创建加密器。
    ///
    /// 本方法只解析公钥，不验证证书来源或有效期；调用方必须提供可信证书。
    pub fn from_certificate(certificate: &[u8]) -> WxPayResult<Self> {
        let cert = if certificate.starts_with(b"-----BEGIN") {
            x509_cert::Certificate::from_pem(certificate)
        } else {
            x509_cert::Certificate::from_der(certificate)
        }
        .map_err(|e| WxPayError::CertificateParseError(format!("证书解析失败：{e}")))?;
        let spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| WxPayError::CertificateParseError(format!("提取证书公钥失败：{e}")))?;
        Self::from_public_key_der(&spki)
    }

    /// 从 SPKI (`PUBLIC KEY`) 或 PKCS#1 (`RSA PUBLIC KEY`) PEM 公钥创建加密器。
    pub fn from_public_key(public_key_pem: &[u8]) -> WxPayResult<Self> {
        let pem = std::str::from_utf8(public_key_pem)
            .map_err(|_| WxPayError::InvalidKey("公钥 PEM 不是 UTF-8".into()))?;
        let (label, document) = der::Document::from_pem(pem)
            .map_err(|_| WxPayError::InvalidKey("无法解析公钥 PEM".into()))?;
        if !matches!(label, "PUBLIC KEY" | "RSA PUBLIC KEY") {
            return Err(WxPayError::InvalidKey(
                "只支持 RSA SPKI 或 PKCS#1 公钥".into(),
            ));
        }
        Self::from_public_key_der(document.as_bytes())
    }

    /// 从 SPKI 或 PKCS#1 DER 公钥创建加密器，支持 2048 至 8192 位 RSA 密钥。
    pub fn from_public_key_der(public_key_der: &[u8]) -> WxPayResult<Self> {
        let public_key = PublicKey::from_der(public_key_der)
            .map_err(|_| WxPayError::InvalidKey("无效的 RSA 公钥".into()))?;
        let spki = AsDer::<PublicKeyX509Der>::as_der(&public_key)
            .map_err(|_| WxPayError::InvalidKey("无法编码 RSA 公钥".into()))?;
        let key = PublicEncryptingKey::from_der(spki.as_ref())
            .map_err(|_| WxPayError::InvalidKey("不受支持的 RSA 公钥".into()))?;
        let oaep_key = OaepPublicEncryptingKey::new(key.clone())
            .map_err(|_| WxPayError::InvalidKey("无法创建 RSA-OAEP 公钥".into()))?;
        let pkcs1_key = Pkcs1PublicEncryptingKey::new(key)
            .map_err(|_| WxPayError::InvalidKey("无法创建 RSA PKCS1 公钥".into()))?;
        Ok(Self {
            oaep_key,
            pkcs1_key,
        })
    }

    /// 使用 OAEP-SHA1 加密 UTF-8 明文，返回 Base64 密文。
    ///
    /// 2048 位密钥最多加密 214 字节，超长输入返回错误。
    pub fn encrypt(&self, plaintext: &str) -> WxPayResult<String> {
        let mut ciphertext = vec![0; self.oaep_key.ciphertext_size()];
        let bytes = self
            .oaep_key
            .encrypt(
                &OAEP_SHA1_MGF1SHA1,
                plaintext.as_bytes(),
                &mut ciphertext,
                None,
            )
            .map_err(|_| WxPayError::EncryptionError("RSA-OAEP 加密失败".into()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// 使用 PKCS1v15 加密，供需要此填充的既有接口使用。
    ///
    /// APIv3 敏感字段应调用 [`Self::encrypt`]。
    pub fn encrypt_pkcs1v15(&self, plaintext: &str) -> WxPayResult<String> {
        let mut ciphertext = vec![0; self.pkcs1_key.ciphertext_size()];
        let bytes = self
            .pkcs1_key
            .encrypt(plaintext.as_bytes(), &mut ciphertext)
            .map_err(|_| WxPayError::EncryptionError("RSA PKCS1v15 加密失败".into()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }
}

impl std::fmt::Debug for RsaOaepCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOaepCipher").finish_non_exhaustive()
    }
}

/// RSA 解密器，默认使用微信支付规定的 OAEP-SHA1 / MGF1-SHA1。
pub struct RsaOaepDecrypter {
    oaep_key: OaepPrivateDecryptingKey,
    pkcs1_key: Pkcs1PrivateDecryptingKey,
}

impl RsaOaepDecrypter {
    /// 从未加密的 PKCS#8 或 PKCS#1 PEM 私钥创建解密器。
    pub fn new(private_key_pem: &[u8]) -> WxPayResult<Self> {
        let key_pair = parse_rsa_private_key(private_key_pem)?;
        let document = AsDer::<Pkcs8V1Der>::as_der(&key_pair)
            .map_err(|_| WxPayError::InvalidPrivateKey("无法编码 RSA 私钥".into()))?;
        let key = PrivateDecryptingKey::from_pkcs8(document.as_ref())
            .map_err(|_| WxPayError::InvalidPrivateKey("不受支持的 RSA 私钥".into()))?;
        let oaep_key = OaepPrivateDecryptingKey::new(key.clone())
            .map_err(|_| WxPayError::InvalidPrivateKey("无法创建 RSA-OAEP 私钥".into()))?;
        let pkcs1_key = Pkcs1PrivateDecryptingKey::new(key)
            .map_err(|_| WxPayError::InvalidPrivateKey("无法创建 RSA PKCS1 私钥".into()))?;
        Ok(Self {
            oaep_key,
            pkcs1_key,
        })
    }

    /// 解密 Base64 编码的 OAEP-SHA1 密文，返回 UTF-8 明文。
    pub fn decrypt(&self, ciphertext: &str) -> WxPayResult<String> {
        self.decrypt_oaep(ciphertext, &OAEP_SHA1_MGF1SHA1)
    }

    /// 迁移 SDK 2.0.2 及之前自行生成的 OAEP-SHA256 密文。
    ///
    /// 微信支付数据必须使用 [`Self::decrypt`]，不会自动回退到旧算法。
    pub fn decrypt_legacy_sha256(&self, ciphertext: &str) -> WxPayResult<String> {
        self.decrypt_oaep(ciphertext, &OAEP_SHA256_MGF1SHA256)
    }

    fn decrypt_oaep(
        &self,
        ciphertext: &str,
        algorithm: &'static OaepAlgorithm,
    ) -> WxPayResult<String> {
        let ciphertext = decode_ciphertext(ciphertext)?;
        let mut plaintext = vec![0; self.oaep_key.min_output_size()];
        let bytes = self
            .oaep_key
            .decrypt(algorithm, &ciphertext, &mut plaintext, None)
            .map_err(|_| WxPayError::DecryptionError("RSA-OAEP 解密失败".into()))?;
        decode_plaintext(bytes)
    }

    /// 使用 PKCS1v15 解密既有数据。
    ///
    /// 不应将此入口暴露为可由不可信调用方反复探测的解密服务；新协议使用 OAEP。
    pub fn decrypt_pkcs1v15(&self, ciphertext: &str) -> WxPayResult<String> {
        let ciphertext = decode_ciphertext(ciphertext)?;
        let mut plaintext = vec![0; self.pkcs1_key.min_output_size()];
        let bytes = self
            .pkcs1_key
            .decrypt(&ciphertext, &mut plaintext)
            .map_err(|_| WxPayError::DecryptionError("RSA PKCS1v15 解密失败".into()))?;
        decode_plaintext(bytes)
    }
}

fn decode_ciphertext(ciphertext: &str) -> WxPayResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .map_err(|_| WxPayError::InvalidCiphertext("密文 Base64 解码失败".into()))
}

fn decode_plaintext(plaintext: &[u8]) -> WxPayResult<String> {
    std::str::from_utf8(plaintext)
        .map(str::to_owned)
        .map_err(|_| WxPayError::DecryptionError("解密结果不是有效的 UTF-8".into()))
}

impl std::fmt::Debug for RsaOaepDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOaepDecrypter").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_fixtures::*;

    #[test]
    fn decrypts_openssl_oaep_sha1_vector() {
        let decrypter = RsaOaepDecrypter::new(PRIVATE_KEY_PEM.as_bytes()).unwrap();
        assert_eq!(
            decrypter.decrypt(OAEP_SHA1_CIPHERTEXT).unwrap(),
            "Hello, WeChat Pay!"
        );
    }

    #[test]
    fn requires_explicit_migration_for_legacy_sha256_ciphertext() {
        let decrypter = RsaOaepDecrypter::new(PRIVATE_KEY_PEM.as_bytes()).unwrap();
        assert!(decrypter.decrypt(OAEP_SHA256_CIPHERTEXT).is_err());
        assert_eq!(
            decrypter
                .decrypt_legacy_sha256(OAEP_SHA256_CIPHERTEXT)
                .unwrap(),
            "Hello, WeChat Pay!"
        );
    }

    #[test]
    fn accepts_both_public_and_private_key_encodings() {
        for public in [PUBLIC_KEY_PEM, PKCS1_PUBLIC_KEY_PEM] {
            let cipher = RsaOaepCipher::from_public_key(public.as_bytes()).unwrap();
            for private in [PRIVATE_KEY_PEM, PKCS1_PRIVATE_KEY_PEM] {
                let decrypter = RsaOaepDecrypter::new(private.as_bytes()).unwrap();
                let encrypted = cipher.encrypt("微信支付测试").unwrap();
                assert_eq!(decrypter.decrypt(&encrypted).unwrap(), "微信支付测试");
            }
        }
    }

    #[test]
    fn enforces_oaep_sha1_plaintext_byte_limit() {
        let cipher = RsaOaepCipher::from_public_key(PUBLIC_KEY_PEM.as_bytes()).unwrap();
        assert!(cipher.encrypt(&"x".repeat(214)).is_ok());
        assert!(cipher.encrypt(&"x".repeat(215)).is_err());
        assert!(cipher.encrypt(&"中".repeat(72)).is_err());
    }

    #[test]
    fn pkcs1v15_legacy_operations_remain_available() {
        let cipher = RsaOaepCipher::from_public_key(PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let decrypter = RsaOaepDecrypter::new(PRIVATE_KEY_PEM.as_bytes()).unwrap();
        assert_eq!(
            decrypter
                .decrypt_pkcs1v15(&cipher.encrypt_pkcs1v15("legacy").unwrap())
                .unwrap(),
            "legacy"
        );
    }

    #[test]
    fn rejects_malformed_keys_and_ciphertext() {
        assert!(RsaOaepCipher::from_public_key(b"bad PEM").is_err());
        assert!(RsaOaepDecrypter::new(b"bad PEM").is_err());
        let decrypter = RsaOaepDecrypter::new(PRIVATE_KEY_PEM.as_bytes()).unwrap();
        assert!(decrypter.decrypt("not base64").is_err());
        assert!(decrypter.decrypt("YQ==").is_err());
    }
}
