//! Response signature verification backed by a shared platform trust store.

use crate::cert::CertManager;
use crate::cert::manager::VerificationKey;
use crate::error::{WxPayError, WxPayResult};
use async_trait::async_trait;
use base64::Engine;
use std::sync::Arc;

/// Signature verification. Protocol entry points should always choose a key
/// with `verify_with_serial` using the original `Wechatpay-Serial` header.
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify with an active configured key. Prefer serial-scoped verification.
    async fn verify(&self, message: &str, signature: &str) -> WxPayResult<bool>;

    /// Verify with the certificate serial or exact platform public-key ID.
    async fn verify_with_serial(
        &self,
        message: &str,
        signature: &str,
        serial_number: &str,
    ) -> WxPayResult<bool>;
}

/// SHA256-RSA verifier. Parsed keys are shared with certificate refreshes; keys
/// are selected by serial/ID and certificate validity is checked on every use.
#[derive(Debug)]
pub struct Sha256RsaVerifier {
    manager: Arc<CertManager>,
}

impl Sha256RsaVerifier {
    /// Create a verifier from trusted PEM or DER X.509 certificates.
    pub fn new(certificates: Vec<Vec<u8>>) -> WxPayResult<Self> {
        Self::new_with_public_keys(certificates, vec![])
    }

    /// Create a verifier with trusted certificates and/or platform public keys.
    pub fn new_with_public_keys(
        certificates: Vec<Vec<u8>>,
        public_keys: Vec<(String, Vec<u8>)>,
    ) -> WxPayResult<Self> {
        Ok(Self::from_manager(Arc::new(CertManager::from_material(
            certificates,
            public_keys,
        )?)))
    }

    /// Use a live shared manager so authenticated refreshes take effect immediately.
    pub fn from_manager(manager: Arc<CertManager>) -> Self {
        Self { manager }
    }

    /// Build the APIv3 signature message: timestamp, nonce, original body, each
    /// followed by a newline. The body must not be parsed and reserialized.
    pub fn build_verify_message(timestamp: i64, nonce: &str, body: &str) -> String {
        use std::fmt::Write;
        let mut message = String::with_capacity(nonce.len() + body.len() + 23);
        let _ = write!(message, "{timestamp}\n{nonce}\n{body}\n");
        message
    }

    fn decode_signature(signature: &str) -> WxPayResult<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|e| {
                WxPayError::InvalidSignatureFormat(format!("Invalid Base64 signature: {e}"))
            })
    }

    fn verify_signature(key: &VerificationKey, message: &str, signature: &[u8]) -> bool {
        key.key.verify_sig(message.as_bytes(), signature).is_ok()
    }
}

#[async_trait]
impl Verifier for Sha256RsaVerifier {
    async fn verify(&self, message: &str, signature: &str) -> WxPayResult<bool> {
        let keys = self.manager.verification_keys();
        if keys.is_empty() {
            return Err(WxPayError::CertificateVerificationError(
                "No active verification keys".into(),
            ));
        }
        let signature = Self::decode_signature(signature)?;
        Ok(keys
            .iter()
            .any(|key| Self::verify_signature(key, message, &signature)))
    }

    async fn verify_with_serial(
        &self,
        message: &str,
        signature: &str,
        serial_number: &str,
    ) -> WxPayResult<bool> {
        let key = self.manager.verification_key(serial_number)?;
        let signature = Self::decode_signature(signature)?;
        Ok(Self::verify_signature(&key, message, &signature))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::{Sha256RsaSigner, Signer};
    use base64::Engine;

    /// 测试用自签名证书（DER，base64 编码）及其配套 PKCS#8 私钥（PEM）。
    /// 由 openssl 离线生成，CN=wxpay-rs-test，2048-bit，SHA256WithRSA。
    pub(crate) const TEST_CERT_DER_B64: &str = "MIIDMTCCAhmgAwIBAgIUO0KjQ4nVBzRZyR/2689auBsGMPcwDQYJKoZIhvcNAQELBQAwJzEWMBQGA1UEAwwNd3hwYXktcnMtdGVzdDENMAsGA1UECgwEdGVzdDAgFw0yNjA2MTYwNDE3MDlaGA8yMDUzMTEwMTA0MTcwOVowJzEWMBQGA1UEAwwNd3hwYXktcnMtdGVzdDENMAsGA1UECgwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAXC1vTGcxi6aB67mWFz4W/9d9TaElw+da2OGbcxUGEQzvd2axnTKu87Fm0mGzh18qzwGVYq8MiefPTn7aWsN0CQ02+3RcT/QHnmfYduTjJkjHrM5+wmWtwSgsxN8Txg2GYZ5GYT4vc4nYv0gB4xlbkh/dPbQTrn7wGiETyfAthed1cNMxkPUwAePd/KAKfZNkcqotR/2XNih5orlZz0DySY7p0xx59eSyS8koln5L8bR/7VoVw3wxojsYWBSR2zOCcSVkpbF+K/+tdC3ZPzxlwrQCmzKmXl+W51b0jMqOlOsm0bHxHi1V9nS95DPfFNTuOhFTuZSMHKF9J6zpATe0CAwEAAaNTMFEwHQYDVR0OBBYEFGo+jzczvrST9JVBo875auuysJS3MB8GA1UdIwQYMBaAFGo+jzczvrST9JVBo875auuysJS3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAChV2tnTzVIRbSHRrP0unCUYxf9mPldpVVB3Zbzb+S1oMllYwtUuNCgOuaIWz8LlA2A9yEoV5zvPJfrQFNJ3KYrMyAXJ7Q9UDFMSpP5aaqvtIq1GcLfw8EiyuGN3nQwHBPA2AN3JznDufWY5LI2TLDwiX/mv8U4ZzWHMOye7huI3AEIVTXv01NXWleI2TA/MxTMppaO8t5lzlaDXgPMnZqW5qsuHZzGk+aq07SO9KitKO4E5PoNYfE6ywWn13mOZrRklCtT9mauaE/kCHIAQPuyfWrZ2lvkjWIefQ/onZBxAKP5z6VcSb3Z/3G85MQm9kSnwUFjKw7yuauDv/wyq/AU=";

    pub(crate) const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDQFwtb0xnMYumg\neu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz\n05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2\nL9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoe\naK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/r\nXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhf\nSes6QE3tAgMBAAECgf8ZVV+Mo6arELULVJaxcBj+WjW/epK3s4lhxSLDYx1LXKQo\nJa+FIw5dL3hBc5BwW7kUdHh33ikLGKdq3S4UjJlQ+XWNgYRpIDCCitpeRurF1G8i\npKp5m9u8Y29K7YhcnF/iVyuaDhuhFhh79avGDZjCpg/ni+6PKssc7llTYNy5MGya\nBNkxzXX2Oo5WI1IBOptOEUb6iWYz5FoAf91Ai0K8mFuB5tPCv67DqB2Rq4c6LMoX\nVzwzMZ64GhzYC6vyjltzMjtYTIDvheOZsOUgJe1pAaChwiGRDpmuf8/oybSQFFsy\n1PYF+TddnNk0NOQCPI0qXLHE2OXtdDAigPiA5v8CgYEA6/BnV4O/ZS34WvaGucPx\nQp9s59FolMyWtwELLxOZaO1LPAa9pdNC1+IfUl6zpeRu2z1kNG9f2TbgtTVrF7Lu\n5XvuhJ2OqnL8GgGYpS0vj2Sx5XRO8/pgxiAnpRy7Mkp1jA4+ZTpNQH3FoA6LZZfM\n1v/ijOH9NeHUWEw64OE/OoMCgYEA4ch19Yp73ijLvEUyAkqYrvPOkm7G02mlRD4T\nTUe2tGe8HUbOZGi5CphvItto9mssPDDsEVLilkrPDKlg3899L+ZLE8vHzw6QVoaK\n8LDQaapWbW3LazwLAna4kpNDd06h+Rx7j/n1lha6Vj/2dbEQhAAllos92B7SCNf8\nYIiXqs8CgYACC3tZztKB1fwpDantQj19DlSrTa1SXNORkni+V7Ukq6nTQ1uxbDtQ\nE62h0SBNd8VeMRIFQlHaWBdqeqQK+IoJgyF2FMd/wq9cqlbgV5vp6j2Ad5mXk7vy\n+6RcUfttXCfYpubziaXRwUVNNdMPdllYI6+a+Ppw1Rw6B68a89jQcQKBgFaW+JY4\njBTBdJE5wFocnb3LBxgln98IjzdCz0g+DpXVitF3jEP53a1wlH67wt9ubsKOyJpE\nPV4CRrHGa76p5oruOTDYYELKhRSJ+NMiHGvJxeelyfPQTTCes16TV7Zz066j+8dV\nx5fOE5xsX2r3gyv8mm3H7OnruAVoQAQNno0FAoGBAOvD07di46NEaY7OTGzt4JwE\nWa/0KzWvrQ6SCaHUnZ1yIqL6jEV7RCxKGr206cW9nlG2+n2QqAC8dinDrdLspLZG\noEqm/DoCUaghQOGnh7teguj3eqS+MHU5T/ugSJdJoMNtpQ/BlSnqkWLPoh+yrvh5\nmVKYyABhNkZONhC533bA\n-----END PRIVATE KEY-----\n";

    pub(crate) fn test_cert_der() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(TEST_CERT_DER_B64)
            .expect("测试证书 base64 解码应成功")
    }

    pub(crate) fn test_signer() -> Sha256RsaSigner {
        Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456")
            .expect("测试签名器应创建成功")
    }

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

    #[tokio::test]
    async fn test_verify_valid_signature() {
        // 用配套私钥对消息签名，再用证书中的公钥验签 —— 端到端验证验签器正确性。
        let verifier = Sha256RsaVerifier::new(vec![test_cert_der()]).unwrap();
        let signer = test_signer();

        let message = r#"{"code":"SUCCESS","message":"成功"}"#;
        let signature = signer.sign(message).await.unwrap();

        let valid = verifier.verify(message, &signature).await.unwrap();
        assert!(valid, "匹配公钥验签应返回 true");
    }

    #[tokio::test]
    async fn test_verify_tampered_message_returns_false() {
        let verifier = Sha256RsaVerifier::new(vec![test_cert_der()]).unwrap();
        let signer = test_signer();

        let signature = signer.sign("original message").await.unwrap();

        // 篡改消息内容：验签应失败（返回 false，而非报错）。
        let valid = verifier
            .verify("tampered message", &signature)
            .await
            .unwrap();
        assert!(!valid, "篡改消息后验签应返回 false");
    }

    #[tokio::test]
    async fn test_verify_with_serial_matches_certificate() {
        let der = test_cert_der();
        let verifier = Sha256RsaVerifier::new(vec![der.clone()]).unwrap();
        let signer = test_signer();

        // 用与验签器相同的方式推导证书序列号（私有方法在本模块内可见）。
        let (serial, _) = crate::cert::manager::CertEntry::parse(&der).unwrap();

        let message = "serial-scoped verify";
        let signature = signer.sign(message).await.unwrap();

        // 指定正确序列号：验签通过。
        let ok = verifier
            .verify_with_serial(message, &signature, &serial)
            .await
            .unwrap();
        assert!(ok);

        // 指定不存在的序列号：返回 CertificateNotFound 错误。
        let missing = verifier
            .verify_with_serial(message, &signature, "NON_EXISTENT_SERIAL")
            .await;
        assert!(matches!(missing, Err(WxPayError::CertificateNotFound(_))));
    }

    #[tokio::test]
    async fn test_verify_with_no_certificates_errors() {
        // 没有任何证书时，verify 应返回错误（而非 panic）。
        let verifier = Sha256RsaVerifier::new(vec![]).unwrap();
        let result = verifier.verify("msg", "sig").await;
        assert!(matches!(
            result,
            Err(WxPayError::CertificateVerificationError(_))
        ));
    }

    #[test]
    fn test_verifier_rejects_invalid_certificate() {
        // 非法的 DER 数据应解析失败。
        let result = Sha256RsaVerifier::new(vec![b"not a valid der".to_vec()]);
        assert!(matches!(result, Err(WxPayError::CertificateParseError(_))));
    }

    #[tokio::test]
    async fn test_verify_rejects_malformed_signature() {
        let verifier = Sha256RsaVerifier::new(vec![test_cert_der()]).unwrap();
        // 非法 base64 的签名应返回 InvalidSignatureFormat 错误。
        let result = verifier.verify("msg", "!!!not-base64!!!").await;
        assert!(matches!(result, Err(WxPayError::InvalidSignatureFormat(_))));
    }
}
