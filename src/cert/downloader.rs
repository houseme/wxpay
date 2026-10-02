//! Authenticated platform certificate download and bounded refresh lifecycle.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use serde::Deserialize;

use crate::auth::signer::build_authorization_header;
use crate::auth::{Sha256RsaSigner, Sha256RsaVerifier, Signer, Verifier};
use crate::cert::CertManager;
use crate::cert::manager::{CertEntry, insert_certificate, normalize_serial};
use crate::crypto::Aes256GcmCipher;
use crate::error::{WxPayError, WxPayResult};
use crate::http::HttpClient;
use crate::http::client::HttpResponse;
use crate::utils::nonce::generate_nonce;
use crate::utils::timestamp::get_timestamp;

#[derive(Deserialize)]
struct EncryptedCertificate {
    algorithm: String,
    #[serde(default)]
    associated_data: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct CertificateEntry {
    serial_no: String,
    effective_time: Option<String>,
    expire_time: Option<String>,
    // The API only returns authenticated encrypted certificates. A plaintext
    // certificate cannot establish a trust root, even on a successful response.
    encrypt_certificate: EncryptedCertificate,
}

#[derive(Deserialize)]
struct CertificateResponse {
    data: Vec<CertificateEntry>,
}

/// Download and authenticate platform certificates before publishing them.
#[async_trait]
pub trait CertificateDownloader: Send + Sync {
    /// Return the authenticated certificate batch as serial/DER pairs.
    async fn download(&self) -> WxPayResult<Vec<(String, Vec<u8>)>>;
}

/// Authenticated WeChat Pay certificate downloader.
///
/// Bootstrap and rotation require the APIv3 key. Each encrypted certificate is
/// authenticated with AES-GCM, and the complete original response must verify
/// using an existing key or the authenticated candidate for a new serial.
pub struct CertDownloader {
    base_url: String,
    merchant_id: String,
    signer: Arc<dyn Signer>,
    http_client: Arc<dyn HttpClient>,
    cert_manager: Arc<CertManager>,
    api_v3_key: Option<String>,
}

impl CertDownloader {
    /// Construct a downloader sharing the live platform trust store.
    pub fn new(
        base_url: impl Into<String>,
        merchant_id: impl Into<String>,
        signer: Arc<dyn Signer>,
        http_client: Arc<dyn HttpClient>,
        cert_manager: Arc<CertManager>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            merchant_id: merchant_id.into(),
            signer,
            http_client,
            cert_manager,
            api_v3_key: None,
        }
    }

    /// Configure the APIv3 key used to authenticate and decrypt certificates.
    pub fn with_api_v3_key(mut self, api_v3_key: impl Into<String>) -> Self {
        self.api_v3_key = Some(api_v3_key.into());
        self
    }

    fn build_url(&self) -> String {
        format!("{}/v3/certificates", self.base_url.trim_end_matches('/'))
    }

    async fn build_headers(&self) -> WxPayResult<Vec<(String, String)>> {
        let timestamp = get_timestamp();
        let nonce = generate_nonce();
        let message =
            Sha256RsaSigner::build_sign_message("GET", "/v3/certificates", timestamp, &nonce, "");
        let signature = self.signer.sign(&message).await?;
        let authorization = build_authorization_header(
            &self.merchant_id,
            self.signer.cert_serial_number(),
            &nonce,
            timestamp,
            &signature,
        );
        Ok(vec![
            ("Authorization".into(), authorization),
            ("Accept".into(), "application/json".into()),
            (
                "User-Agent".into(),
                concat!("wxpay-rs/", env!("CARGO_PKG_VERSION")).into(),
            ),
        ])
    }
}

#[async_trait]
impl CertificateDownloader for CertDownloader {
    async fn download(&self) -> WxPayResult<Vec<(String, Vec<u8>)>> {
        let cipher = Aes256GcmCipher::new(
            self.api_v3_key
                .as_deref()
                .ok_or_else(|| WxPayError::missing_config("api_v3_key"))?,
        )?;
        let response = self
            .http_client
            .get(&self.build_url(), self.build_headers().await?)
            .await?;
        if !response.is_success() {
            return Err(WxPayError::CertificateDownloadError(format!(
                "HTTP status {}",
                response.status
            )));
        }
        let serial = required_header(&response, "Wechatpay-Serial")?;
        let timestamp = required_header(&response, "Wechatpay-Timestamp")?;
        let nonce = required_header(&response, "Wechatpay-Nonce")?;
        let signature = required_header(&response, "Wechatpay-Signature")?;
        let seconds = timestamp
            .parse::<i64>()
            .map_err(|_| WxPayError::InvalidSignatureFormat("Invalid response timestamp".into()))?;
        if seconds.abs_diff(get_timestamp()) > 300 {
            return Err(WxPayError::SignatureVerificationFailed);
        }
        let response_data: CertificateResponse = serde_json::from_str(&response.body)?;
        if response_data.data.is_empty() {
            return Err(WxPayError::CertificateParseError(
                "Empty certificate batch".into(),
            ));
        }
        let mut batch = BTreeMap::new();
        for item in response_data.data {
            if item.encrypt_certificate.algorithm != "AEAD_AES_256_GCM" {
                return Err(WxPayError::CertificateParseError(
                    "Unsupported certificate encryption algorithm".into(),
                ));
            }
            let plaintext = cipher.decrypt_notification(
                &item.encrypt_certificate.nonce,
                &item.encrypt_certificate.ciphertext,
                &item.encrypt_certificate.associated_data,
            )?;
            let (actual_serial, mut entry) =
                CertEntry::parse(&decode_certificate_der(&plaintext)?)?;
            if normalize_serial(&item.serial_no)? != actual_serial {
                return Err(WxPayError::InvalidCertificate(
                    "Downloaded certificate serial mismatch".into(),
                ));
            }
            entry.restrict_validity(item.effective_time.as_deref(), item.expire_time.as_deref())?;
            insert_certificate(&mut batch, actual_serial, entry)?;
        }

        // Keep the timestamp and original body bytes exactly as signed. Only an
        // unknown serial may fall back to an AEAD-authenticated candidate; an
        // invalid signature for an installed identity must never replace it.
        let message = format!("{timestamp}\n{nonce}\n{}\n", response.body);
        let existing_verifier = Sha256RsaVerifier::from_manager(self.cert_manager.clone());
        let verified = match existing_verifier
            .verify_with_serial(&message, signature, serial)
            .await
        {
            Ok(verified) => verified,
            Err(WxPayError::CertificateNotFound(_)) => {
                let candidates = Arc::new(CertManager::from_batch(batch.clone()));
                Sha256RsaVerifier::from_manager(candidates)
                    .verify_with_serial(&message, signature, serial)
                    .await?
            }
            Err(error) => return Err(error),
        };
        if !verified {
            return Err(WxPayError::SignatureVerificationFailed);
        }
        let result = batch
            .iter()
            .map(|(serial, entry)| (serial.clone(), entry.der().to_vec()))
            .collect();
        self.cert_manager.publish_batch(batch)?;
        Ok(result)
    }
}

fn required_header<'a>(response: &'a HttpResponse, name: &str) -> WxPayResult<&'a str> {
    let mut values = response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = values
        .next()
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| WxPayError::InvalidSignatureFormat(format!("Missing {name}")))?;
    if values.next().is_some() {
        return Err(WxPayError::InvalidSignatureFormat(format!(
            "Duplicate {name}"
        )));
    }
    Ok(value)
}

fn decode_certificate_der(data: &str) -> WxPayResult<Vec<u8>> {
    let data = data.trim();
    if data.starts_with("-----BEGIN") {
        return crate::cert::manager::decode_pem_or_der(data.as_bytes(), "CERTIFICATE");
    }
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| WxPayError::CertificateParseError(format!("Invalid Base64 certificate: {e}")))
}

impl std::fmt::Debug for CertDownloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertDownloader")
            .field("base_url", &self.base_url)
            .field("merchant_id", &self.merchant_id)
            .finish_non_exhaustive()
    }
}

/// Owns a background refresh task; dropping the handle cancels it.
#[must_use = "dropping the handle stops automatic certificate refresh"]
pub struct CertRefreshHandle {
    task: tokio::task::JoinHandle<()>,
}

impl CertRefreshHandle {
    /// Cancel a refresh, including any in-flight download.
    pub fn cancel(&self) {
        self.task.abort();
    }

    /// Check whether the task has stopped.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for CertRefreshHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl std::fmt::Debug for CertRefreshHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertRefreshHandle")
            .field("finished", &self.is_finished())
            .finish()
    }
}

/// Periodic certificate refresh with an immediate first download.
#[derive(Debug)]
pub struct CertRefresher {
    downloader: Arc<CertDownloader>,
    interval: u64,
}

impl CertRefresher {
    /// Configure a refresh interval in seconds; `start_auto_refresh` rejects zero.
    pub fn new(downloader: Arc<CertDownloader>, interval: u64) -> Self {
        Self {
            downloader,
            interval,
        }
    }

    /// Start refreshing in the current Tokio runtime. Retain the returned handle
    /// for the lifetime of the client. Failed refreshes preserve existing keys.
    pub fn start_auto_refresh(&self) -> WxPayResult<CertRefreshHandle> {
        let duration = std::time::Duration::from_secs(self.interval);
        if duration.is_zero() || std::time::Instant::now().checked_add(duration).is_none() {
            return Err(WxPayError::config(
                "Certificate refresh interval must be positive and representable",
            ));
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| WxPayError::config("Certificate refresh requires a Tokio runtime"))?;
        let downloader = self.downloader.clone();
        let task = runtime.spawn(async move {
            loop {
                match downloader.download().await {
                    Ok(certificates) => tracing::info!(
                        count = certificates.len(),
                        "Platform certificates refreshed"
                    ),
                    Err(error) => tracing::error!(%error, "Platform certificate refresh failed"),
                }
                tokio::time::sleep(duration).await;
            }
        });
        Ok(CertRefreshHandle { task })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verifier::tests::{test_cert_der, test_signer};
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const API_KEY: &str = "abcdefghijklmnopqrstuvwxyz123456";
    // OpenSSL-generated independent X.509 fixture, serial BEEF; same test signer.
    const ROTATED_CERT_DER_B64: &str = "MIIC7TCCAdWgAwIBAgIDAL7vMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME3d4cGF5LXJvdGF0aW9uLXRlc3QwIBcNMjYxMDAyMTI1MDE0WhgPMjA1NDAyMTcxMjUwMTRaMB4xHDAaBgNVBAMME3d4cGF5LXJvdGF0aW9uLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQFwtb0xnMYumgeu5lhc+Fv/XfU2hJcPnWtjhm3MVBhEM73dmsZ0yrvOxZtJhs4dfKs8BlWKvDInnz05+2lrDdAkNNvt0XE/0B55n2Hbk4yZIx6zOfsJlrcEoLMTfE8YNhmGeRmE+L3OJ2L9IAeMZW5If3T20E65+8BohE8nwLYXndXDTMZD1MAHj3fygCn2TZHKqLUf9lzYoeaK5Wc9A8kmO6dMcefXkskvJKJZ+S/G0f+1aFcN8MaI7GFgUkdszgnElZKWxfiv/rXQt2T88ZcK0Apsypl5fludW9IzKjpTrJtGx8R4tVfZ0veQz3xTU7joRU7mUjByhfSes6QE3tAgMBAAGjMjAwMB0GA1UdDgQWBBRqPo83M760k/SVQaPO+WrrsrCUtzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA0C1ytjJsmmzDZSpGzSgEZT90ZhJ088LOp3PGNZOxpYkRPmtLmcpBm9yZlieu+ZthMnCPJ0s/O2jbSfHj00TgYc6auj7NbXsnr8ny4Mdwa2zJu3s1xpwYv0jZteQMbW4eT2zopOakoQQfjVpKxWTzCiTsTp6JMcrlNDDCYCba4Orwm6JKOzr3IO4kA976ayW32g5AWLsVY2sh631iiDpvEqeuvfhNlDIDwVDPQnNZaycnVk+yJcq69L+CNvBrFpbKTk+lsEHSETfh1yiVh2MDb4FpGOvZ7/MGWQmzEv01/BrDX0MSwnBjzTSOoepByXSnsjaMVPi/kk1p2WgWZDi3m";

    struct MockHttp {
        response: HttpResponse,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl HttpClient for MockHttp {
        async fn get(
            &self,
            _url: &str,
            _headers: Vec<(String, String)>,
        ) -> WxPayResult<HttpResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.response.clone())
        }
        async fn post(
            &self,
            _: &str,
            _: Vec<(String, String)>,
            _: &str,
        ) -> WxPayResult<HttpResponse> {
            unreachable!()
        }
        async fn put(
            &self,
            _: &str,
            _: Vec<(String, String)>,
            _: &str,
        ) -> WxPayResult<HttpResponse> {
            unreachable!()
        }
        async fn delete(&self, _: &str, _: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
            unreachable!()
        }
        async fn patch(
            &self,
            _: &str,
            _: Vec<(String, String)>,
            _: &str,
        ) -> WxPayResult<HttpResponse> {
            unreachable!()
        }
    }

    fn serial() -> String {
        CertEntry::parse(&test_cert_der()).unwrap().0
    }

    fn encrypted_entry() -> Value {
        encrypted_certificate_entry(&test_cert_der())
    }

    fn encrypted_certificate_entry(der: &[u8]) -> Value {
        // Independent raw-key AES-GCM producer with the official certificate AAD.
        let pem = der::Document::try_from(der)
            .unwrap()
            .to_pem("CERTIFICATE", der::pem::LineEnding::LF)
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(API_KEY.as_bytes()).unwrap();
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(*b"test-nonce12"),
                Payload {
                    msg: pem.as_bytes(),
                    aad: b"certificate",
                },
            )
            .unwrap();
        json!({"serial_no":CertEntry::parse(der).unwrap().0, "encrypt_certificate":{
            "algorithm":"AEAD_AES_256_GCM", "nonce":"test-nonce12", "associated_data":"certificate",
            "ciphertext":base64::engine::general_purpose::STANDARD.encode(ciphertext)
        }})
    }

    async fn response(body: &Value) -> HttpResponse {
        let body = serde_json::to_string_pretty(body).unwrap();
        let timestamp = get_timestamp().to_string();
        let nonce = "server-nonce";
        let message = format!("{timestamp}\n{nonce}\n{body}\n");
        HttpResponse::new(
            200,
            vec![
                ("Wechatpay-Serial".into(), serial()),
                ("Wechatpay-Timestamp".into(), timestamp),
                ("Wechatpay-Nonce".into(), nonce.into()),
                (
                    "Wechatpay-Signature".into(),
                    test_signer().sign(&message).await.unwrap(),
                ),
            ],
            body,
        )
    }

    fn downloader(response: HttpResponse, manager: Arc<CertManager>) -> CertDownloader {
        CertDownloader::new(
            "https://api.mch.weixin.qq.com/",
            "1900000109",
            Arc::new(test_signer()),
            Arc::new(MockHttp {
                response,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            manager,
        )
        .with_api_v3_key(API_KEY)
    }

    #[tokio::test]
    async fn authenticated_bootstrap_updates_live_verifier() {
        let manager = Arc::new(CertManager::new());
        let verifier = Sha256RsaVerifier::from_manager(manager.clone());
        let downloader = downloader(
            response(&json!({"data":[encrypted_entry()]})).await,
            manager.clone(),
        );
        let downloaded = downloader.download().await.unwrap();
        assert_eq!(downloaded, vec![(serial(), test_cert_der())]);
        let signature = test_signer().sign("business message").await.unwrap();
        assert!(
            verifier
                .verify_with_serial("business message", &signature, &serial())
                .await
                .unwrap()
        );
        assert_eq!(
            downloader.build_url(),
            "https://api.mch.weixin.qq.com/v3/certificates"
        );
        let headers = downloader.build_headers().await.unwrap();
        let authorization = &headers[0].1;
        assert!(authorization.ends_with('"'));
        assert_eq!(authorization.matches('"').count(), 10);
    }

    #[tokio::test]
    async fn rotation_to_unknown_serial_is_authenticated_and_keeps_overlap() {
        let rotated = base64::engine::general_purpose::STANDARD
            .decode(ROTATED_CERT_DER_B64)
            .unwrap();
        for tamper in [true, false] {
            let manager =
                Arc::new(CertManager::from_material(vec![test_cert_der()], vec![]).unwrap());
            let verifier = Sha256RsaVerifier::from_manager(manager.clone());
            let mut reply =
                response(&json!({"data":[encrypted_certificate_entry(&rotated)]})).await;
            reply.headers[0].1 = "BEEF".into();
            if tamper {
                reply.body.push(' ');
            }
            let result = downloader(reply, manager.clone()).download().await;
            if tamper {
                assert!(result.is_err());
                assert_eq!(manager.count().await, 1);
                assert!(!manager.has_certificate("BEEF").await);
            } else {
                result.unwrap();
                assert_eq!(manager.count().await, 2);
                let signature = test_signer().sign("overlap").await.unwrap();
                for serial in [serial(), "BEEF".into()] {
                    assert!(
                        verifier
                            .verify_with_serial("overlap", &signature, &serial)
                            .await
                            .unwrap()
                    );
                }
                assert_eq!(manager.encryption_key().await.unwrap().0, "BEEF");
            }
        }
    }

    #[tokio::test]
    async fn unsigned_plaintext_and_bad_candidate_signatures_do_not_establish_trust() {
        let plaintext = json!({"data":[{"serial_no":serial(),"certificate":base64::engine::general_purpose::STANDARD.encode(test_cert_der())}]});
        for mut response in [
            response(&plaintext).await,
            response(&json!({"data":[encrypted_entry()]})).await,
        ] {
            let manager = Arc::new(CertManager::new());
            if response.body.contains("encrypt_certificate") {
                response.headers.clear();
            }
            assert!(
                downloader(response, manager.clone())
                    .download()
                    .await
                    .is_err()
            );
            assert_eq!(manager.count().await, 0);
        }
        let manager = Arc::new(CertManager::new());
        let mut bad = response(&json!({"data":[encrypted_entry()]})).await;
        bad.body.push(' '); // JSON remains valid, signature must fail on original bytes.
        assert!(downloader(bad, manager.clone()).download().await.is_err());
        assert_eq!(manager.count().await, 0);
    }

    #[tokio::test]
    async fn invalid_batch_is_atomic_and_preserves_existing_keys() {
        let valid = encrypted_entry();
        let mut wrong_serial = valid.clone();
        wrong_serial["serial_no"] = json!("01");
        let mut wrong_algorithm = valid.clone();
        wrong_algorithm["encrypt_certificate"]["algorithm"] = json!("OTHER");
        let mut wrong_aead = valid.clone();
        wrong_aead["encrypt_certificate"]["associated_data"] = json!("forged");
        for invalid in [wrong_serial, wrong_algorithm, wrong_aead, valid.clone()] {
            let manager = Arc::new(CertManager::new());
            let reply = response(&json!({"data":[valid.clone(),invalid]})).await;
            assert!(downloader(reply, manager.clone()).download().await.is_err());
            assert_eq!(manager.count().await, 0);
        }
        let manager = Arc::new(CertManager::from_material(vec![test_cert_der()], vec![]).unwrap());
        let mut reply = response(&json!({"data":[valid]})).await;
        reply.body.push(' ');
        assert!(downloader(reply, manager.clone()).download().await.is_err());
        assert_eq!(
            manager.get_certificate_data(&serial()).await.unwrap(),
            test_cert_der()
        );
    }

    #[tokio::test]
    async fn rejects_stale_duplicate_headers_and_expired_candidates() {
        let mut reply = response(&json!({"data":[encrypted_entry()]})).await;
        reply.headers.push(("wechatpay-serial".into(), serial()));
        assert!(
            downloader(reply, Arc::new(CertManager::new()))
                .download()
                .await
                .is_err()
        );
        let mut reply = response(&json!({"data":[encrypted_entry()]})).await;
        reply.headers[1].1 = i64::MIN.to_string();
        assert!(
            downloader(reply, Arc::new(CertManager::new()))
                .download()
                .await
                .is_err()
        );
        let mut entry = encrypted_entry();
        entry["expire_time"] = json!("2026-06-17T00:00:00Z");
        let reply = response(&json!({"data":[entry]})).await;
        assert!(
            downloader(reply, Arc::new(CertManager::new()))
                .download()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn refresher_starts_immediately_and_cancels() {
        let reply = response(&json!({"data":[encrypted_entry()]})).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let downloader = Arc::new(
            CertDownloader::new(
                "https://api.mch.weixin.qq.com",
                "1900000109",
                Arc::new(test_signer()),
                Arc::new(MockHttp {
                    response: reply,
                    calls: calls.clone(),
                }),
                Arc::new(CertManager::new()),
            )
            .with_api_v3_key(API_KEY),
        );
        assert!(
            CertRefresher::new(downloader.clone(), 0)
                .start_auto_refresh()
                .is_err()
        );
        let handle = CertRefresher::new(downloader, 3600)
            .start_auto_refresh()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        handle.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
