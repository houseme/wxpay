//! Response authentication and completion-observer regression coverage.
#[allow(dead_code)]
mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use wxpay_rs::WxPayClient;
use wxpay_rs::auth::{Sha256RsaSigner, Sha256RsaVerifier, Signer, Verifier};
use wxpay_rs::error::{WxPayError, WxPayResult};
use wxpay_rs::http::client::HttpResponse;
use wxpay_rs::http::{HttpClient, HttpMethod};
use wxpay_rs::notify::NotifyHeaders;
use wxpay_rs::services::transport::{ServiceTransport, TransportEvent, TransportObserver};

use common::{
    TEST_CERT_SERIAL, TEST_PRIVATE_KEY_PEM, signed_response, signed_response_at, test_certificate,
    test_config,
};

#[derive(Clone)]
struct FixedResponse(HttpResponse);

#[async_trait]
impl HttpClient for FixedResponse {
    async fn get(&self, _: &str, _: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        Ok(self.0.clone())
    }
    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        _: &str,
    ) -> WxPayResult<HttpResponse> {
        self.get(url, headers).await
    }
    async fn put(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        _: &str,
    ) -> WxPayResult<HttpResponse> {
        self.get(url, headers).await
    }
    async fn delete(&self, url: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        self.get(url, headers).await
    }
    async fn patch(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        _: &str,
    ) -> WxPayResult<HttpResponse> {
        self.get(url, headers).await
    }
}

fn signer() -> Arc<dyn Signer> {
    Arc::new(
        Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456").unwrap(),
    )
}

fn transport(response: HttpResponse) -> ServiceTransport {
    ServiceTransport::new(
        Arc::new(test_config()),
        Arc::new(FixedResponse(response)),
        signer(),
    )
}

async fn request(response: HttpResponse) -> WxPayResult<serde_json::Value> {
    transport(response)
        .request(HttpMethod::Get, "/v3/test", None, "verification.test")
        .await
}

fn change_header(response: &mut HttpResponse, name: &str, value: &str) {
    response
        .headers
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .unwrap()
        .1 = value.into();
}

#[tokio::test]
async fn signed_raw_json_with_whitespace_and_case_insensitive_headers_is_accepted() {
    let mut response = signed_response(200, "{\n  \"ok\" : true, \"extra\" : 7\n}\n").await;
    for (key, _) in &mut response.headers {
        *key = key.to_lowercase();
    }
    assert_eq!(request(response).await.unwrap()["ok"], true);
}

#[tokio::test]
async fn every_signature_header_is_mandatory_for_success() {
    let signed = signed_response(200, r#"{"ok":true}"#).await;
    for name in [
        "Wechatpay-Signature",
        "Wechatpay-Serial",
        "Wechatpay-Timestamp",
        "Wechatpay-Nonce",
    ] {
        let mut response = signed.clone();
        response
            .headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        assert!(
            matches!(
                request(response).await,
                Err(WxPayError::InvalidSignatureFormat(_))
            ),
            "missing {name} must fail"
        );
    }
    assert!(
        request(HttpResponse::new(200, vec![], r#"{"ok":true}"#.into()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn modified_body_nonce_serial_and_duplicate_headers_fail_closed() {
    let signed = signed_response(200, r#"{"ok":true}"#).await;
    let mut body = signed.clone();
    body.body = r#"{ "ok":true }"#.into();
    assert!(matches!(
        request(body).await,
        Err(WxPayError::SignatureVerificationFailed)
    ));
    let mut nonce = signed.clone();
    change_header(&mut nonce, "Wechatpay-Nonce", "other-nonce");
    assert!(matches!(
        request(nonce).await,
        Err(WxPayError::SignatureVerificationFailed)
    ));
    let mut serial = signed.clone();
    change_header(&mut serial, "Wechatpay-Serial", "UNKNOWN");
    assert!(matches!(
        request(serial).await,
        Err(WxPayError::CertificateNotFound(_))
    ));
    let mut duplicate = signed.clone();
    duplicate
        .headers
        .push(("wechatpay-serial".into(), TEST_CERT_SERIAL.into()));
    assert!(matches!(
        request(duplicate).await,
        Err(WxPayError::InvalidSignatureFormat(_))
    ));
    let mut probe = signed;
    change_header(
        &mut probe,
        "Wechatpay-Signature",
        "WECHATPAY/SIGNTEST/probe",
    );
    assert!(request(probe).await.is_err());
}

#[tokio::test]
async fn stale_future_and_extreme_timestamps_are_rejected_without_panics() {
    let now = chrono::Utc::now().timestamp();
    for timestamp in [
        (now - 301).to_string(),
        (now + 600).to_string(),
        i64::MIN.to_string(),
        i64::MAX.to_string(),
        "overflow99999999999999999".into(),
    ] {
        let response = signed_response_at(200, "{}", &timestamp).await;
        assert!(
            request(response).await.is_err(),
            "timestamp {timestamp} must fail"
        );
    }
}

#[tokio::test]
async fn signed_empty_success_is_verified_before_default_is_returned() {
    let response = signed_response(204, "").await;
    transport(response)
        .request_default::<()>(HttpMethod::Post, "/v3/test", Some("{}"), "empty")
        .await
        .unwrap();
    let unsigned = HttpResponse::new(204, vec![], String::new());
    assert!(
        transport(unsigned)
            .request_default::<()>(HttpMethod::Post, "/v3/test", Some("{}"), "empty")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unsigned_errors_remain_errors_and_partial_signatures_never_downgrade() {
    let response = HttpResponse::new(
        429,
        vec![],
        r#"{"code":"FREQ_LIMIT","message":"limited"}"#.into(),
    );
    assert!(matches!(
        request(response.clone()).await,
        Err(WxPayError::ApiError { .. })
    ));
    let mut partial = response;
    partial
        .headers
        .push(("Wechatpay-Nonce".into(), "nonce".into()));
    assert!(matches!(
        request(partial).await,
        Err(WxPayError::InvalidSignatureFormat(_))
    ));
    let mut signed_error = signed_response(400, r#"{"code":"PARAM_ERROR","message":"bad"}"#).await;
    signed_error.body = r#"{"code":"ORDER_CLOSED","message":"changed"}"#.into();
    assert!(matches!(
        request(signed_error).await,
        Err(WxPayError::SignatureVerificationFailed)
    ));
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<(bool, u16, u128)>>>);
impl TransportObserver for Recorder {
    fn on_success(&self, event: &TransportEvent) {
        self.0
            .lock()
            .unwrap()
            .push((true, event.status, event.elapsed_ms));
    }
    fn on_error(&self, event: &TransportEvent, _: &WxPayError) {
        self.0
            .lock()
            .unwrap()
            .push((false, event.status, event.elapsed_ms));
    }
}

struct DelayedSigner {
    fail: bool,
}
#[async_trait]
impl Signer for DelayedSigner {
    async fn sign(&self, message: &str) -> WxPayResult<String> {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if self.fail {
            Err(WxPayError::SignError("test failure".into()))
        } else {
            signer().sign(message).await
        }
    }
    fn merchant_id(&self) -> &str {
        "1900000109"
    }
    fn cert_serial_number(&self) -> &str {
        "CERT123456"
    }
}

#[tokio::test]
async fn observer_counts_json_verification_and_signer_failures_once() {
    for (body, signed, signer_fails, status) in [
        ("not json", true, false, 200),
        ("{}", false, false, 200),
        ("{}", true, true, 0),
    ] {
        let response = if signed {
            signed_response(200, body).await
        } else {
            HttpResponse::new(200, vec![], body.into())
        };
        let observer = Recorder::default();
        let transport = ServiceTransport::new_with_observer(
            Arc::new(test_config()),
            Arc::new(FixedResponse(response)),
            Arc::new(DelayedSigner { fail: signer_fails }),
            Some(Arc::new(observer.clone())),
        );
        assert!(
            transport
                .request::<serde_json::Value>(HttpMethod::Get, "/v3/test", None, "failure")
                .await
                .is_err()
        );
        let events = observer.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(!events[0].0);
        assert_eq!(events[0].1, status);
        assert!(events[0].2 >= 20, "elapsed time must include signing");
    }
}

struct SlowVerifier(Sha256RsaVerifier);
#[async_trait]
impl Verifier for SlowVerifier {
    async fn verify(&self, message: &str, signature: &str) -> WxPayResult<bool> {
        self.0.verify(message, signature).await
    }
    async fn verify_with_serial(
        &self,
        message: &str,
        signature: &str,
        serial: &str,
    ) -> WxPayResult<bool> {
        tokio::time::sleep(Duration::from_millis(20)).await;
        self.0.verify_with_serial(message, signature, serial).await
    }
}

#[tokio::test]
async fn client_custom_verifier_is_used_and_elapsed_covers_verification() {
    let observer = Recorder::default();
    let client = WxPayClient::builder()
        .config(test_config())
        .http_client(FixedResponse(signed_response(200, r#"{"data":[]}"#).await))
        .verifier(SlowVerifier(
            Sha256RsaVerifier::new(vec![test_certificate()]).unwrap(),
        ))
        .transport_observer(observer.clone())
        .build()
        .await
        .unwrap();
    assert!(
        client
            .certificates()
            .get_certificates()
            .await
            .unwrap()
            .is_empty()
    );
    let events = observer.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].0);
    assert!(events[0].2 >= 20);
}

#[tokio::test]
async fn live_certificate_store_updates_reach_existing_services_and_notify_handlers() {
    let client = WxPayClient::builder()
        .config(test_config())
        .http_client(FixedResponse(signed_response(200, r#"{"data":[]}"#).await))
        .build()
        .await
        .unwrap();
    let handler = client.notify_handler().unwrap();
    let notify = signed_response(200, r#"{"id":"notification-1","create_time":"2026-10-02T00:00:00+08:00","event_type":"TRANSACTION.SUCCESS","resource":{"algorithm":"AEAD_AES_256_GCM","ciphertext":"unused-for-envelope-verification","nonce":"nonce"}}"#).await;
    let headers = NotifyHeaders {
        timestamp: notify.get_header("Wechatpay-Timestamp").unwrap(),
        nonce: notify.get_header("Wechatpay-Nonce").unwrap(),
        serial: notify.get_header("Wechatpay-Serial").unwrap(),
        signature: notify.get_header("Wechatpay-Signature").unwrap(),
    };
    assert!(
        handler
            .verify_and_parse(headers, notify.body.as_bytes())
            .await
            .is_ok()
    );
    let verifier_message = "live-store-check";
    let signature = signer().sign(verifier_message).await.unwrap();
    assert!(
        client
            .verifier()
            .verify_with_serial(verifier_message, &signature, TEST_CERT_SERIAL)
            .await
            .unwrap()
    );
    client
        .cert_manager()
        .remove_certificate(TEST_CERT_SERIAL)
        .await
        .unwrap();
    assert!(client.certificates().get_certificates().await.is_err());
    assert!(
        handler
            .verify_and_parse(headers, notify.body.as_bytes())
            .await
            .is_err()
    );
    assert!(
        client
            .verifier()
            .verify_with_serial(verifier_message, &signature, TEST_CERT_SERIAL)
            .await
            .is_err()
    );
    client
        .cert_manager()
        .add_certificate(TEST_CERT_SERIAL.into(), test_certificate())
        .await
        .unwrap();
    assert!(
        client
            .certificates()
            .get_certificates()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        client
            .verifier()
            .verify_with_serial(verifier_message, &signature, TEST_CERT_SERIAL)
            .await
            .unwrap()
    );
    assert!(
        handler
            .verify_and_parse(headers, notify.body.as_bytes())
            .await
            .is_ok()
    );
}

struct RejectingVerifier;
#[async_trait]
impl Verifier for RejectingVerifier {
    async fn verify(&self, _: &str, _: &str) -> WxPayResult<bool> {
        Ok(false)
    }
    async fn verify_with_serial(&self, _: &str, _: &str, _: &str) -> WxPayResult<bool> {
        Ok(false)
    }
}

#[tokio::test]
async fn client_custom_verifier_rejection_is_not_bypassed() {
    let client = WxPayClient::builder()
        .config(test_config())
        .http_client(FixedResponse(signed_response(200, r#"{"data":[]}"#).await))
        .verifier(RejectingVerifier)
        .build()
        .await
        .unwrap();
    assert!(matches!(
        client.certificates().get_certificates().await,
        Err(WxPayError::SignatureVerificationFailed)
    ));
}

#[tokio::test]
async fn timestamp_original_header_text_is_part_of_the_authenticated_message() {
    let timestamp = format!("0{}", chrono::Utc::now().timestamp());
    assert_eq!(
        request(signed_response_at(200, r#"{"ok":true}"#, &timestamp).await)
            .await
            .unwrap()["ok"],
        true
    );
}

type CapturedRequest = (String, Vec<(String, String)>);

#[derive(Clone)]
struct CapturingHttp {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    body: &'static str,
}

impl CapturingHttp {
    fn new(body: &'static str) -> Self {
        Self {
            requests: Arc::default(),
            body,
        }
    }

    async fn capture(
        &self,
        method: &str,
        headers: Vec<(String, String)>,
    ) -> WxPayResult<HttpResponse> {
        // Emulate migration: only requests advertising a public-key ID receive
        // a response bearing that ID; other requests receive certificate serials.
        let serial = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Wechatpay-Serial"))
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| TEST_CERT_SERIAL.to_string());
        self.requests.lock().unwrap().push((method.into(), headers));
        let mut response =
            signed_response(if self.body.is_empty() { 204 } else { 200 }, self.body).await;
        change_header(&mut response, "Wechatpay-Serial", &serial);
        Ok(response)
    }
}

#[async_trait]
impl HttpClient for CapturingHttp {
    async fn get(&self, _: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        self.capture("GET", headers).await
    }
    async fn post(
        &self,
        _: &str,
        headers: Vec<(String, String)>,
        _: &str,
    ) -> WxPayResult<HttpResponse> {
        self.capture("POST", headers).await
    }
    async fn put(
        &self,
        _: &str,
        headers: Vec<(String, String)>,
        _: &str,
    ) -> WxPayResult<HttpResponse> {
        self.capture("PUT", headers).await
    }
    async fn delete(&self, _: &str, headers: Vec<(String, String)>) -> WxPayResult<HttpResponse> {
        self.capture("DELETE", headers).await
    }
    async fn patch(
        &self,
        _: &str,
        headers: Vec<(String, String)>,
        _: &str,
    ) -> WxPayResult<HttpResponse> {
        self.capture("PATCH", headers).await
    }
}

fn platform_public_key() -> Vec<u8> {
    use der::{Decode, Encode};
    x509_cert::Certificate::from_der(&test_certificate())
        .unwrap()
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap()
}

fn public_key_config(id: &str) -> wxpay_rs::WxPayConfig {
    let mut config = test_config();
    config.platform_certificates.clear();
    config
        .platform_public_keys
        .push((id.to_string(), platform_public_key()));
    config
}

fn assert_serial_header(headers: &[(String, String)], expected: &str) {
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Wechatpay-Serial"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values, vec![expected]);
}

#[tokio::test]
async fn standalone_public_key_only_get_and_post_advertise_response_key() {
    let http = CapturingHttp::new(r#"{"ok":true}"#);
    let transport = ServiceTransport::new(
        Arc::new(public_key_config("PUB_KEY_ID_A")),
        Arc::new(http.clone()),
        signer(),
    );
    for method in [HttpMethod::Get, HttpMethod::Post] {
        assert_eq!(
            transport
                .request::<serde_json::Value>(method, "/v3/test", Some("{}"), "public-key")
                .await
                .unwrap()["ok"],
            true
        );
    }
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0, "GET");
    assert_eq!(requests[1].0, "POST");
    for (_, headers) in requests.iter() {
        assert_serial_header(headers, "PUB_KEY_ID_A");
    }
}

#[tokio::test]
async fn client_negotiates_public_key_after_shared_store_rotation() {
    let http = CapturingHttp::new(r#"{"data":[]}"#);
    let client = WxPayClient::builder()
        .config(public_key_config("PUB_KEY_ID_A"))
        .http_client(http.clone())
        .build()
        .await
        .unwrap();
    client.certificates().get_certificates().await.unwrap();
    client
        .cert_manager()
        .add_public_key("PUB_KEY_ID_B".into(), platform_public_key())
        .await
        .unwrap();
    client.certificates().get_certificates().await.unwrap();
    client
        .cert_manager()
        .remove_public_key("PUB_KEY_ID_B")
        .await;
    client.certificates().get_certificates().await.unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    for ((_, headers), serial) in
        requests
            .iter()
            .zip(["PUB_KEY_ID_A", "PUB_KEY_ID_B", "PUB_KEY_ID_A"])
    {
        assert_serial_header(headers, serial);
    }
}

fn expired_certificate() -> Vec<u8> {
    // This fixture is pinned test material; adjust only validity fields to model
    // a parsed RSA certificate whose entire validity window is in the past.
    let mut certificate = test_certificate();
    for (old, new) in [
        (b"260616041709Z".as_slice(), b"010616041709Z".as_slice()),
        (b"20531101041709Z".as_slice(), b"20031101041709Z".as_slice()),
    ] {
        let offset = certificate
            .windows(old.len())
            .position(|part| part == old)
            .unwrap();
        certificate[offset..offset + old.len()].copy_from_slice(new);
    }
    certificate
}

#[tokio::test]
async fn default_clients_with_missing_removed_or_expired_trust_do_not_send_post() {
    for trust_state in ["missing", "removed", "expired"] {
        let mut config = test_config();
        if trust_state == "missing" {
            config.platform_certificates.clear();
        }
        if trust_state == "expired" {
            config.platform_certificates = vec![expired_certificate()];
        }
        let http = CapturingHttp::new("");
        let client = WxPayClient::builder()
            .config(config)
            .http_client(http.clone())
            .build()
            .await
            .unwrap();
        if trust_state == "removed" {
            client.cert_manager().clear().await;
        }
        assert!(matches!(
            client.query().close("order-1").await,
            Err(WxPayError::CertificateVerificationError(_))
        ));
        assert!(
            http.requests.lock().unwrap().is_empty(),
            "{trust_state} trust must prevent network effects"
        );
    }
}

#[tokio::test]
async fn standalone_missing_trust_does_not_send_post() {
    let mut config = test_config();
    config.platform_certificates.clear();
    let http = CapturingHttp::new("");
    let transport = ServiceTransport::new(Arc::new(config), Arc::new(http.clone()), signer());
    assert!(matches!(
        transport
            .request_default::<()>(HttpMethod::Post, "/v3/test", Some("{}"), "missing-trust")
            .await,
        Err(WxPayError::CertificateVerificationError(_))
    ));
    assert!(http.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn explicit_custom_verifier_can_supply_trust_without_manager_keys() {
    let mut config = test_config();
    config.platform_certificates.clear();
    let http = CapturingHttp::new("");
    let client = WxPayClient::builder()
        .config(config)
        .http_client(http.clone())
        .verifier(Sha256RsaVerifier::new(vec![test_certificate()]).unwrap())
        .build()
        .await
        .unwrap();
    client.query().close("order-1").await.unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "POST");
}
