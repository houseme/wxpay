//! Fail-closed webhook example. Before deployment, implement the two
//! `accept_*` functions with a durable inbox or an idempotent database transaction.
//! Until then valid callbacks deliberately receive HTTP 503, never a false ACK.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use dotenvy::dotenv;
use serde_json::json;
use wxpay_rs::{
    WxPayClient, WxPayConfig, WxPayError, WxPayResult,
    notify::{
        NotifyHandler, NotifyHeaders,
        handler::{PaymentNotifyData, RefundNotifyData},
    },
};

#[derive(Clone)]
struct AppState {
    handler: Arc<NotifyHandler>,
    appid: String,
    mchid: String,
}

async fn build_client() -> WxPayResult<WxPayClient> {
    let _ = dotenv();
    let mut config = WxPayConfig::builder()
        .app_id(required_env("WXPAY_APP_ID")?)
        .merchant_id(required_env("WXPAY_MERCHANT_ID")?)
        .api_v3_key(required_env("WXPAY_API_V3_KEY")?)
        .private_key_from_file(required_env("WXPAY_PRIVATE_KEY_PATH")?)
        .cert_serial_number(required_env("WXPAY_CERT_SERIAL_NUMBER")?);

    // Obtain platform keys/certificates through a trusted provisioning channel.
    // Never trust a key supplied in the callback itself.
    if let Ok(key_path) = std::env::var("WXPAY_PLATFORM_PUBLIC_KEY_PATH") {
        config = config.platform_public_key(
            required_env("WXPAY_PLATFORM_PUBLIC_KEY_ID")?,
            read_verifier_material(&key_path)?,
        );
    } else {
        config = config.platform_certificate(read_verifier_material(&required_env(
            "WXPAY_PLATFORM_CERTIFICATE_PATH",
        )?)?);
    }
    WxPayClient::new(config.build()?).await
}

fn read_verifier_material(path: &str) -> WxPayResult<Vec<u8>> {
    std::fs::read(path).map_err(|_| WxPayError::ConfigError {
        message: "unable to read configured platform key/certificate".to_string(),
    })
}

fn required_env(name: &str) -> WxPayResult<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            WxPayError::missing_config(format!("{name} environment variable is required"))
        })
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> WxPayResult<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| WxPayError::InvalidNotifyFormat(format!("missing {name}")))?;
    if values.next().is_some() {
        return Err(WxPayError::InvalidNotifyFormat(format!("duplicate {name}")));
    }
    value
        .to_str()
        .map_err(|_| WxPayError::InvalidNotifyFormat(format!("invalid {name}")))
}

fn signature_headers(headers: &HeaderMap) -> WxPayResult<NotifyHeaders<'_>> {
    Ok(NotifyHeaders {
        timestamp: required_header(headers, "wechatpay-timestamp")?,
        nonce: required_header(headers, "wechatpay-nonce")?,
        signature: required_header(headers, "wechatpay-signature")?,
        serial: required_header(headers, "wechatpay-serial")?,
    })
}

async fn payment_notify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    notification_response(handle_payment_notify_inner(&state, &headers, &body).await)
}

async fn refund_notify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    notification_response(handle_refund_notify_inner(&state, &headers, &body).await)
}

fn notification_response(result: WxPayResult<()>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            let status = match &err {
                WxPayError::InvalidNotifyFormat(_)
                | WxPayError::InvalidNotifyType(_)
                | WxPayError::NotifySignatureVerificationFailed
                | WxPayError::SignatureVerificationFailed
                | WxPayError::InvalidSignatureFormat(_)
                | WxPayError::DecryptionError(_)
                | WxPayError::InvalidCiphertext(_)
                | WxPayError::JsonError(_) => StatusCode::BAD_REQUEST,
                // Unknown/expired certificates may require local key refresh;
                // all acceptance/storage failures remain retriable.
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            // Never echo plaintext, keys, or detailed verifier errors to callers.
            tracing::warn!(status = status.as_u16(), "wxpay callback not accepted");
            (status, Json(json!({ "code": "FAIL", "message": "失败" }))).into_response()
        }
    }
}

async fn handle_payment_notify_inner(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> WxPayResult<()> {
    let request = state
        .handler
        .verify_and_parse(signature_headers(headers)?, body)
        .await?;
    let data = state
        .handler
        .handle_verified_payment_notify(&request)
        .await?;
    if data.appid != state.appid || data.mchid != state.mchid {
        return Err(WxPayError::InvalidNotifyFormat(
            "unexpected appid or mchid".to_string(),
        ));
    }
    accept_payment(request.request().id.as_str(), &data).await
}

async fn handle_refund_notify_inner(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> WxPayResult<()> {
    let request = state
        .handler
        .verify_and_parse(signature_headers(headers)?, body)
        .await?;
    let data = state
        .handler
        .handle_verified_refund_notify(&request)
        .await?;
    if data.mchid != state.mchid {
        return Err(WxPayError::InvalidNotifyFormat(
            "unexpected mchid".to_string(),
        ));
    }
    accept_refund(request.request().id.as_str(), &data).await
}

async fn accept_payment(_notification_id: &str, _payment: &PaymentNotifyData) -> WxPayResult<()> {
    // Implement: lookup the order, call payment.validate_order(PaymentExpectation
    // populated from your database), then atomically deduplicate notification /
    // transaction IDs and commit the state change or a durable work item.
    // A matching previously committed notification returns Ok(()).
    Err(WxPayError::BusinessError(
        "payment persistence must be implemented".to_string(),
    ))
}

async fn accept_refund(_notification_id: &str, _refund: &RefundNotifyData) -> WxPayResult<()> {
    // Implement: lookup original order + refund, call refund.validate_order(...),
    // and atomically deduplicate and persist SUCCESS / ABNORMAL / CLOSED handling.
    // Return Ok(()) only once acceptance is durable, including known duplicates.
    Err(WxPayError::BusinessError(
        "refund persistence must be implemented".to_string(),
    ))
}

fn build_router(client: WxPayClient) -> WxPayResult<Router> {
    let state = AppState {
        handler: Arc::new(client.notify_handler()?),
        appid: client.config().app_id.clone(),
        mchid: client.config().merchant_id.clone(),
    };
    Ok(Router::new()
        .route("/wxpay/payment-notify", post(payment_notify_handler))
        .route("/wxpay/refund-notify", post(refund_notify_handler))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(build_client().await?)?;
    let bind = std::env::var("WXPAY_WEBHOOK_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("axum webhook listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    use async_trait::async_trait;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use wxpay_rs::{auth::Verifier, config::NotifyConfig};

    struct ExactVerifier(String);

    #[async_trait]
    impl Verifier for ExactVerifier {
        async fn verify(&self, _message: &str, _signature: &str) -> WxPayResult<bool> {
            panic!("webhooks must select a verifier by serial")
        }

        async fn verify_with_serial(
            &self,
            message: &str,
            signature: &str,
            serial: &str,
        ) -> WxPayResult<bool> {
            Ok(message == self.0 && signature == "signature" && serial == "serial")
        }
    }

    fn payment_fixture(appid: &str, mchid: &str) -> (AppState, HeaderMap, Bytes) {
        let key = "abcdefghijklmnopqrstuvwxyz123456";
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let resource = json!({
            "appid":appid, "mchid":mchid, "out_trade_no":"order-1", "transaction_id":"tx-1",
            "trade_type":"JSAPI", "trade_state":"SUCCESS", "trade_state_desc":"成功",
            "bank_type":"OTHERS", "success_time":"2026-10-02T10:00:00+08:00",
            "amount":{"total":100,"currency":"CNY"}
        });
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(*b"nonce1234567"),
                Payload {
                    msg: resource.to_string().as_bytes(),
                    aad: b"",
                },
            )
            .unwrap();
        let body = serde_json::to_string_pretty(&json!({
            "id":"EV-TEST", "create_time":"2026-10-02T10:00:00+08:00", "event_type":"TRANSACTION.SUCCESS",
            "unknown":"signed field", "resource":{"algorithm":"AEAD_AES_256_GCM",
                "ciphertext":STANDARD.encode(ciphertext), "nonce":"nonce1234567"}
        })).unwrap();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let message = format!("{timestamp}\nnonce\n{body}\n");
        let handler = NotifyHandler::new(
            NotifyConfig {
                api_v3_key: key.to_string(),
                cert_serial_number: "serial".to_string(),
                platform_certificate: vec![],
            },
            Arc::new(ExactVerifier(message)),
        )
        .unwrap();
        let state = AppState {
            handler: Arc::new(handler),
            appid: "configured-app".to_string(),
            mchid: "configured-merchant".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("wechatpay-timestamp", timestamp.parse().unwrap());
        headers.insert("wechatpay-nonce", "nonce".parse().unwrap());
        headers.insert("wechatpay-signature", "signature".parse().unwrap());
        headers.insert("wechatpay-serial", "serial".parse().unwrap());
        (state, headers, Bytes::from(body))
    }

    #[tokio::test]
    async fn raw_bytes_reach_serial_verifier_and_acceptance_failures_are_retriable() {
        let (state, headers, body) = payment_fixture("configured-app", "configured-merchant");
        let response =
            payment_notify_handler(State(state.clone()), headers.clone(), body.clone()).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let normalized = serde_json::from_slice::<serde_json::Value>(&body)
            .unwrap()
            .to_string();
        let response = payment_notify_handler(State(state), headers, Bytes::from(normalized)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callbacks_for_other_merchants_or_apps_are_rejected() {
        for (appid, mchid) in [
            ("other-app", "configured-merchant"),
            ("configured-app", "other-merchant"),
        ] {
            let (state, headers, body) = payment_fixture(appid, mchid);
            let response = payment_notify_handler(State(state), headers, body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn missing_and_duplicate_headers_are_rejected() {
        let names = [
            "wechatpay-timestamp",
            "wechatpay-nonce",
            "wechatpay-signature",
            "wechatpay-serial",
        ];
        for omitted in names {
            let mut headers = HeaderMap::new();
            for name in names {
                if name != omitted {
                    headers.insert(name, "value".parse().unwrap());
                }
            }
            assert!(
                signature_headers(&headers).is_err(),
                "accepted missing {omitted}"
            );
        }
        let mut headers = HeaderMap::new();
        for name in names {
            headers.insert(name, "value".parse().unwrap());
        }
        assert!(signature_headers(&headers).is_ok());
        for name in names {
            let mut duplicated = headers.clone();
            duplicated.append(name, "other".parse().unwrap());
            assert!(signature_headers(&duplicated).is_err());
        }
    }

    #[test]
    fn unsuccessful_callbacks_never_acknowledge_success() {
        assert_eq!(
            notification_response(Ok(())).status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            notification_response(Err(WxPayError::NotifySignatureVerificationFailed)).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            notification_response(Err(WxPayError::BusinessError("storage failed".to_string())))
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
