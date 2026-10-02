//! Independent wire fixtures: raw APIv3 key encryption and direct RSA signing,
//! without using the SDK's AES encryption or request-signing helpers.
#[allow(dead_code)]
mod common;

use std::sync::Arc;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use aws_lc_rs::{
    rand::SystemRandom,
    rsa::KeyPair,
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use wxpay_rs::{
    WxPayError,
    auth::Sha256RsaVerifier,
    config::NotifyConfig,
    notify::{NotifyHandler, NotifyHeaders, NotifyParser, PaymentExpectation, RefundExpectation},
};

const KEY: &str = "abcdefghijklmnopqrstuvwxyz123456";
const SERIAL: &str = "PUB_KEY_ID_3000000001";
const NONCE: &str = "signed-header-nonce";

fn signing_key() -> KeyPair {
    let (label, document) = der::SecretDocument::from_pem(common::TEST_PRIVATE_KEY_PEM).unwrap();
    assert_eq!(label, "PRIVATE KEY");
    KeyPair::from_pkcs8(document.as_bytes()).unwrap()
}

fn handler() -> NotifyHandler {
    let private = signing_key();
    let public = private.public_key().as_ref();
    let verifier = Sha256RsaVerifier::new_with_public_keys(
        vec![],
        vec![(SERIAL.to_string(), public.to_vec())],
    )
    .unwrap();
    NotifyHandler::new(
        NotifyConfig {
            api_v3_key: KEY.to_string(),
            cert_serial_number: SERIAL.to_string(),
            platform_certificate: vec![],
        },
        Arc::new(verifier),
    )
    .unwrap()
}

fn payment() -> Value {
    json!({
        "appid":"wx88888888", "mchid":"1900000109", "out_trade_no":"order-1",
        "transaction_id":"4200000001", "trade_type":"JSAPI", "trade_state":"SUCCESS",
        "trade_state_desc":"支付成功", "bank_type":"OTHERS", "success_time":"2026-10-02T10:00:00+08:00",
        "payer":{"openid":"test-openid"},
        "amount":{"total":100,"payer_total":80,"currency":"CNY","payer_currency":"CNY"}
    })
}

fn refund(status: &str) -> Value {
    json!({
        "mchid":"1900000109", "out_trade_no":"order-1", "transaction_id":"4200000001",
        "out_refund_no":"refund-1", "refund_id":"5000000001", "refund_status":status,
        "amount":{"total":100,"refund":50,"payer_total":80,"payer_refund":40}
    })
}

fn body(event: &str, resource: &Value) -> String {
    let cipher = Aes256Gcm::new_from_slice(KEY.as_bytes()).unwrap();
    let nonce = Nonce::from(*b"nonce1234567");
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: resource.to_string().as_bytes(),
                aad: b"resource",
            },
        )
        .unwrap();
    // Pretty printing and unknown fields exercise byte-exact verification.
    serde_json::to_string_pretty(&json!({
        "id":"EV-TEST", "create_time":"2026-10-02T10:00:00+08:00", "event_type":event,
        "resource_type":"encrypt-resource", "summary":"回调通知", "future_field":{"keep":"signed"},
        "resource": {"algorithm":"AEAD_AES_256_GCM", "ciphertext":STANDARD.encode(encrypted),
            "nonce":"nonce1234567", "associated_data":"resource", "original_type":"transaction"}
    }))
    .unwrap()
}

fn signature(timestamp: &str, body: &str) -> String {
    let private = signing_key();
    let message = format!("{timestamp}\n{NONCE}\n{body}\n");
    let mut signature = vec![0; private.public_modulus_len()];
    private
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .unwrap();
    STANDARD.encode(signature)
}

fn headers<'a>(timestamp: &'a str, signature: &'a str) -> NotifyHeaders<'a> {
    NotifyHeaders {
        timestamp,
        nonce: NONCE,
        serial: SERIAL,
        signature,
    }
}

fn expected_payment() -> PaymentExpectation<'static> {
    PaymentExpectation {
        appid: "wx88888888",
        mchid: "1900000109",
        out_trade_no: "order-1",
        total: 100,
        currency: "CNY",
    }
}

fn expected_refund() -> RefundExpectation<'static> {
    RefundExpectation {
        mchid: "1900000109",
        out_trade_no: "order-1",
        out_refund_no: "refund-1",
        total: 100,
        refund: 50,
    }
}

#[tokio::test]
async fn authentic_raw_body_with_unknown_fields_decrypts_and_matches_order() {
    let handler = handler();
    let body = body("TRANSACTION.SUCCESS", &payment());
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = signature(&timestamp, &body);
    let verified = handler
        .verify_and_parse(headers(&timestamp, &signature), body.as_bytes())
        .await
        .unwrap();
    assert_eq!(verified.request().id, "EV-TEST");
    let data = handler
        .handle_verified_payment_notify(&verified)
        .await
        .unwrap();
    data.validate_order(expected_payment()).unwrap();
    // Merchant amount is 100 although user actually paid 80 after discounts.
    assert_eq!(data.amount.as_ref().unwrap().payer_total, Some(80));
    assert!(
        data.validate_order(PaymentExpectation {
            total: 80,
            ..expected_payment()
        })
        .is_err()
    );
    assert!(
        data.validate_order(PaymentExpectation {
            appid: "other",
            ..expected_payment()
        })
        .is_err()
    );
    assert!(
        data.validate_order(PaymentExpectation {
            mchid: "other",
            ..expected_payment()
        })
        .is_err()
    );
    assert!(
        data.validate_order(PaymentExpectation {
            out_trade_no: "other",
            ..expected_payment()
        })
        .is_err()
    );
    assert!(
        data.validate_order(PaymentExpectation {
            currency: "USD",
            ..expected_payment()
        })
        .is_err()
    );
}

#[tokio::test]
async fn reserialized_or_tampered_raw_body_is_rejected_before_decryption() {
    let handler = handler();
    let body = body("TRANSACTION.SUCCESS", &payment());
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = signature(&timestamp, &body);
    let compact = serde_json::to_string(&serde_json::from_str::<Value>(&body).unwrap()).unwrap();
    for altered in [
        compact,
        body.replace("EV-TEST", "EV-OTHER"),
        format!("{body}\n"),
    ] {
        assert!(matches!(
            handler
                .verify_and_parse(headers(&timestamp, &signature), altered.as_bytes())
                .await,
            Err(WxPayError::NotifySignatureVerificationFailed)
        ));
    }
}

#[tokio::test]
async fn missing_malformed_unknown_or_forged_signature_headers_fail_closed() {
    let handler = handler();
    let body = body("TRANSACTION.SUCCESS", &payment());
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let sig = signature(&timestamp, &body);
    let good = headers(&timestamp, &sig);
    for invalid in [
        NotifyHeaders {
            timestamp: "",
            ..good
        },
        NotifyHeaders { nonce: "", ..good },
        NotifyHeaders { serial: "", ..good },
        NotifyHeaders {
            signature: "",
            ..good
        },
        NotifyHeaders {
            timestamp: "nonnumeric",
            ..good
        },
        NotifyHeaders {
            timestamp: "-9223372036854775808",
            ..good
        },
        NotifyHeaders {
            timestamp: "9223372036854775807",
            ..good
        },
        NotifyHeaders {
            timestamp: "18446744073709551615",
            ..good
        },
        NotifyHeaders {
            nonce: "injected\nline",
            ..good
        },
        NotifyHeaders {
            serial: "PUB_KEY_ID_UNKNOWN",
            ..good
        },
        NotifyHeaders {
            signature: "WECHATPAY/SIGNTEST/fake",
            ..good
        },
        NotifyHeaders {
            signature: "not-base64!",
            ..good
        },
        NotifyHeaders {
            signature: "AAAA",
            ..good
        },
    ] {
        assert!(
            handler
                .verify_and_parse(invalid, body.as_bytes())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn stale_and_future_correctly_signed_callbacks_are_rejected() {
    let handler = handler();
    let body = body("TRANSACTION.SUCCESS", &payment());
    for offset in [-3600, 3600] {
        let timestamp = (chrono::Utc::now().timestamp() + offset).to_string();
        let signature = signature(&timestamp, &body);
        assert!(matches!(
            handler
                .verify_and_parse(headers(&timestamp, &signature), body.as_bytes())
                .await,
            Err(WxPayError::NotifySignatureVerificationFailed)
        ));
    }
}

#[tokio::test]
async fn all_refund_events_are_supported_and_must_match_resource_state() {
    let handler = handler();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    for event_status in ["SUCCESS", "ABNORMAL", "CLOSED"] {
        for resource_status in ["SUCCESS", "ABNORMAL", "CLOSED"] {
            let body = body(&format!("REFUND.{event_status}"), &refund(resource_status));
            let signature = signature(&timestamp, &body);
            let verified = handler
                .verify_and_parse(headers(&timestamp, &signature), body.as_bytes())
                .await
                .unwrap();
            let result = handler.handle_verified_refund_notify(&verified).await;
            if event_status == resource_status {
                let data = result.unwrap();
                assert!(data.success_time.is_none());
                data.validate_order(expected_refund()).unwrap();
                assert!(
                    data.validate_order(RefundExpectation {
                        mchid: "other",
                        ..expected_refund()
                    })
                    .is_err()
                );
                assert!(
                    data.validate_order(RefundExpectation {
                        out_refund_no: "other",
                        ..expected_refund()
                    })
                    .is_err()
                );
                assert!(
                    data.validate_order(RefundExpectation {
                        refund: 100,
                        ..expected_refund()
                    })
                    .is_err()
                );
            } else {
                assert!(matches!(result, Err(WxPayError::InvalidNotifyFormat(_))));
            }
        }
    }
}

#[tokio::test]
async fn signed_but_invalid_payment_state_or_missing_amount_is_rejected() {
    let handler = handler();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let mut wrong_state = payment();
    wrong_state["trade_state"] = json!("NOTPAY");
    let mut missing_amount = payment();
    missing_amount.as_object_mut().unwrap().remove("amount");
    for resource in [wrong_state, missing_amount] {
        let body = body("TRANSACTION.SUCCESS", &resource);
        let signature = signature(&timestamp, &body);
        let verified = handler
            .verify_and_parse(headers(&timestamp, &signature), body.as_bytes())
            .await
            .unwrap();
        assert!(
            handler
                .handle_verified_payment_notify(&verified)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn signature_success_does_not_bypass_aes_authentication() {
    let handler = handler();
    let mut wire: Value = serde_json::from_str(&body("TRANSACTION.SUCCESS", &payment())).unwrap();
    let ciphertext = wire["resource"]["ciphertext"].as_str().unwrap();
    let mut encrypted = STANDARD.decode(ciphertext).unwrap();
    encrypted[0] ^= 1;
    wire["resource"]["ciphertext"] = json!(STANDARD.encode(encrypted));
    let body = wire.to_string();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = signature(&timestamp, &body);
    let verified = handler
        .verify_and_parse(headers(&timestamp, &signature), body.as_bytes())
        .await
        .unwrap();
    assert!(
        handler
            .handle_verified_payment_notify(&verified)
            .await
            .is_err()
    );
}

#[test]
fn official_event_field_serializes_canonically_and_legacy_alias_still_reads() {
    let body = body("TRANSACTION.SUCCESS", &payment());
    let parsed = NotifyParser::parse(&body).unwrap();
    assert_eq!(
        NotifyParser::get_notify_type(&body).unwrap(),
        "TRANSACTION.SUCCESS"
    );
    let encoded = serde_json::to_value(parsed).unwrap();
    assert_eq!(encoded["event_type"], "TRANSACTION.SUCCESS");
    assert!(encoded.get("type").is_none());
    let legacy = body.replace("\"event_type\"", "\"type\"");
    assert_eq!(
        NotifyParser::parse(&legacy).unwrap().notify_type,
        "TRANSACTION.SUCCESS"
    );
    assert_eq!(
        NotifyParser::get_notify_type(&legacy).unwrap(),
        "TRANSACTION.SUCCESS"
    );
}
