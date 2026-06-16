//! HTTP 客户端重试集成测试。
//!
//! 使用 `wiremock` 启动真实 HTTP mock 服务，配合 SDK 内置的 `ReqwestHttpClient`
//! 验证：对 5xx/429 的指数退避重试、网络错误的处理，以及成功路径。
//! 这一层不涉及微信签名，仅测试底层 reqwest 封装的重试逻辑。

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wxpay_rs::http::{HttpClient, ReqwestHttpClient};

/// 构造一个关闭重试的客户端，避免测试时被退避延迟拖慢。
fn client_no_retry() -> ReqwestHttpClient {
    ReqwestHttpClient::builder()
        .timeout(5)
        .max_retries(0)
        .build()
        .expect("HTTP 客户端应构建成功")
}

#[tokio::test]
async fn get_success_returns_body_and_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v3/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .mount(&server)
        .await;

    let client = client_no_retry();
    let resp = client
        .get(&format!("{}/v3/ping", server.uri()), vec![])
        .await
        .expect("GET 应成功");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, r#"{"ok":true}"#);
    assert!(resp.is_success());
}

#[tokio::test]
async fn post_sends_body_and_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v3/echo"))
        .and(header("x-custom", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("created"))
        .mount(&server)
        .await;

    let client = client_no_retry();
    let resp = client
        .post(
            &format!("{}/v3/echo", server.uri()),
            vec![("x-custom".to_string(), "abc".to_string())],
            r#"{"k":"v"}"#,
        )
        .await
        .expect("POST 应成功");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "created");
}

#[tokio::test]
async fn get_retries_on_5xx_then_fails() {
    let server = MockServer::start().await;

    // 持续返回 500：max_retries=2 时应发起 1（初始）+ 2（重试）= 3 次后失败。
    Mock::given(method("GET"))
        .and(path("/v3/flaky"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = ReqwestHttpClient::builder()
        .timeout(5)
        .max_retries(2)
        .build()
        .unwrap();

    let resp = client
        .get(&format!("{}/v3/flaky", server.uri()), vec![])
        .await
        .expect("GET 框架内最终仍返回响应（非网络错误）");

    // 重试耗尽后返回最后一次的 500 响应（重试逻辑在 transport 层不抛错，而是透传最终响应）。
    assert_eq!(resp.status, 500);

    // wiremock 记录的命中次数应为 3（初始 + 2 次重试）。
    let hits = server.received_requests().await.unwrap().len();
    assert_eq!(hits, 3, "应发起初始 + 2 次重试 = 3 次请求");
}

#[tokio::test]
async fn get_retries_then_succeeds() {
    let server = MockServer::start().await;

    // 计数器：前两次返回 503，第三次返回 200。
    let counter = Arc::new(AtomicU32::new(0));
    let counter_for_handler = counter.clone();

    Mock::given(method("GET"))
        .and(path("/v3/recover"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter_for_handler.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_string(r#"{"recovered":true}"#)
            }
        })
        .mount(&server)
        .await;

    let client = ReqwestHttpClient::builder()
        .timeout(5)
        .max_retries(5)
        .build()
        .unwrap();

    let resp = client
        .get(&format!("{}/v3/recover", server.uri()), vec![])
        .await
        .expect("重试后应成功");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, r#"{"recovered":true}"#);
    // 第 3 次成功：共 3 次请求。
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn get_does_not_retry_on_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v3/bad"))
        .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"code":"PARAM_ERROR"}"#))
        .mount(&server)
        .await;

    let client = ReqwestHttpClient::builder()
        .timeout(5)
        .max_retries(3)
        .build()
        .unwrap();

    let resp = client
        .get(&format!("{}/v3/bad", server.uri()), vec![])
        .await
        .unwrap();

    assert_eq!(resp.status, 400);
    // 4xx（非 429）不应触发重试：仅 1 次请求。
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
