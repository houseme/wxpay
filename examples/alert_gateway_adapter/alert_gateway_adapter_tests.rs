#[cfg(test)]
use super::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use wxpay_rs::error::{WxPayAlertLevel, WxPayErrorKind};
use serde_json::Value;

fn critical_test_event() -> (TransportEvent, WxPayError) {
    let event = TransportEvent {
        operation: "payment.create_order".into(),
        method: "POST".into(),
        path: "/v3/pay/transactions/jsapi".into(),
        status: 500,
        request_id: "test-request-id".into(),
        elapsed_ms: 123,
        merchant_id: "mch_123".into(),
        app_id: "app_123".into(),
        is_success: false,
        error_code: Some("SERVICE_UNAVAILABLE".into()),
        error_kind: Some(WxPayErrorKind::Internal),
        alert_level: WxPayAlertLevel::Critical,
        alert_policy: "system.internal".into(),
        should_retry: true,
        is_auth_error: false,
    };

    (event, WxPayError::api("SYSTEM_ERROR", "mock-system-error"))
}

fn low_level_event() -> (TransportEvent, WxPayError) {
    let event = TransportEvent {
        operation: "certificate.get".into(),
        method: "GET".into(),
        path: "/v3/certificates".into(),
        status: 400,
        request_id: "low-level-request-id".into(),
        elapsed_ms: 45,
        merchant_id: "mch_123".into(),
        app_id: "app_123".into(),
        is_success: false,
        error_code: Some("PARAM_ERROR".into()),
        error_kind: Some(WxPayErrorKind::InvalidParameter),
        alert_level: WxPayAlertLevel::Low,
        alert_policy: "params.invalid".into(),
        should_retry: false,
        is_auth_error: false,
    };

    (event, WxPayError::api("PARAM_ERROR", "mock-param-error"))
}

#[tokio::test]
async fn alert_gateway_retry_count_should_match_policy() {
    let mock = Arc::new(MockAlertGateway::script_fail_n_times(2, "temporary gateway error"));

    let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_retry_policy(2, 20, 120)
        .with_concurrency_limit(4)
        .with_fallback_to_stdout(false);

    let (event, err) = critical_test_event();
    observer.on_error(&event, &err);

    tokio::time::sleep(Duration::from_millis(220)).await;

    assert_eq!(mock.call_count(), 3, "expect 1 initial + 2 retries");
}

#[tokio::test]
async fn alert_gateway_route_filter_should_skip_unmatched_route() {
    let mock = Arc::new(MockAlertGateway::script_success());

    let observer = AlertGatewayAdapter::new(vec!["critical.security".to_string()])
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_fallback_to_stdout(false);

    let (event, err) = critical_test_event();

    observer.on_error(&event, &err);
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(mock.call_count(), 0, "route not matched should be filtered");
}

#[derive(Debug)]
struct ConcurrencyMockGateway {
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    latency: Duration,
}

impl ConcurrencyMockGateway {
    fn new(latency: Duration) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max_active: Arc::new(AtomicUsize::new(0)),
            latency,
        }
    }

    fn max_concurrency_observed(&self) -> usize {
        self.max_active.load(Ordering::Acquire)
    }

    fn call_count(&self) -> usize {
        self.max_active.load(Ordering::Acquire)
    }
}

impl AlertGateway for ConcurrencyMockGateway {
    fn send<'a>(
        &'a self,
        _endpoint: &'a str,
        _token: Option<&'a str>,
        _payload: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let active = self.active.clone();
        let max_active = self.max_active.clone();
        let latency = self.latency;

        Box::pin(async move {
            let current = active.fetch_add(1, Ordering::Acquire) + 1;
            max_active.fetch_max(current, Ordering::AcqRel);

            tokio::time::sleep(latency).await;

            active.fetch_sub(1, Ordering::Release);
            Ok(())
        })
    }
}

#[tokio::test]
async fn alert_gateway_concurrency_should_respect_limit() {
    let mock = Arc::new(ConcurrencyMockGateway::new(Duration::from_millis(80)));

    let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_retry_policy(0, 20, 20)
        .with_concurrency_limit(4)
        .with_fallback_to_stdout(false);

    let (event, err) = critical_test_event();

    for _ in 0..12 {
        observer.on_error(&event, &err);
    }

    tokio::time::sleep(Duration::from_millis(700)).await;

    assert_eq!(
        mock.max_concurrency_observed(),
        4,
        "concurrency must be bounded by limit 4"
    );
}

#[tokio::test]
async fn alert_gateway_no_endpoint_should_fallback_without_gateway_call() {
    let mock = Arc::new(MockAlertGateway::script_success());
    let logs = Arc::new(Mutex::new(Vec::new()));
    let logs_for_sink = logs.clone();

    let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
        .with_gateway_client(mock.clone())
        .with_fallback_to_stdout(true)
        .with_fallback_sink(move |line: &str| {
            logs_for_sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(line.to_string());
        });

    let (event, err) = critical_test_event();
    observer.on_error(&event, &err);

    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(mock.call_count(), 0, "no endpoint means no gateway call");

    let entries = logs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(entries.len(), 1, "no-endpoint fallback should emit one line");
    assert!(
        entries[0].contains("[alert-fallback(no-endpoint)]"),
        "expect no-endpoint fallback line, got: {}",
        entries[0]
    );
}

#[test]
fn alert_gateway_no_runtime_should_fallback_without_gateway_call() {
    let mock = Arc::new(MockAlertGateway::script_success());
    let logs = Arc::new(Mutex::new(Vec::new()));
    let logs_for_sink = logs.clone();

    let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_fallback_to_stdout(true)
        .with_fallback_sink(move |line: &str| {
            logs_for_sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(line.to_string());
        });

    let (event, err) = critical_test_event();

    thread::spawn(move || {
        observer.on_error(&event, &err);
    })
    .join()
    .expect("thread should finish");

    assert_eq!(
        mock.call_count(),
        0,
        "no tokio runtime context should fallback instead of spawn"
    );
    let entries = logs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(entries.len(), 1, "no-runtime fallback should emit one line");
    assert!(
        entries[0].contains("[alert-dropped(no-runtime)]"),
        "expect no-runtime fallback line, got: {}",
        entries[0]
    );
}

#[tokio::test]
async fn alert_gateway_low_level_should_not_send_alert() {
    let mock = Arc::new(MockAlertGateway::script_success());

    let observer = AlertGatewayAdapter::new(vec!["low.".to_string()])
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_fallback_to_stdout(false);

    let (event, err) = low_level_event();
    observer.on_error(&event, &err);

    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(mock.call_count(), 0, "low-level non-retry event should not alert");
}

#[tokio::test]
async fn alert_gateway_send_error_should_emit_fallback_lines() {
    let mock = Arc::new(MockAlertGateway::script_fail_n_times(1, "gateway rejected"));
    let logs = Arc::new(Mutex::new(Vec::new()));
    let logs_for_sink = logs.clone();

    let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_retry_policy(0, 20, 20)
        .with_fallback_to_stdout(true)
        .with_fallback_sink(move |line: &str| {
            logs_for_sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(line.to_string());
        });

    let (event, err) = critical_test_event();
    observer.on_error(&event, &err);

    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(mock.call_count(), 1, "retry policy 0 should keep one send attempt");

    let entries = logs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        entries.len(),
        2,
        "failed send with fallback true should emit two lines"
    );
    assert!(
        entries[0].contains("alert gateway send failed:"),
        "expect send error line first, got: {}",
        entries[0]
    );
    assert!(
        entries[1].contains("[alert-fallback:critical.system.internal]"),
        "expect fallback payload line, got: {}",
        entries[1]
    );
}

#[derive(Debug)]
struct StressMockGateway {
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    latency: Duration,
}

impl StressMockGateway {
    fn new(latency: Duration) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max_active: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(AtomicUsize::new(0)),
            latency,
        }
    }

    fn max_concurrency_observed(&self) -> usize {
        self.max_active.load(Ordering::Acquire)
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl AlertGateway for StressMockGateway {
    fn send<'a>(
        &'a self,
        _endpoint: &'a str,
        _token: Option<&'a str>,
        _payload: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let active = self.active.clone();
        let max_active = self.max_active.clone();
        let calls = self.calls.clone();
        let latency = self.latency;

        Box::pin(async move {
            calls.fetch_add(1, Ordering::AcqRel);

            let current = active.fetch_add(1, Ordering::Acquire) + 1;
            max_active.fetch_max(current, Ordering::AcqRel);

            tokio::time::sleep(latency).await;

            active.fetch_sub(1, Ordering::Release);
            Ok(())
        })
    }
}

#[tokio::test]
#[ignore]
async fn alert_gateway_stress_high_concurrency_should_stabilize_under_limit() {
    let total_events = 240;
    let concurrency_limit = 12;
    let payload_latency = Duration::from_millis(40);
    let mock = Arc::new(StressMockGateway::new(payload_latency));

    let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
        .with_thresholds(10_000, 10_000, 60)
        .with_gateway("https://alert-gateway.example.internal/v1/events", None)
        .with_gateway_client(mock.clone())
        .with_retry_policy(0, 20, 20)
        .with_concurrency_limit(concurrency_limit)
        .with_fallback_to_stdout(false);

    let (event, err) = critical_test_event();

    let start = Instant::now();
    for _ in 0..total_events {
        observer.on_error(&event, &err);
    }

    let deadline = start + Duration::from_secs(8);
    while Instant::now() < deadline && mock.call_count() < total_events {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    assert_eq!(
        mock.call_count(),
        total_events,
        "all critical events should finish under stress"
    );

    assert!(
        mock.max_concurrency_observed() <= concurrency_limit,
        "send concurrency should stay within limit"
    );
    assert!(
        start.elapsed() <= Duration::from_secs(8),
        "stress window should be bounded, avoid spike-driven stall"
    );
}
