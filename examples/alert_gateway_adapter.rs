use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use wxpay_rs::{TransportEvent, TransportObserver, WxPayClientBuilder, WxPayError};

#[derive(Clone)]
pub struct AlertGatewayAdapter {
    /// 路由规则清单（按前缀匹配）
    /// 例如："critical.security.auth"、"high.business.ratelimit"
    routes: Vec<String>,

    /// 单路由告警窗口内的无采样阈值
    burst_threshold: u64,

    /// 进入采样阶段后的采样步长（例如 10 代表每 10 条采一条）
    sample_every: u64,

    /// 每个路由的窗口长度
    window: Duration,

    /// 告警速率统计（路由 -> 计数与时间窗）
    state: Arc<Mutex<HashMap<String, RouteState>>>,

    /// 自定义告警网关地址，如 https://alert.example.com/events
    gateway_endpoint: Option<String>,

    /// 可选鉴权 token
    gateway_token: Option<String>,

    /// 发送失败是否降级为本地打印
    fallback_to_stdout: bool,

    /// 最大重试次数（不包含首次发送）
    max_retries: u32,

    /// 重试初始退避（毫秒）
    retry_base_backoff_ms: u64,

    /// 重试最大退避（毫秒）
    retry_max_backoff_ms: u64,

    /// 发送并发上限（每实例）
    concurrency_limit: usize,

    /// 并发控制信号量
    semaphore: Arc<Semaphore>,

    /// 可插拔的网关发送器（默认 HttpAlertGateway）
    gateway_client: Arc<dyn AlertGateway>,

    /// 告警 fallback 事件输出通道（None=stdout）
    fallback_sink: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

#[derive(Debug)]
struct RouteState {
    window_start: Instant,
    count: u64,
}

impl AlertGatewayAdapter {
    pub fn new(routes: Vec<String>) -> Self {
        Self {
            routes,
            burst_threshold: 20,
            sample_every: 20,
            window: Duration::from_secs(60),
            state: Arc::new(Mutex::new(HashMap::new())),
            gateway_endpoint: None,
            gateway_token: None,
            fallback_to_stdout: true,
            max_retries: 2,
            retry_base_backoff_ms: 200,
            retry_max_backoff_ms: 2000,
            concurrency_limit: 8,
            semaphore: Arc::new(Semaphore::new(8)),
            gateway_client: Arc::new(HttpAlertGateway),
            fallback_sink: None,
        }
    }

    pub fn with_thresholds(
        mut self,
        burst_threshold: u64,
        sample_every: u64,
        window_secs: u64,
    ) -> Self {
        self.burst_threshold = burst_threshold.max(1);
        self.sample_every = sample_every.max(1);
        self.window = Duration::from_secs(window_secs.max(1));
        self
    }

    pub fn with_gateway(mut self, endpoint: impl Into<String>, token: Option<String>) -> Self {
        self.gateway_endpoint = Some(endpoint.into());
        self.gateway_token = token;
        self
    }

    pub fn with_gateway_client(mut self, gateway: Arc<dyn AlertGateway>) -> Self {
        self.gateway_client = gateway;
        self
    }

    pub fn with_fallback_to_stdout(mut self, enabled: bool) -> Self {
        self.fallback_to_stdout = enabled;
        self
    }

    pub fn with_fallback_sink<F>(mut self, sink: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.fallback_sink = Some(Arc::new(sink));
        self
    }

    pub fn with_retry_policy(
        mut self,
        max_retries: u32,
        base_backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Self {
        self.max_retries = max_retries;
        self.retry_base_backoff_ms = base_backoff_ms.max(50);
        self.retry_max_backoff_ms = max_backoff_ms.max(self.retry_base_backoff_ms);
        self
    }

    pub fn with_concurrency_limit(mut self, concurrency_limit: usize) -> Self {
        let limit = concurrency_limit.max(1);
        self.concurrency_limit = limit;
        self.semaphore = Arc::new(Semaphore::new(limit));
        self
    }

    fn match_route(&self, alert_key: &str) -> bool {
        if self.routes.is_empty() {
            return true;
        }

        self.routes.iter().any(|route| alert_key.starts_with(route))
    }

    fn should_send_alert(&self, route_key: &str) -> bool {
        if !self.match_route(route_key) {
            return false;
        }

        let mut states = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = Instant::now();
        let state = states.entry(route_key.to_string()).or_insert(RouteState {
            window_start: now,
            count: 0,
        });

        if now.duration_since(state.window_start) > self.window {
            state.window_start = now;
            state.count = 0;
        }

        state.count += 1;
        let idx = state.count;

        if idx <= self.burst_threshold {
            return true;
        }

        // 采样阶段：每 sample_every 条告警采一条。
        // 使用稳定哈希做路由级抖动，减少多个节点同一时刻连锁触发。
        let jitter = Self::stable_jitter(route_key, self.sample_every);
        let offset = idx - self.burst_threshold;

        offset.saturating_sub(jitter) % self.sample_every == 0
    }

    fn stable_jitter(seed: &str, modulo: u64) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        hasher.finish() % modulo.max(1)
    }

    fn route_payload(event: &TransportEvent, error: &WxPayError, alert_route: String) -> Value {
        json!({
            "status": "open",
            "severity": event.alert_level.as_str(),
            "source": "wxpay-rs",
            "alert_route": alert_route,
            "service": "wxpay",
            "operation": event.operation,
            "method": event.method,
            "path": event.path,
            "status_code": event.status,
            "request_id": event.request_id,
            "error_code": event.error_code.clone().unwrap_or_default(),
            "error_kind": event.error_kind_label(),
            "alert_policy": event.alert_policy,
            "should_retry": event.should_retry,
            "is_auth_error": event.is_auth_error,
            "elapsed_ms": event.elapsed_ms,
            "merchant_id": event.merchant_id,
            "app_id": event.app_id,
            "error_message": error.to_string(),
            "ts": chrono::Utc::now().to_rfc3339(),
        })
    }
}

impl TransportObserver for AlertGatewayAdapter {
    fn on_success(&self, _event: &TransportEvent) {}

    fn on_error(&self, event: &TransportEvent, error: &WxPayError) {
        if !event.should_alert() {
            return;
        }

        let route_key = event.alert_key();

        if !self.should_send_alert(&route_key) {
            return;
        }

        let payload = Self::route_payload(event, error, route_key.clone());
        let payload_for_print = payload.clone();
        let endpoint = self.gateway_endpoint.clone();
        let token = self.gateway_token.clone();
        let fallback = self.fallback_to_stdout;
        let max_retries = self.max_retries;
        let retry_base_backoff_ms = self.retry_base_backoff_ms;
        let retry_max_backoff_ms = self.retry_max_backoff_ms;
        let semaphore = self.semaphore.clone();
        let route_for_log = route_key.clone();
        let gateway_client = self.gateway_client.clone();
        let fallback_sink = self.fallback_sink.clone();

        match (endpoint, Handle::try_current()) {
            (Some(url), Ok(handle)) => {
                handle.spawn(async move {
                    let _permit = match semaphore.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };

                    if let Err(err) = send_to_alert_gateway(
                        gateway_client.as_ref(),
                        &url,
                        token.as_deref(),
                        payload,
                        max_retries,
                        retry_base_backoff_ms,
                        retry_max_backoff_ms,
                    )
                    .await
                    {
                        if fallback {
                            emit_fallback(
                                &fallback_sink,
                                format!("alert gateway send failed: {}", err),
                            );
                            emit_fallback(
                                &fallback_sink,
                                format!("[alert-fallback:{}] {}", route_for_log, payload_for_print),
                            );
                        }
                    } else if fallback {
                        emit_fallback(
                            &fallback_sink,
                            format!("[alert-success:{}] send ok", route_for_log),
                        );
                    }
                });
            }
            (Some(_), Err(_)) => {
                if fallback {
                    emit_fallback(
                        &fallback_sink,
                        format!(
                            "[alert-dropped(no-runtime)] {}",
                            serde_json::to_string(&payload_for_print)
                                .unwrap_or_else(|_| "<invalid_json>".into())
                        ),
                    );
                }
            }
            (None, _) => {
                if fallback {
                    emit_fallback(
                        &fallback_sink,
                        format!(
                            "[alert-fallback(no-endpoint)] {}",
                            serde_json::to_string(&payload_for_print)
                                .unwrap_or_else(|_| "<invalid_json>".into())
                        ),
                    );
                }
            }
        }
    }
}

fn emit_fallback(sink: &Option<Arc<dyn Fn(&str) + Send + Sync>>, text: impl AsRef<str>) {
    if let Some(sink) = sink {
        (sink)(text.as_ref());
    } else {
        println!("{}", text.as_ref());
    }
}

/// 告警网关发送器抽象，支持替换为 mock/网关SDK/本地队列等实现。
pub trait AlertGateway: Send + Sync + 'static {
    fn send<'a>(
        &'a self,
        endpoint: &'a str,
        token: Option<&'a str>,
        payload: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// 默认 HTTP 网关实现。
#[derive(Debug)]
pub struct HttpAlertGateway;

impl AlertGateway for HttpAlertGateway {
    fn send<'a>(
        &'a self,
        endpoint: &'a str,
        token: Option<&'a str>,
        payload: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let endpoint = endpoint.to_string();
        let token = token.map(|value| value.to_string());
        let payload = payload.clone();

        Box::pin(
            async move { send_to_alert_gateway_once(&endpoint, token.as_deref(), &payload).await },
        )
    }
}

/// 可复用 mock：支持脚本式响应（如 [Err, Err, Ok]）和调用序列记录，便于单测/压测。
#[derive(Debug, Default)]
pub struct MockAlertGateway {
    script: Mutex<VecDeque<Result<(), String>>>,
    calls: Mutex<Vec<String>>,
}

impl MockAlertGateway {
    pub fn new(script: Vec<Result<(), String>>) -> Self {
        Self {
            script: Mutex::new(VecDeque::from(script)),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn script_success() -> Self {
        Self::new(vec![Ok(())])
    }

    pub fn script_fail_n_times(times: usize, err_msg: impl Into<String>) -> Self {
        let err_msg = err_msg.into();
        let mut script = Vec::with_capacity(times + 1);
        script.extend((0..times).map(|_| Err(err_msg.clone())));
        script.push(Ok(()));
        Self::new(script)
    }

    pub fn call_count(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl AlertGateway for MockAlertGateway {
    fn send<'a>(
        &'a self,
        endpoint: &'a str,
        token: Option<&'a str>,
        payload: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let mut script = self
            .script
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let token = token.unwrap_or("<none>");
        let route = payload
            .get("alert_route")
            .and_then(Value::as_str)
            .unwrap_or("unknown");

        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        calls.push(format!("route={route},endpoint={endpoint},token={token}"));

        let result = script.pop_front().unwrap_or_else(|| Ok(()));
        Box::pin(async move { result })
    }
}

async fn send_to_alert_gateway(
    gateway: &dyn AlertGateway,
    endpoint: &str,
    token: Option<&str>,
    payload: Value,
    max_retries: u32,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
) -> Result<(), String> {
    let mut tries = 0u32;
    let mut backoff_ms = base_backoff_ms.max(50);
    let max_backoff_ms = max_backoff_ms.max(backoff_ms);

    loop {
        let result = gateway.send(endpoint, token, &payload).await;
        match result {
            Ok(_) => return Ok(()),
            Err(err) => {
                tries = tries.saturating_add(1);
                if tries > max_retries {
                    return Err(format!(
                        "alert gateway failed after retry {}: {}",
                        max_retries, err
                    ));
                }

                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms.saturating_mul(2)).min(max_backoff_ms);
            }
        }
    }
}

async fn send_to_alert_gateway_once(
    endpoint: &str,
    token: Option<&str>,
    payload: &Value,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    let mut req = client.post(endpoint).json(payload);

    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let response = req.send().await.map_err(|err| err.to_string())?;
    let status = response.status();

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("http {}: {}", status, body));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let routes = vec![
        "critical.security".to_string(),
        "critical.network".to_string(),
        "high.business.ratelimit".to_string(),
        "high.system.internal".to_string(),
        "medium.unknown".to_string(),
    ];

    let _builder = WxPayClientBuilder::new().transport_observer(
        AlertGatewayAdapter::new(routes)
            .with_thresholds(20, 8, 60)
            .with_gateway(
                "https://alert-gateway.example.internal/v1/events",
                Some("replace-with-service-token".to_string()),
            )
            .with_retry_policy(2, 200, 5_000)
            .with_concurrency_limit(16)
            .with_fallback_to_stdout(true),
    );

    // 这里展示接入方式；真实项目里继续沿用你们现有配置组装 client。
    // let client = builder.config(config).build().await?;

    Ok(())
}

#[cfg(test)]
#[path = "alert_gateway_adapter/alert_gateway_adapter_tests.rs"]
mod alert_gateway_adapter_tests;
