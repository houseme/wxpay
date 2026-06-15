# 微信支付 Rust SDK 文档（实现快照）

本文件面向当前 `houseme/wxpay` Rust SDK 实现快照。历史 PHP SDK 文档内容已从这里移除，避免与当前 API 命名冲突。

## 特性入口

- `WxPayClient` 提供统一入口：`client.jsapi()` / `client.native()` / `client.h5()` / `client.app()`
- 查询：`client.query()`
- 退款：`client.refund()`
- 转账：`client.transfer()`
- 分账：`client.profit_sharing()`
- 证书：`client.certificates()`

## 创建客户端（示例）

```rust
use wxpay_rs::{WxPayClient, WxPayConfig};

let config = WxPayConfig::builder()
    .app_id("wx888888888")
    .merchant_id("22222222")
    .api_v3_key("abcdefghijklmnopqrstuvwxyz123456")
    .private_key(vec![1, 2, 3, 4])
    .cert_serial_number("CERT123456")
    .base_url("https://api.mch.weixin.qq.com")
    .build()?;

let client = WxPayClient::new(config).await?;
```

## 主要 API 速查（文档风格）

### 支付服务

| API | 说明 | 状态 |
|-----|------|------|
| `jsapi().prepay(request)` | JSAPI 预支付 | ✅ |
| `native().prepay(request)` | Native 预支付 | ✅ |
| `h5().prepay(request)` | H5 预支付 | ✅ |
| `app().prepay(request)` | APP 预支付 | ✅ |

### 订单查询

| API | 说明 | 状态 |
|-----|------|------|
| `query().by_transaction_id(transaction_id)` | 微信支付单号查询 | ✅ |
| `query().by_out_trade_no(out_trade_no)` | 商户订单号查询 | ✅ |
| `query().by_filter(&QueryFilter { .. })` | 复杂条件查询 | ✅ |
| `query().close(out_trade_no)` | 关闭订单 | ✅ |

### 退款服务

| API | 说明 | 状态 |
|-----|------|------|
| `refund().create(request)` | 申请退款 | ✅ |
| `refund().query(&QueryRefundRequest)` | 查询退款 | ✅ |

### 转账服务

| API | 说明 | 状态 |
|-----|------|------|
| `transfer().create(request)` | 发起转账 | ✅ |
| `transfer().query(&QueryTransferBatchRequest)` | 查询转账 | ✅ |

### 分账服务

| API | 说明 | 状态 |
|-----|------|------|
| `profit_sharing().create(request)` | 创建分账 | ✅ |
| `profit_sharing().query(&QueryProfitSharingRequest)` | 查询分账 | ✅ |
| `profit_sharing().add_receiver(&AddProfitSharingReceiverRequest)` | 添加分账接收方 | ✅ |
| `profit_sharing().delete_receiver(&DeleteProfitSharingReceiverRequest)` | 删除分账接收方 | ✅ |
| `profit_sharing().finish(&ProfitSharingFinishRequest)` | 完成分账 | ✅ |

### 证书服务

| API | 说明 | 状态 |
|-----|------|------|
| `certificates().get_certificates()` | 获取平台证书 | ✅ |

### 可观测与告警（结构化日志策略）

SDK 在请求失败时会输出以下结构化字段，便于直接接入日志告警链路：

- `operation`：服务级操作名（如 `payments.jsapi.create_order`）
- `method`：HTTP 方法
- `path`：请求路径
- `status`：HTTP 状态码
- `request_id`：微信返回的 `Request-ID`
- `error_code`：微信 API 错误码（如 `SIGN_ERROR`）
- `error_kind`：统一分类（`Authentication`/`Signature`/`RateLimited` ...）
- `alert_level`：告警级别（`low`/`medium`/`high`/`critical`）
- `alert_policy`：告警策略路由（`security.auth`/`security.signature`/`business.ratelimit`/`certificate`...）
- `should_retry`：是否建议重试
- `is_auth_error`：是否鉴权/签名相关问题
- `elapsed_ms`：请求耗时

建议告警路由（初版）：

- `critical` + `security.auth/security.signature`：立即告警
- `critical` + `network`：网络告警（可配置抖动缓冲）
- `high` + `system.internal/business.blocked/business.http`：高优先关注
- `high` + `business.ratelimit`：检查请求频率并触发限流策略

### 与现有 metrics/告警系统的完整接入示例

`WxPayClientBuilder` 支持 `transport_observer` 回调，建议在这里打通链路：

- `on_success`：上报成功请求计数 / 耗时（Prometheus/OpenTelemetry）
- `on_error`：直接使用 `error_kind` + `alert_policy` + `alert_key` 打通告警规则

```rust
use std::sync::Arc;
use wxpay_rs::{TransportEvent, TransportObserver, WxPayClientBuilder, WxPayError};

struct MetricsAndAlertObserver;

impl TransportObserver for MetricsAndAlertObserver {
    fn on_success(&self, event: &TransportEvent) {
        // 示例：Prometheus/Otel 指标上报
        // metrics::histogram!(
        //   "wxpay_request_duration_ms", 
        //   "operation" => event.operation.clone(),
        //   "method" => event.method.clone(),
        //   "status" => "success"
        // ).record(event.elapsed_ms as f64);
        // metrics::increment_counter!(
        //   "wxpay_request_total",
        //   "operation" => event.operation.clone(),
        //   "method" => event.method.clone(),
        //   "app_id" => event.app_id.clone()
        // );
    }

    fn on_error(&self, event: &TransportEvent, error: &WxPayError) {
        let alert_policy = match event.error_kind_label().as_ref() {
            "Authentication" => "security.auth",
            "Signature" => "security.signature",
            "RateLimited" => "business.ratelimit",
            "RequestTimeout" => "network.timeout",
            "ConnectionError" => "network.connectivity",
            "InvalidParameter" => "params.invalid",
            "Internal" => "system.internal",
            _ => &event.alert_policy,
        };

        // 统一告警路由：<告警级别>.<告警策略>
        // 例如：critical.security.auth / high.business.ratelimit / medium.unknown
        let alert_route = format!("{}.{}", event.alert_level.as_str(), alert_policy);

        // 指标标签：error_kind 直接参与路由与聚合
        // metrics::increment_counter!(
        //   "wxpay_request_errors_total",
        //   "operation" => event.operation.clone(),
        //   "error_kind" => event.error_kind_label().to_string(),
        //   "alert_level" => event.alert_level.as_str().to_string(),
        //   "alert_policy" => alert_policy.to_string(),
        //   "alert_route" => alert_route,
        // );

        // 结构化告警策略：error_kind + alert_policy + 级联条件
        if event.should_alert() {
            let severity = event.alert_level.as_str();
            let payload = serde_json::json!({
                "status": "open",
                "severity": severity,
                "service": "wxpay",
                "operation": event.operation,
                "path": event.path,
                "status_code": event.status,
                "request_id": event.request_id,
                "error_kind": event.error_kind_label(),
                "alert_policy": alert_policy,
                "alert_route": alert_route,
                "should_retry": event.should_retry,
                "is_auth_error": event.is_auth_error,
                "should_alert": event.should_alert(),
                "error_message": error.to_string(),
            });

            // send_to_alert_gateway(payload);
            // otel::opentelemetry::global::tracer("wxpay").in_span("wxpay_alert", |cx| { ... });
        }
    }
}

let client = WxPayClientBuilder::new()
    .config(config)
    .transport_observer(MetricsAndAlertObserver)
    .build()
    .await?;
```

`TransportEvent` 字段已带通道友好标签：

- `operation / method / path`
- `status / request_id / elapsed_ms`
- `app_id / merchant_id`
- `error_code / error_kind`
- `alert_level / alert_policy / alert_key / should_retry / should_alert / is_auth_error`

### 可复用告警网关 Adapter 示例

仓库已提供一个可直接迁移的示例实现：`examples/alert_gateway_adapter.rs`（已集成 HTTP 告警网关上报 + 抖动采样）。  
该示例覆盖：

- `Vec<String>` 路由白名单（按前缀匹配）
- 1 分钟窗口内突发阈值（`burst_threshold`）与限流后采样（`sample_every`）
- `request_id` 参与的抖动偏移，避免同路由告警同时刷屏
- `send_to_alert_gateway_once` 的同步失败自动重试（指数退避）
- `concurrency_limit` 并发上限控制（避免网关瞬时压垮）
- 直接上报到自定义网关函数（示例里为可替换的 HTTP 请求层）
- `AlertGateway` trait 可插拔能力（默认 HTTP 实现 + Mock 适配器）

你可以直接在当前仓库运行该示例并接入你的网关 client（按需替换 endpoint 与鉴权）：

```bash
cargo run --example alert_gateway_adapter
```

示例中的 `with_gateway` 会绑定网关路由规则与 `Authorization: Bearer {token}`，例如：

```rust
let observer = AlertGatewayAdapter::new(routes)
    .with_gateway("https://alert-gateway.example.internal/v1/events", Some("service-token".into()))
    .with_retry_policy(2, 200, 5_000)    // 失败重试 2 次，200ms -> 5s 退避
    .with_concurrency_limit(16);          // 同时发送上限

// fallback 输出可注入，用于单测断言 stdout 打印内容
let fallback_logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
let logs = fallback_logs.clone();
let observer = AlertGatewayAdapter::new(routes)
    .with_gateway("https://alert-gateway.example.internal/v1/events", Some("service-token".into()))
    .with_fallback_to_stdout(true)
    .with_fallback_sink(move |line: &str| {
        logs.lock().unwrap().push(line.to_string());
    });
```

更进一步，如果你要做单测/回归压测，可直接注入自定义网关（例如 mock）：

```rust
use std::sync::Arc;
use wxpay_rs::alert_gateway_adapter::{AlertGatewayAdapter, MockAlertGateway};

let mock = Arc::new(MockAlertGateway::script_fail_n_times(2, "temporary gateway 503"));

let observer = AlertGatewayAdapter::new(vec!["critical.".to_string()])
    .with_gateway("http://127.0.0.1:9999/v1/events", Some("test-token".into()))
    .with_gateway_client(mock.clone())
    .with_retry_policy(3, 50, 200)
    .with_concurrency_limit(4)
    .with_fallback_to_stdout(false);

// 在单测中可断言：mock.call_count() == 3（首次 + 2 次重试）
```

在 `examples/alert_gateway_adapter.rs` 中可直接运行以下三类 `tokio::test`（重试、并发上限、fallback）回归。
后续新增了路由过滤和低优先级事件过滤分支的回归验证。
测试实现已抽离到独立测试子模块文件：`examples/alert_gateway_adapter_tests.rs`。
覆盖测试：
- `alert_gateway_retry_count_should_match_policy`
- `alert_gateway_concurrency_should_respect_limit`
- `alert_gateway_route_filter_should_skip_unmatched_route`
- `alert_gateway_low_level_should_not_send_alert`
- `alert_gateway_no_endpoint_should_fallback_without_gateway_call`
- `alert_gateway_no_runtime_should_fallback_without_gateway_call`
- `alert_gateway_send_error_should_emit_fallback_lines`
- `alert_gateway_stress_high_concurrency_should_stabilize_under_limit`（高并发持续压测）

```bash
# 日常 CI（快速路径）：只跑常规用例
cargo test --example alert_gateway_adapter alert_gateway_

# 夜间/perf job（只跑压测用例，结果非阻塞）
# 同名任务并发保护：同工作流新一轮触发会取消旧执行
# nightly 环境可用
cargo +nightly test --example alert_gateway_adapter alert_gateway_stress_high_concurrency_should_stabilize_under_limit -- --ignored

# 非 nightly 的本地手工触发（等价行为）
cargo test --example alert_gateway_adapter alert_gateway_stress_high_concurrency_should_stabilize_under_limit -- --ignored

# workflow_dispatch 支持手动触发
# 若希望在 GitHub 界面手动跑该压测用例，请设置输入：
# run_stress_test=true

# 若在 CI 引入夜间 perf 任务，可配置一个独立 job 单独触发 ignore 用例
```

### error_kind 与告警路由建议映射（可直接接入告警规则）

建议将 `TransportEvent` 的 `error_kind` 与 `alert_policy` 做联合分层，形成可复用路由规则：

| error_kind | 告警优先级 | 推荐 alert_policy | 告警动作 | 示例规则表达 |
|---|---:|---|---|---|
| `Authentication` | critical | `security.auth` | 立即发送（不采样） | `event.error_kind=="Authentication"` |
| `Signature` | critical | `security.signature` | 立即发送（不采样） | `event.error_kind=="Signature"` |
| `InvalidParameter` | medium | `params.invalid` | 有限速采样/低优先级告警 | `>= burst_threshold -> sample_every` |
| `RateLimited` | high | `business.ratelimit` | 告警+触发保护策略 | `is_auth_error==false && status==429` |
| `RequestTimeout` | high | `network.timeout` | 有采样，配合抖动阈值 | `status==408 || status==504` |
| `ConnectionError` | high | `network.connectivity` | 有采样+重试后告警 | `status==0` 或网络层异常 |
| `NotFound` | low | `resource.not_found` | 通常不告警或仅日志告警 | 视业务配置 |
| `Internal` | critical | `system.internal` | 建议高优先级上报，结合 retry 结果 | `status>=500` |
| `Unknown` | medium | `unknown` | 保守采样/观察期 | `event.alert_level` 决定 |

规则落地建议：

- metrics 维度始终携带 `error_kind`、`alert_policy`、`alert_route`、`operation`、`app_id`。
- 告警策略聚合时先按 `error_kind` 粗分桶，再按 `alert_route` 聚合，最后结合 `error_kind` 的回归率设置噪音阈值（例如 1 分钟内 `critical` + `Authentication` > 5 次）。
