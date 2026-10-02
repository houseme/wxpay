# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 安全与依赖

- 移除 `webhook_actix.rs` 示例及 `actix-web` 开发依赖（功能由等价的 `webhook_axum.rs` 覆盖），
  消除 dev-dependency 链 `actix-web → actix-http → h2 0.3.27` 引入的
  RUSTSEC-2026-0258（h2 unbounded empty DATA frames）告警，锁文件瘦身约 500 行（-48 个传递依赖）
- `cargo shear` 复核确认无其他未使用依赖

### 依赖更新

- 刷新 23 个兼容版本的锁定依赖，包括 `thiserror 2.0.21`、`hyper-util 0.1.21`、
  `tokio-rustls 0.26.6`、`rustls-platform-verifier 0.7.1` 与 `zerocopy 0.8.59`；
  移除不再使用的 `multiversion`、`multiversion-macros` 传递依赖
- 更新 `aes-gcm` 到 `0.11.1`、`uuid` 到 `1.26`、`der` 锁定到 `0.8.2`（传递依赖全量刷新：`rustls`、`hyper`、`hickory`、`tokio-rustls` 等）
- 更新开发依赖 `actix-web` 到 `4.15`

### 性能优化

- `ServiceTransport::build_headers`：每次请求的 `Authorization` 头构建改为预分配容量 + `write!` 就地写入，去除 `format!` 临时分配
- `Sha256RsaVerifier::build_verify_message`：验签消息构建与签名路径对齐，预分配容量并就地格式化时间戳
- `ReqwestHttpClient`：POST/PUT/PATCH 请求体由"入参拷贝 + 每次重试再克隆"改为闭包借用 `&str` 按需分配，正常路径减少一次请求体拷贝
- `ReqwestHttpClient` 构建：启用 `TCP_NODELAY`，避免 Nagle 算法给小 JSON 报文带来的发送延迟
- `WxPayRequest::full_url`：URL 拼接改为预分配容量直接拼接，去除 `format!` 开销
- `TransportEvent::alert_key`：告警路由键拼接改为预分配容量就地写入
- `CertManager`：解析后证书与原始 DER 数据合并到单一 `RwLock` 映射，读写操作从两次加锁降为一次，并保证两份数据的原子一致性

### 完善

- 修正 `User-Agent` 中硬编码的过期版本号，改为编译期注入 `CARGO_PKG_VERSION`
- 基准测试新增签名/验签消息构建与 URL 拼接路径（`sign_message/build`、`verify_message/build`、`request/full_url`）

## [2.0.2] - 2026-07-16

- 精简 `tokio` feature 配置，移除 `full`，仅保留 SDK、示例和测试实际需要的运行时能力
- 精简 `reqwest` feature 配置，移除未使用的 `form` / `query`，保留 JSON、HTTP/2、系统代理、Hickory DNS 与 charset 解码支持
- 保持 `tls-rustls` 作为默认 crate feature，通过 `reqwest/rustls` 提供 HTTPS/TLS 支持，避免把 TLS 后端硬编码到基础依赖行
- 更新 `uuid` 到 `1.24`，并刷新锁文件中的相关传递依赖

## [2.0.1] - 2026-06-16

- 新增 `wiremock` 集成测试（服务端到端签名/分发/解析 + HTTP 5xx 重试）与全模块单元测试，用例数达 200+
- 新增 6 个可运行示例：`crypto_demo`、`signing_demo`、`payment_native`、`query_and_refund`、`transfer_and_profit_sharing`、
  `cert_download_demo`
- 新增 criterion 基准测试 `benches/crypto`（摘要 / nonce / AES / RSA 签名热路径）
- 性能优化：请求签名热路径以 `String::with_capacity` + `write!` 取代 `format!`，`Uuid::simple()` 去掉 `replace`
- 修复 `Authorization` 头结尾引号缺失的签名问题，并清理若干 clippy 提示

## [2.0.0] - 2026-06-15

- 对齐核心微信支付服务 API，包括支付、查询、退款、转账、分账、证书与通知处理链路
- 补充面向 `wechatpay-apiv3/wechatpay-go` 的兼容入口与快捷方法，降低迁移成本
- 新增 `Axum` / `Actix-Web` Webhook 示例与 `.env.example` 本地联调模板
- 增加告警网关示例，并补齐发布元信息与 `docs` feature 模块占位
- 完成 `crates.io` 发布校验与 `2.0.0` 版本准备
