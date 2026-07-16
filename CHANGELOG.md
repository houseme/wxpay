# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
