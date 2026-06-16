### Changelog

##### v2.0.1

- 新增 `wiremock` 集成测试（服务端到端签名/分发/解析 + HTTP 5xx 重试）与全模块单元测试，用例数达 200+
- 新增 6 个可运行示例：`crypto_demo`、`signing_demo`、`payment_native`、`query_and_refund`、`transfer_and_profit_sharing`、`cert_download_demo`
- 新增 criterion 基准测试 `benches/crypto`（摘要 / nonce / AES / RSA 签名热路径）
- 性能优化：请求签名热路径以 `String::with_capacity` + `write!` 取代 `format!`，`Uuid::simple()` 去掉 `replace`
- 修复 `Authorization` 头结尾引号缺失的签名问题，并清理若干 clippy 提示

##### v2.0.0

- 对齐核心微信支付服务 API，包括支付、查询、退款、转账、分账、证书与通知处理链路
- 补充面向 `wechatpay-apiv3/wechatpay-go` 的兼容入口与快捷方法，降低迁移成本
- 新增 `Axum` / `Actix-Web` Webhook 示例与 `.env.example` 本地联调模板
- 增加告警网关示例，并补齐发布元信息与 `docs` feature 模块占位
- 完成 `crates.io` 发布校验与 `2.0.0` 版本准备

##### v1.0.0
