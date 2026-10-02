# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and compatibility changes are documented explicitly for each release.

## [Unreleased]

## [2.1.0] - 2026-10-02

本版本修复支付协议及安全边界，并包含相对于 `2.0.x` 的源码和行为不兼容变化。
虽然版本号为 `2.1.0`，升级仍需按 [README 迁移说明](README.md#加密与升级注意事项) 调整调用方，
尤其是响应模型、原始通知验签、姓名加密、信任材料和旧密文读取。

### 文档与验证

- 重写 README 为当前可编译 API，删除不存在的上传接口、配置类型和本机路径；
  明确 2.1.0 安装、秒级 timeout、平台信任配置、认证 bootstrap、刷新句柄及真实业务接收责任
- `docs` feature 将 README 示例纳入 doctest；CI 实际执行默认及无默认 feature 检查，
  扩大到所有 targets，使用锁文件并将 Clippy 警告作为错误
- 示例通过平台证书或公钥 ID/PEM 配置可信材料，缺少配置时跳过真实调用
- 升级注意：RSA 公钥加密和验签要求受支持的 2048 至 8192 位密钥；
  移除对旧后端 `rsa::Error`、`pkcs8::Error` 的 `From` 实现。
  新增公开配置字段及响应类型变更需调用方适配，建议固定 `=2.1.0` 完成升级验证

### 支付与资金接口

- JSAPI/APP 调起参数使用正确的四行签名串及前端 JSON 字段，支持使用下单时的 AppID 生成参数
- 新增可选支付、退款、分账及批次查询选项，补齐分账标记、订单有效期、退款资金来源等参数；
  发送前检查必填字段、金额、退款来源合计、批次总额及明细，URL 标识符统一编码后签名
- 未支付订单的 `transaction_id` 改为 `Option`；分账响应使用 `state` 并保留逐接收方结果，
  请求携带 `unfreeze_unsplit`，解冻剩余资金使用 `/v3/profitsharing/orders/unfreeze`
- 转账按微信批次号和商户批次号使用不同查询路径，支持明细分页；查询返回独立的嵌套 `transfer_batch` 模型，
  创建应答包含 `create_time`、可选 `batch_status`，早期批次成功/失败计数为可选值
- 转账及分账的姓名参数现在接收明文，由同一次请求的平台密钥快照加密并携带对应 `Wechatpay-Serial`；
  不应继续由调用方预加密，避免双重加密；无姓名时避免复制整个请求
- 更新查单、退款、转账和分账示例及独立契约测试；本版本包含上述响应字段和返回类型修正

### 业务响应认证

- 主客户端及直接创建的服务都强制验证成功响应的原文签名、平台序列号和时间戳，包括空响应的 204
- 默认验签器缺少有效信任材料时，在签名和发送业务请求前拒绝，避免资金请求已执行但无法验证结果；
  显式自定义验签器仍可使用自己的密钥来源
- 公钥模式的普通请求也声明 `Wechatpay-Serial`，支持证书向公钥迁移；敏感字段选定的加密 serial 不被覆盖
- 所有服务、响应验签器和缓存的通知处理器复用共享信任上下文，证书及公钥更新对已有实例立即生效
- 在验签及响应模型解析完成后才记录成功，观测时长包含签名、网络、验签和解析；移除多余请求体复制
- 无签名的非 2xx 响应仅作为未认证的错误返回；只要出现签名元数据，就必须完整验证

### HTTP 传输边界

- 按响应原始字节读取并严格验证 UTF-8，避免 charset 转码或替换字符改变验签内容
- 默认限制响应体为 8 MiB，可通过 `max_response_bytes` 调整；禁止自动跳转和 reqwest 隐式重试
- HTTP timeout 现在覆盖完整请求、响应体读取及全部重试等待；GET/DELETE 遵守 `Retry-After`，
  只重试适用状态、连接失败和超时，POST/PUT/PATCH 保持不自动重试

### 回调通知

- 通知模型对齐 `event_type`，保留旧 `type` 的输入兼容；支持退款成功、异常、关闭事件
- 新增 `NotifyHeaders`、`VerifiedNotifyRequest` 与 `verify_and_parse`，先校验完整签名头、
  原始请求体、平台序列号及 300 秒时效，再解密并核对事件状态
- 提供支付及退款订单、金额、商户和应用一致性核对方法；低层解密入口不再被描述为完整验签流程
- 时间戳校验拒绝极值及负容差，避免整数溢出；复用通知配置和 AES cipher
- Axum 示例保留原始 Bytes，拒绝缺失或重复签名头，失败返回非 2xx；只有业务持久化成功才返回 204。
  示例的接收事务入口默认返回 503，接入方必须补充幂等订单事务后启用成功应答

### 密钥、证书与加密

- 使用 `aws-lc-rs` 替换 RSA 运算后端，移除命中 RUSTSEC-2023-0071 的 `rsa` 及相关传递依赖；
  保持 SHA256-RSA 签名、PKCS#1/PKCS#8 私钥以及 PEM/DER 公钥兼容
- AES-GCM 直接使用原始 32 字节 APIv3 密钥；RSA-OAEP 敏感字段对齐 SHA1/MGF1-SHA1。
  旧版自加密数据分别使用 `from_legacy_sha256_key`、`decrypt_legacy_sha256` 显式迁移，不自动降级
- RSA 签名移至有界 Tokio blocking 任务，限制执行与等待数量，取消调用不会提前释放在途计算配额；
  新增并发签名基准和独立 OpenSSL/AES 测试向量。内置签名器需要 Tokio 运行时，超载返回 `SignError`
- 平台证书和公钥使用共享的已解析密钥存储，支持 PEM/DER、证书序列号规范化、公钥 ID 精确匹配，
  使用时验证有效期，拒绝同一身份替换为不同密钥
- 证书下载强制 AES-GCM 认证及原始响应验签，整批通过后原子发布，支持认证后的首次下载与轮换重叠；
  修复下载请求 Authorization 引号，并防止已弃用证书被重新加载激活
- 证书刷新立即启动并返回可取消的 `CertRefreshHandle`；`start_auto_refresh` 现在返回 `Result`，
  调用方必须持有句柄，释放句柄即停止刷新
- 配置新增 `platform_public_key(id, pem)`；配置及凭据 Debug 隐藏密钥，拒绝不受支持的 Sandbox 和非法配置

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

### 性能优化

- 告警网关示例在创建异步任务前限制总待处理数量，默认最多 256 个执行及等待任务；
  超限计入 `dropped_alerts`，支持 `with_pending_limit`，避免并发限制之外仍积累无界等待任务
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
