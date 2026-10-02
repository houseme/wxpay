# 微信支付 API v3 Rust SDK

[![Crates.io](https://img.shields.io/crates/v/wxpay-rs.svg)](https://crates.io/crates/wxpay-rs)
[![Documentation](https://docs.rs/wxpay-rs/badge.svg)](https://docs.rs/wxpay-rs)
[![License](https://img.shields.io/crates/l/wxpay-rs.svg)](LICENSE)
[![Build](https://github.com/houseme/wxpay/actions/workflows/Build.yml/badge.svg)](https://github.com/houseme/wxpay/actions/workflows/Build.yml)

提供 JSAPI、小程序、Native、H5、APP 支付，以及订单查询、退款、分账和批量转账接口。基于 Tokio 和 reqwest，支持请求签名、响应验签、平台证书或公钥管理、RSA-OAEP 敏感字段加密和 AES-256-GCM 通知解密。

本 README 对应 `wxpay-rs 2.1.0`；完整发布记录见 [CHANGELOG](CHANGELOG.md#210---2026-10-02)。`docs` feature 将本文的 Rust 示例纳入文档编译检查。

## 安装

`2.1.0` 修正了 `2.0.x` 的支付协议、验签与加密行为，并包含源码不兼容的模型调整。升级前请阅读下方的迁移说明；建议先固定为 `=2.1.0`，完成应用验证后再选择兼容版本范围。

```toml
[dependencies]
wxpay-rs = "=2.1.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde_json = "1"
```

默认启用 `tls-rustls`。`--no-default-features` 可用于自定义 HTTP transport 和本地测试；访问微信支付 HTTPS 接口需要启用 TLS。

## 初始化客户端

从商户平台取得商户私钥、商户证书序列号、32 字节 APIv3 密钥，以及受信任的微信支付平台公钥或证书。商户证书序列号用于请求签名；平台公钥 ID 或平台证书序列号用于响应和通知验签，两者不能互换。

```rust,no_run
use wxpay_rs::{WxPayClient, WxPayConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = WxPayConfig::builder()
        .app_id("wx88888888")
        .merchant_id("1900000109")
        .api_v3_key(std::env::var("WXPAY_API_V3_KEY")?)
        .private_key_from_file("certs/apiclient_key.pem")
        .cert_serial_number("YOUR_MERCHANT_CERT_SERIAL")
        .platform_public_key(
            "PUB_KEY_ID_YOUR_PLATFORM_KEY_ID",
            std::fs::read("certs/wechatpay_public_key.pem")?,
        )
        .timeout(30) // 秒
        .build()?;

    let client = WxPayClient::new(config).await?;
    let _ = client;
    Ok(())
}
```

证书模式将上例的 `.platform_public_key(id, pem)` 替换为 `.platform_certificate(std::fs::read("certs/wechatpay_platform.pem")?)`。公钥模式和证书模式可以同时配置，便于迁移。证书必须在有效期内；公钥 ID 必须与微信支付响应中的 `Wechatpay-Serial` 对应。

客户端按响应原文验签。缺少签名头、未知的平台密钥、过期证书或不正确的签名都会导致业务请求失败；不能把未验签的数据作为可信业务结果。初始化客户端不会自动下载证书，也不会自动启动后台刷新。

`CertDownloader` 支持经过认证的首次证书下载：先以 APIv3 密钥通过 AES-256-GCM 认证并解密候选证书，再用对应候选证书验证完整响应签名；全部检查通过后才写入共享信任状态。已有可信平台密钥时优先使用它验签，已知密钥的验签失败不会触发候选替换。未加密的证书内容或没有有效签名的响应不能建立信任。

APIv3 不提供本 SDK 可用的沙箱；`Environment::Sandbox` 会返回配置错误。本地自动化测试应注入 mock HTTP transport，真实请求会操作正式商户数据。

## JSAPI / 小程序支付

```rust,no_run
use wxpay_rs::{WxPayClient, WxPayResult};
use wxpay_rs::services::payments::jsapi::{Amount, JsapiPayParams, JsapiRequest, Payer};

async fn create_jsapi_order(client: &WxPayClient, openid: String) -> WxPayResult<JsapiPayParams> {
    let request = JsapiRequest {
        appid: client.config().app_id.clone(),
        mchid: client.config().merchant_id.clone(),
        description: "测试商品".into(),
        out_trade_no: "ORDER_202610020001".into(),
        amount: Some(Amount { total: 100, currency: Some("CNY".into()) }),
        payer: Some(Payer { openid }),
        notify_url: Some("https://example.com/webhooks/wechatpay/payment".into()),
    };

    let response = client.jsapi().create_order(&request).await?;
    client.jsapi().build_pay_params(&response.prepay_id).await
}
```

金额单位为分。订单号必须由业务系统生成并持久化。`JsapiPayParams` 的 JSON 字段对应 WeixinJSBridge / 小程序 `requestPayment`；使用 JSSDK `chooseWXpay` 时，将 `timeStamp` 映射为 `timestamp`。前端返回成功后仍需以验签通知或主动查单确认支付结果。

## Native 支付

```rust,no_run
use wxpay_rs::{WxPayClient, WxPayResult};
use wxpay_rs::services::payments::{jsapi::Amount, native::NativeRequest};

async fn create_native_order(client: &WxPayClient) -> WxPayResult<String> {
    let request = NativeRequest {
        appid: client.config().app_id.clone(),
        mchid: client.config().merchant_id.clone(),
        description: "测试商品".into(),
        out_trade_no: "ORDER_202610020002".into(),
        amount: Some(Amount { total: 100, currency: Some("CNY".into()) }),
        notify_url: Some("https://example.com/webhooks/wechatpay/payment".into()),
    };
    Ok(client.native().create_order(&request).await?.code_url)
}
```

将返回的 `code_url` 转成二维码展示给用户。H5、APP 的请求类型分别为 `H5Request`、`AppRequest`，通过 `client.h5()`、`client.app()` 调用。

## 查询订单与退款

```rust,no_run
use wxpay_rs::{WxPayClient, WxPayResult};
use wxpay_rs::services::refund::{RefundAmount, RefundRequest};

async fn query_and_refund(client: &WxPayClient, out_trade_no: &str) -> WxPayResult<()> {
    let order = client.query().by_out_trade_no(out_trade_no).await?;
    if order.trade_state != "SUCCESS" {
        return Ok(());
    }
    // 未支付订单可能没有微信支付订单号，应处理 Option。
    let _transaction_id = order.transaction_id.as_deref();

    let request = RefundRequest {
        transaction_id: None,
        out_trade_no: Some(out_trade_no.into()),
        out_refund_no: "REFUND_202610020001".into(),
        reason: Some("用户申请退款".into()),
        amount: RefundAmount { refund: 100, total: 100, currency: "CNY".into() },
        notify_url: Some("https://example.com/webhooks/wechatpay/refund".into()),
    };
    let refund = client.refund().create_refund(&request).await?;
    let _latest = client.refund().query_refund(&refund.out_refund_no).await?;
    Ok(())
}
```

退款时 `transaction_id` 与 `out_trade_no` 恰好提供一个。生产代码应从已持久化订单读取原金额、退款金额和幂等退款单号。请求超时并不证明业务操作失败，应使用同一业务单号查单确认。

## 验签并解密通知

在应用启动时创建 `client.notify_handler()?`，并在请求之间复用。将 HTTP 原始 body 字节和四个签名头传入 `verify_and_parse`，不要先解析 JSON 再重新序列化。

```rust,no_run
use wxpay_rs::notify::{NotifyHandler, NotifyHeaders, PaymentExpectation};
use wxpay_rs::notify::handler::PaymentNotifyData;
use wxpay_rs::WxPayResult;

async fn verify_payment(
    handler: &NotifyHandler,
    headers: NotifyHeaders<'_>,
    raw_body: &[u8],
    expected: PaymentExpectation<'_>, // 必须来自本地订单，而不是通知字段
) -> WxPayResult<(String, PaymentNotifyData)> {
    let verified = handler.verify_and_parse(headers, raw_body).await?;
    let payment = handler.handle_verified_payment_notify(&verified).await?;
    payment.validate_order(expected)?;
    // 将通知 ID、订单状态变更和业务任务写入同一个幂等事务后，才能应答成功。
    Ok((verified.request().id.clone(), payment))
}
```

`NotifyHeaders` 包含 `timestamp`、`nonce`、`serial`、`signature`，分别取自 `Wechatpay-Timestamp`、`Wechatpay-Nonce`、`Wechatpay-Serial`、`Wechatpay-Signature`。验签入口检查 300 秒时间窗口；窗口内的重复通知仍需数据库幂等处理。

退款通知使用 `handle_verified_refund_notify` 和 `RefundExpectation`，支持成功、关闭及异常状态。请根据本地商户、订单、金额和退款单核对结果推进业务状态。

[Axum Webhook 示例](examples/webhook_axum.rs) 展示原始请求体验签和 HTTP 应答流程。其持久化接收函数默认返回失败；完成订单核对和数据库事务后再启用成功应答。仅在业务持久化成功后返回 HTTP 204，验签、解密或业务处理失败时返回非 2xx。

## 证书与公钥管理

`client.cert_manager()`、响应验签器和通知处理器共享可信密钥状态。通过管理器更新证书或公钥后，已有服务和通知处理器即可使用更新后的密钥。

证书下载和刷新入口为 `cert::CertDownloader` 与 `cert::downloader::CertRefresher`。`CertRefresher::new(downloader, interval_secs).start_auto_refresh()?` 返回 `CertRefreshHandle`，启动后立即执行首次刷新，之后按秒间隔运行；间隔必须大于零。应用需持有该句柄，通过 `cancel()` 或释放句柄停止任务。公钥模式的密钥轮换需按商户平台下发的新公钥 ID 更新配置或共享管理器；平台公钥不是通过证书接口自动下载的。

## API 入口

| 功能 | 入口 |
| --- | --- |
| JSAPI、Native、H5、APP 下单 | `client.jsapi()/native()/h5()/app().create_order(&request)` |
| 前端调起参数 | `client.jsapi().build_pay_params()` / `client.app().generate_pay_params()`，均为异步方法 |
| 订单查询和关闭 | `client.query().by_out_trade_no()` / `by_transaction_id()` / `close()` |
| 退款申请和查询 | `client.refund().create_refund()` / `query_refund()` |
| 分账及接收方管理 | `client.profit_sharing().create()` / `query()` / `add_receiver()` / `delete_receiver()` / `finish()` |
| 批量转账及查询 | `client.transfer().create_transfer()` / `query_transfer_batch()` / `query_batch()` |
| 下载平台证书响应 | `client.certificates().get_certificates()` |
| 支付和退款通知 | `client.notify_handler()` |

分账、转账请求与查询具有不同的模型，按方法签名传递参数。当前批量转账服务对应 `/v3/transfer/batches`，不是新版商家转账单接口；使用前确认商户开通的产品。SDK 不提供文件上传接口。

保留 Go SDK 风格的薄兼容入口：`refunddomestic()`、`transferbatch()`、`profitsharing()`，以及 `query_order_by_out_trade_no()`、`query_order_by_id()` 等别名。完整签名请查看 [API 文档](https://docs.rs/wxpay-rs)。

## 加密与升级注意事项

从 `2.0.x` 升级时，请按下面的变化调整调用方。此次版本号为 `2.1.0`，但以下 API 修正并非完全向后兼容。

| 范围 | 2.1.0 迁移要求 |
| --- | --- |
| 订单查询 | `Transaction.transaction_id` 改为 `Option<String>`；未支付订单可能没有微信支付单号。 |
| 转账查询 | 使用 `QueryTransferBatchResponse.transfer_batch` 读取批次；成功/失败计数可能为 `None`，不能等同于零。 |
| 转账创建 | 应答包含 `create_time`，`batch_status` 改为可选字段。 |
| 分账结果 | 将 `status` 改为 `state`，并检查每个接收方的处理结果；整体完成不代表所有接收方都成功。 |
| 敏感姓名 | 传入明文，由 SDK 使用平台密钥加密；移除调用方原有的预加密步骤，避免重复加密。 |
| JSAPI 参数 | 使用正确的 `appId`、`timeStamp`、`nonceStr`、`package`、`signType`、`paySign` 字段；按下单 AppID 生成签名。 |
| 通知入口 | 使用 `verify_and_parse` 接收原始 body 与完整签名头，再调用已验签通知处理方法。 |
| 信任配置 | 默认客户端发送请求前必须具备有效平台证书或公钥；优先通过 `WxPayConfig::builder()` 配置新增字段。 |
| 证书刷新 | `start_auto_refresh()` 返回 `Result<CertRefreshHandle>`；保存句柄，释放或取消句柄会停止刷新。 |
| RSA 签名 | 内置签名器需要 Tokio 运行时，队列满时返回 `SignError`；可通过 `with_signing_capacity` 调整容量。 |

- APIv3 请求和调起支付使用 SHA256-RSA。敏感字段使用微信支付要求的 RSA-OAEP-SHA1，RSA 后端为 `aws-lc-rs`。
- `Aes256GcmCipher::new` 直接使用 32 字节 APIv3 密钥。旧版本本地自加密数据使用 `Aes256GcmCipher::from_legacy_sha256_key` 或 `RsaOaepDecrypter::decrypt_legacy_sha256` 显式迁移；微信支付通知和证书不能使用这些旧格式入口。
- RSA 公钥加密及验签支持 2048 至 8192 位密钥。旧 `rsa::Error`、`pkcs8::Error` 到 `WxPayError` 的自动转换已移除，外部后端应自行映射错误。
- 配置和凭据的 `Debug` 输出隐藏密钥。应用仍需避免记录通知全文、请求签名、个人信息或商户私钥。
- 复用 `WxPayClient` 和通知处理器；客户端共享 HTTP 连接池及验签密钥。性能变化应通过同一环境的基准和并发延迟测量确认。

## 运行示例与验证

复制 [.env.example](.env.example) 并填写本地凭据。除商户配置外，至少提供一份受信任的平台证书，或一组平台公钥 ID 与 PEM 文件。示例缺少配置时会打印说明并跳过真实调用。

```bash
cp .env.example .env
cargo run --locked --example payment_native
cargo run --locked --example webhook_axum

cargo fmt --all --check
cargo check --all-targets --no-default-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --all-features --locked
```

其他示例见 [examples](examples)：`query_and_refund`、`transfer_and_profit_sharing`、`cert_download_demo`、`signing_demo` 和 `crypto_demo`。需要网络的示例会使用正式商户接口，请填写专用测试订单并核对每项业务操作。

## 贡献与许可证

欢迎通过 [GitHub Issues](https://github.com/houseme/wxpay/issues) 和 Pull Requests 反馈问题或提交改进。本项目采用 [Apache-2.0](LICENSE) 许可证。
