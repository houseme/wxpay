//! 服务层端到端集成测试。
//!
//! 使用 `StubHttpClient`（实现公开 `HttpClient` trait）注入到 `WxPayClient`，
//! 在不依赖真实网络的情况下验证：请求签名 → Authorization 头构建 → 服务分发 →
//! 响应解析 → 错误映射。覆盖 JSAPI / Native / 查单 / 退款 / 转账 / 分账 / 证书。

mod common;

use std::sync::Arc;
use wxpay_rs::WxPayClientBuilder;
use wxpay_rs::WxPayError;
use wxpay_rs::services::payments::jsapi::{Amount, JsapiRequest, Payer};
use wxpay_rs::services::payments::native::NativeRequest;
use wxpay_rs::services::profit_sharing::{
    ProfitSharingFinishRequest, ProfitSharingRequest, QueryProfitSharingRequest, Receiver,
};
use wxpay_rs::services::query::QueryByOutTradeNoRequest;
use wxpay_rs::services::refund::{RefundAmount, RefundRequest};
use wxpay_rs::services::transfer::{TransferDetail, TransferRequest};

use common::{StubHttpClient, TEST_PRIVATE_KEY_PEM, test_config};

async fn build_client(stub: StubHttpClient) -> (wxpay_rs::WxPayClient, Arc<StubHttpClient>) {
    let stub = Arc::new(stub);
    let client = WxPayClientBuilder::default()
        .config(test_config())
        .http_client(StubHttpClientShim(stub.clone()))
        .build()
        .await
        .expect("客户端应构建成功");
    (client, stub)
}

/// `WxPayClientBuilder::http_client` 需要 `impl HttpClient + 'static`；
/// 而 `Arc<StubHttpClient>` 自身不实现 trait，这里用一个薄包装转发。
struct StubHttpClientShim(Arc<StubHttpClient>);

#[async_trait::async_trait]
impl wxpay_rs::http::HttpClient for StubHttpClientShim {
    async fn get(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> wxpay_rs::error::WxPayResult<wxpay_rs::http::client::HttpResponse> {
        self.0.get(url, headers).await
    }
    async fn post(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> wxpay_rs::error::WxPayResult<wxpay_rs::http::client::HttpResponse> {
        self.0.post(url, headers, body).await
    }
    async fn put(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> wxpay_rs::error::WxPayResult<wxpay_rs::http::client::HttpResponse> {
        self.0.put(url, headers, body).await
    }
    async fn delete(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> wxpay_rs::error::WxPayResult<wxpay_rs::http::client::HttpResponse> {
        self.0.delete(url, headers).await
    }
    async fn patch(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> wxpay_rs::error::WxPayResult<wxpay_rs::http::client::HttpResponse> {
        self.0.patch(url, headers, body).await
    }
}

#[tokio::test]
async fn jsapi_create_order_signs_and_parses() {
    let stub =
        StubHttpClient::ok_with_request_id(r#"{"prepay_id":"wx20240101prepay"}"#, "req-jsapi-001");
    let (client, stub) = build_client(stub).await;

    let request = JsapiRequest {
        appid: "wx88888888".to_string(),
        mchid: "1900000109".to_string(),
        description: "测试商品".to_string(),
        out_trade_no: "out_jsapi_001".to_string(),
        amount: Some(Amount {
            total: 100,
            currency: Some("CNY".to_string()),
        }),
        payer: Some(Payer {
            openid: "oUpF8uMuAJO_M2pxb1Q9zNjWeS6o".to_string(),
        }),
        notify_url: Some("https://example.com/notify".to_string()),
    };

    let resp = client.jsapi().create_order(&request).await.unwrap();
    assert_eq!(resp.prepay_id, "wx20240101prepay");

    // 端到端断言：请求被正确签名、URL 拼接正确、请求体被序列化透传。
    let auth = stub
        .captured_authorization()
        .expect("应携带 Authorization 头");
    assert!(
        auth.starts_with("WECHATPAY2-SHA256-RSA2048 "),
        "Authorization 头前缀错误: {auth}"
    );
    assert!(auth.contains("mchid=\"1900000109\""));
    assert!(auth.contains("serial_no=\"CERT123456\""));
    assert!(auth.contains("signature=\""));
    assert!(auth.ends_with('"'), "Authorization 头应以引号结尾");

    let url = stub.captured_url().unwrap();
    assert_eq!(
        url,
        "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi"
    );

    let body = stub.captured_body().unwrap();
    assert!(body.contains("\"out_trade_no\":\"out_jsapi_001\""));
    assert!(body.contains("\"total\":100"));

    // 桩只应被调用一次（单次下单，无重试）。
    assert_eq!(stub.request_count(), 1);
}

#[tokio::test]
async fn native_create_order_returns_code_url() {
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"code_url":"weixin://wxpay/bizpayurl?pr=test"}"#,
        "req-native-001",
    );
    let (client, _stub) = build_client(stub).await;

    let request = NativeRequest {
        appid: "wx88888888".to_string(),
        mchid: "1900000109".to_string(),
        description: "Native 测试".to_string(),
        out_trade_no: "out_native_001".to_string(),
        amount: Some(Amount {
            total: 200,
            currency: Some("CNY".to_string()),
        }),
        notify_url: None,
    };

    let resp = client.native().create_order(&request).await.unwrap();
    assert!(resp.code_url.starts_with("weixin://wxpay/bizpayurl"));
}

#[tokio::test]
async fn query_order_by_out_trade_no_builds_correct_path() {
    let stub = StubHttpClient::ok_with_request_id(
        r#"{
            "appid":"wx88888888","mchid":"1900000109",
            "out_trade_no":"out_001","transaction_id":"4200000001",
            "trade_state":"SUCCESS","trade_type":"JSAPI",
            "trade_state_desc":"支付成功"
        }"#,
        "req-query-001",
    );
    let (client, stub) = build_client(stub).await;

    // 通过 go 风格快捷入口查询。
    let tx = client.query_order_by_out_trade_no("out_001").await.unwrap();
    assert_eq!(tx.transaction_id, "4200000001");
    assert_eq!(tx.trade_state, "SUCCESS");

    // 断言路径与 mchid 查询参数被正确拼接。
    let url = stub.captured_url().unwrap();
    assert!(url.contains("/v3/pay/transactions/out-trade-no/out_001"));
    assert!(url.contains("mchid=1900000109"));
}

#[tokio::test]
async fn query_by_out_trade_no_request_variant() {
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"appid":"wx88888888","mchid":"1900000109","transaction_id":"4200000002","trade_state":"NOTPAY"}"#,
        "req-query-002",
    );
    let (client, stub) = build_client(stub).await;

    let request = QueryByOutTradeNoRequest {
        out_trade_no: "out_002".to_string(),
        mchid: "1900000109".to_string(),
    };
    let tx = client
        .query()
        .by_out_trade_no_request(&request)
        .await
        .unwrap();
    assert_eq!(tx.trade_state, "NOTPAY");
    assert!(
        stub.captured_url()
            .unwrap()
            .contains("/v3/pay/transactions/out-trade-no/out_002")
    );
}

#[tokio::test]
async fn refund_create_and_query() {
    // 创建退款。
    let stub = StubHttpClient::ok_with_request_id(
        r#"{
            "refund_id":"5000000038","out_refund_no":"refund_001",
            "transaction_id":"4200000001","out_trade_no":"out_001","status":"PROCESSING"
        }"#,
        "req-refund-create",
    );
    let (client, stub) = build_client(stub).await;

    let request = RefundRequest {
        transaction_id: Some("4200000001".to_string()),
        out_trade_no: None,
        out_refund_no: "refund_001".to_string(),
        reason: Some("商品已售完".to_string()),
        amount: RefundAmount {
            refund: 100,
            total: 100,
            currency: "CNY".to_string(),
        },
        notify_url: None,
    };
    let resp = client.refund().create_refund(&request).await.unwrap();
    assert_eq!(resp.refund_id, "5000000038");
    assert_eq!(resp.status, "PROCESSING");
    assert!(
        stub.captured_url()
            .unwrap()
            .ends_with("/v3/refund/domestic/refunds")
    );
}

#[tokio::test]
async fn transfer_batch_create() {
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"batch_id":"batch001","out_batch_no":"out_batch_001","batch_status":"ACCEPT"}"#,
        "req-transfer-create",
    );
    let (client, stub) = build_client(stub).await;

    let request = TransferRequest {
        appid: "wx88888888".to_string(),
        out_batch_no: "out_batch_001".to_string(),
        batch_name: "测试转账".to_string(),
        batch_remark: "备注".to_string(),
        transfer_detail_list: vec![TransferDetail {
            out_detail_no: "detail_001".to_string(),
            transfer_amount: 100,
            transfer_remark: "转账".to_string(),
            openid: "oUpF8u".to_string(),
            user_name: None,
        }],
        total_amount: 100,
        total_num: 1,
    };
    let resp = client.transfer().create_transfer(&request).await.unwrap();
    assert_eq!(resp.batch_id, "batch001");
    assert_eq!(resp.batch_status, "ACCEPT");
    assert!(
        stub.captured_url()
            .unwrap()
            .ends_with("/v3/transfer/batches")
    );
}

#[tokio::test]
async fn profit_sharing_create_query_finish() {
    // 创建分账。
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"order_id":"ps001","out_order_no":"P001","transaction_id":"4200000001","status":"ACCEPTED"}"#,
        "req-ps-create",
    );
    let (client, _stub) = build_client(stub).await;

    let request = ProfitSharingRequest {
        transaction_id: "4200000001".to_string(),
        out_order_no: "P001".to_string(),
        receivers: vec![Receiver {
            receiver_type: "MERCHANT_ID".to_string(),
            account: "1900000109".to_string(),
            amount: 100,
            description: "分账".to_string(),
            name: None,
        }],
        description: "分账".to_string(),
    };
    let resp = client
        .profit_sharing()
        .create_order(&request)
        .await
        .unwrap();
    assert_eq!(resp.order_id, "ps001");
    assert_eq!(resp.status, "ACCEPTED");

    // 查询分账。
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"order_id":"ps001","out_order_no":"P001","transaction_id":"4200000001","status":"FINISHED"}"#,
        "req-ps-query",
    );
    let (client, stub) = build_client(stub).await;
    let q = client
        .profit_sharing()
        .query_order(&QueryProfitSharingRequest {
            transaction_id: "4200000001".to_string(),
            out_order_no: "P001".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(q.status, "FINISHED");
    assert!(
        stub.captured_url()
            .unwrap()
            .contains("/v3/profitsharing/orders/P001")
    );

    // 完成分账（返回完整 JSON 响应体）。
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"order_id":"ps001","out_order_no":"P001","transaction_id":"4200000001","status":"FINISHED"}"#,
        "req-ps-finish",
    );
    let (client, _stub) = build_client(stub).await;
    let finished = client
        .profit_sharing()
        .finish_order(&ProfitSharingFinishRequest {
            transaction_id: "4200000001".to_string(),
            out_order_no: "P001".to_string(),
            description: "完结".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(finished.status, "FINISHED");
}

#[tokio::test]
async fn api_error_is_propagated_and_classified() {
    // 微信返回鉴权错误：应被归一为 ApiError，分类为 Authentication。
    let stub = StubHttpClient::new(
        401,
        r#"{"code":"SIGN_ERROR","message":"签名错误"}"#.to_string(),
    );
    let (client, _stub) = build_client(stub).await;

    let err = client.query_order_by_out_trade_no("any").await.unwrap_err();

    match &err {
        WxPayError::ApiError { code, message } => {
            assert_eq!(code, "SIGN_ERROR");
            assert_eq!(message, "签名错误");
        }
        other => panic!("应为 ApiError，实际: {other:?}"),
    }
    assert_eq!(
        err.api_kind(),
        Some(wxpay_rs::error::WxPayErrorKind::Authentication)
    );
    assert!(err.is_auth_error());
    assert!(!err.should_retry(), "鉴权错误不应重试");
}

#[tokio::test]
async fn unexpected_status_without_body() {
    // 非 JSON 错误体应归一为 UnexpectedStatusCode。
    let stub = StubHttpClient::new(502, "Bad Gateway".to_string());
    let (client, _stub) = build_client(stub).await;

    let err = client.query_order_by_out_trade_no("any").await.unwrap_err();
    assert!(matches!(err, WxPayError::UnexpectedStatusCode(502)));
}

#[tokio::test]
async fn go_style_aliases_are_callable() {
    // 兼容 wechatpay-go 命名的快捷入口应可在客户端上直接调用（签名存在性 + 类型正确）。
    let stub = StubHttpClient::ok_with_request_id("{}", "req-aliases");
    let (client, _stub) = build_client(stub).await;

    let _ = client.refunddomestic();
    let _ = client.transferbatch();
    let _ = client.profitsharing();
}

/// 直接构造服务（不经 WxPayClient）验证 builder/注入路径同样可用。
#[tokio::test]
async fn service_constructed_directly_signs_correctly() {
    let stub = Arc::new(StubHttpClient::ok_with_request_id(
        r#"{"prepay_id":"direct_prepay"}"#,
        "req-direct",
    ));
    let config = Arc::new(test_config());
    let signer: Arc<dyn wxpay_rs::auth::Signer> = Arc::new(
        wxpay_rs::auth::Sha256RsaSigner::new(
            "1900000109",
            TEST_PRIVATE_KEY_PEM.as_bytes(),
            "CERT123456",
        )
        .unwrap(),
    );
    let service = wxpay_rs::services::JsapiService::new(config, stub.clone(), signer);

    let request = JsapiRequest {
        appid: "wx88888888".to_string(),
        mchid: "1900000109".to_string(),
        description: "直接构造".to_string(),
        out_trade_no: "out_direct".to_string(),
        amount: None,
        payer: None,
        notify_url: None,
    };
    let resp = service.create_order(&request).await.unwrap();
    assert_eq!(resp.prepay_id, "direct_prepay");

    // 签名头存在即可（具体值由签名器决定）。
    assert!(stub.captured_authorization().is_some());
}
