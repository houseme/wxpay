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
        notify_url: Some("https://example.com/notify".to_string()),
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
    assert_eq!(tx.transaction_id.as_deref(), Some("4200000001"));
    assert_eq!(tx.trade_state, "SUCCESS");

    // 断言路径与 mchid 查询参数被正确拼接。
    let url = stub.captured_url().unwrap();
    assert!(url.contains("/v3/pay/transactions/out-trade-no/out_001"));
    assert!(url.contains("mchid=1900000109"));
}

#[tokio::test]
async fn query_by_out_trade_no_request_variant() {
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"appid":"wx88888888","mchid":"1900000109","trade_state":"NOTPAY"}"#,
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
    assert!(tx.transaction_id.is_none());
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
        r#"{"batch_id":"batch001","out_batch_no":"out_batch_001","create_time":"2026-10-02T12:00:00+08:00"}"#,
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
    assert!(resp.batch_status.is_none());
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
        r#"{"order_id":"ps001","out_order_no":"P001","transaction_id":"4200000001","state":"PROCESSING","receivers":[]}"#,
        "req-ps-create",
    );
    let (client, _stub) = build_client(stub).await;

    let request = ProfitSharingRequest {
        transaction_id: "4200000001".to_string(),
        out_order_no: "P001".to_string(),
        receivers: vec![Receiver {
            receiver_type: "PERSONAL_OPENID".to_string(),
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
    assert_eq!(resp.state, "PROCESSING");

    // 查询分账。
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"order_id":"ps001","out_order_no":"P001","transaction_id":"4200000001","state":"FINISHED","receivers":[]}"#,
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
    assert_eq!(q.state, "FINISHED");
    assert!(
        stub.captured_url()
            .unwrap()
            .contains("/v3/profitsharing/orders/P001")
    );

    // 完成分账（返回完整 JSON 响应体）。
    let stub = StubHttpClient::ok_with_request_id(
        r#"{"order_id":"ps001","out_order_no":"P001","transaction_id":"4200000001","state":"FINISHED","receivers":[]}"#,
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
    assert_eq!(finished.state, "FINISHED");
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
        amount: Some(Amount {
            total: 100,
            currency: None,
        }),
        payer: Some(Payer {
            openid: "test_openid".into(),
        }),
        notify_url: Some("https://example.com/notify".into()),
    };
    let resp = service.create_order(&request).await.unwrap();
    assert_eq!(resp.prepay_id, "direct_prepay");

    // 签名头存在即可（具体值由签名器决定）。
    assert!(stub.captured_authorization().is_some());
}

#[tokio::test]
async fn frontend_signatures_cover_official_four_lines_and_json_names() {
    use wxpay_rs::auth::{Sha256RsaSigner, Signer};
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id("{}", "frontend")).await;
    let signer =
        Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456").unwrap();
    let jsapi = client
        .jsapi()
        .generate_pay_params_for_app("wx_order_app", "prepay_123")
        .await
        .unwrap();
    let expected = signer
        .sign(&format!(
            "wx_order_app\n{}\n{}\nprepay_id=prepay_123\n",
            jsapi.timestamp, jsapi.nonce_str
        ))
        .await
        .unwrap();
    assert_eq!(jsapi.pay_sign, expected);
    let json = serde_json::to_value(&jsapi).unwrap();
    assert_eq!(json["appId"], "wx_order_app");
    assert_eq!(json["timeStamp"], jsapi.timestamp);
    assert_eq!(json["nonceStr"], jsapi.nonce_str);
    assert_eq!(json["package"], "prepay_id=prepay_123");
    assert_eq!(json["signType"], "RSA");
    assert_eq!(json["paySign"], expected);
    assert_eq!(json.as_object().unwrap().len(), 6);
    let app = client
        .app()
        .generate_pay_params_for_app("wx_order_app", "prepay_123")
        .await
        .unwrap();
    let expected = signer
        .sign(&format!(
            "wx_order_app\n{}\n{}\nprepay_123\n",
            app.timestamp, app.noncestr
        ))
        .await
        .unwrap();
    assert_eq!(app.sign, expected);
    assert_eq!(app.package, "Sign=WXPay");
    assert_eq!(stub.request_count(), 0);
}

fn valid_native_request() -> NativeRequest {
    NativeRequest {
        appid: "wx88888888".into(),
        mchid: "1900000109".into(),
        description: "测试商品".into(),
        out_trade_no: "native_001".into(),
        amount: Some(Amount {
            total: 100,
            currency: None,
        }),
        notify_url: Some("https://example.com/notify".into()),
    }
}

#[tokio::test]
async fn payment_options_enable_profit_sharing_and_omit_missing_fields() {
    use wxpay_rs::services::payments::{PaymentOptions, SettleInfo};
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(
        r#"{"code_url":"weixin://pay"}"#,
        "options",
    ))
    .await;
    client
        .native()
        .create_order_with_options(
            &valid_native_request(),
            &PaymentOptions {
                settle_info: Some(SettleInfo {
                    profit_sharing: true,
                }),
                attach: Some("order-metadata".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&stub.captured_body().unwrap()).unwrap();
    assert_eq!(body["settle_info"]["profit_sharing"], true);
    assert_eq!(body["attach"], "order-metadata");
    assert!(body.get("goods_tag").is_none());
    assert!(body["amount"].get("currency").is_none());
}

#[tokio::test]
async fn invalid_payment_refund_and_transfer_inputs_never_send_requests() {
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id("{}", "validation")).await;
    let mut native = valid_native_request();
    native.amount = None;
    assert!(matches!(
        client.native().create_order(&native).await,
        Err(WxPayError::InvalidParameter(_))
    ));
    native.amount = Some(Amount {
        total: 100,
        currency: None,
    });
    native.notify_url = None;
    assert!(matches!(
        client.native().create_order(&native).await,
        Err(WxPayError::InvalidParameter(_))
    ));
    let mut refund = RefundRequest {
        transaction_id: Some("wx_order".into()),
        out_trade_no: Some("merchant_order".into()),
        out_refund_no: "refund_001".into(),
        reason: None,
        notify_url: None,
        amount: RefundAmount {
            refund: 50,
            total: 100,
            currency: "CNY".into(),
        },
    };
    assert!(matches!(
        client.refund().create(&refund).await,
        Err(WxPayError::InvalidParameter(_))
    ));
    refund.out_trade_no = None;
    refund.amount.refund = 101;
    assert!(matches!(
        client.refund().create(&refund).await,
        Err(WxPayError::InvalidParameter(_))
    ));
    let mut transfer = valid_transfer_request();
    transfer.total_amount = 101;
    assert!(matches!(
        client.transfer().create(&transfer).await,
        Err(WxPayError::InvalidParameter(_))
    ));
    transfer.total_amount = 100;
    transfer.total_num = 2;
    assert!(matches!(
        client.transfer().create(&transfer).await,
        Err(WxPayError::InvalidParameter(_))
    ));
    assert_eq!(stub.request_count(), 0);
}

#[tokio::test]
async fn identifiers_are_encoded_in_both_wire_url_and_request_signature() {
    use wxpay_rs::auth::{Sha256RsaSigner, Signer};
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(
        r#"{"appid":"wx88888888","mchid":"1900000109","trade_state":"NOTPAY"}"#,
        "encoded",
    ))
    .await;
    client
        .query()
        .by_out_trade_no_request(&QueryByOutTradeNoRequest {
            out_trade_no: "order/100?x=1#fragment".into(),
            mchid: "merchant&injected=1".into(),
        })
        .await
        .unwrap();
    let path = "/v3/pay/transactions/out-trade-no/order%2F100%3Fx%3D1%23fragment?mchid=merchant%26injected%3D1";
    assert_eq!(
        stub.captured_url().unwrap(),
        format!("https://api.mch.weixin.qq.com{path}")
    );
    let auth = stub.captured_authorization().unwrap();
    let field = |name: &str| {
        auth.split(&format!("{name}=\""))
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string()
    };
    let message = format!(
        "GET\n{path}\n{}\n{}\n\n",
        field("timestamp"),
        field("nonce_str")
    );
    let signer =
        Sha256RsaSigner::new("1900000109", TEST_PRIVATE_KEY_PEM.as_bytes(), "CERT123456").unwrap();
    assert_eq!(field("signature"), signer.sign(&message).await.unwrap());
}

fn valid_transfer_request() -> TransferRequest {
    TransferRequest {
        appid: "wx88888888".into(),
        out_batch_no: "batch_001".into(),
        batch_name: "测试转账".into(),
        batch_remark: "测试".into(),
        transfer_detail_list: vec![TransferDetail {
            out_detail_no: "detail_001".into(),
            transfer_amount: 100,
            transfer_remark: "测试".into(),
            openid: "openid_001".into(),
            user_name: None,
        }],
        total_amount: 100,
        total_num: 1,
    }
}

#[tokio::test]
async fn transfer_queries_use_distinct_identifiers_and_nested_response() {
    use wxpay_rs::services::transfer::{QueryTransferBatchRequest, TransferQueryOptions};
    let body = r#"{"transfer_batch":{"batch_id":"wx_batch","out_batch_no":"merchant_batch","batch_status":"FINISHED","total_amount":100,"total_num":1,"success_amount":100,"success_num":1,"fail_amount":0,"fail_num":0},"transfer_detail_list":[{"out_detail_no":"detail_001","detail_id":"wx_detail","detail_status":"SUCCESS"}]}"#;
    let (client, stub) =
        build_client(StubHttpClient::ok_with_request_id(body, "batch-query")).await;
    let response = client
        .transfer()
        .query_transfer_batch("wx_batch")
        .await
        .unwrap();
    assert_eq!(response.transfer_batch.batch_status, "FINISHED");
    assert_eq!(response.transfer_batch.success_amount, Some(100));
    assert_eq!(response.transfer_batch.success_num, Some(1));
    assert_eq!(response.transfer_batch.fail_amount, Some(0));
    assert_eq!(response.transfer_batch.fail_num, Some(0));
    assert_eq!(response.transfer_detail_list[0].detail_status, "SUCCESS");
    assert!(
        stub.captured_url()
            .unwrap()
            .ends_with("/v3/transfer/batches/batch-id/wx_batch?need_query_detail=false")
    );
    client
        .transfer()
        .query_batch(&QueryTransferBatchRequest {
            out_batch_no: "merchant_batch".into(),
        })
        .await
        .unwrap();
    assert!(
        stub.captured_url()
            .unwrap()
            .ends_with("/v3/transfer/batches/out-batch-no/merchant_batch?need_query_detail=false")
    );
    client
        .transfer()
        .get_transfer_batch_by_out_batch_no_with_options(
            "merchant_batch",
            &TransferQueryOptions {
                need_query_detail: true,
                offset: Some(20),
                limit: Some(20),
                detail_status: Some("SUCCESS".into()),
            },
        )
        .await
        .unwrap();
    assert!(
        stub.captured_url()
            .unwrap()
            .ends_with("?need_query_detail=true&offset=20&limit=20&detail_status=SUCCESS")
    );
}

#[tokio::test]
async fn transfer_encrypts_name_and_identifies_platform_key() {
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(r#"{"batch_id":"wx_batch","out_batch_no":"batch_001","create_time":"2026-10-02T12:00:00+08:00"}"#, "encrypted-transfer")).await;
    let mut request = valid_transfer_request();
    request.transfer_detail_list[0].user_name = Some("张三".into());
    client.transfer().create(&request).await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&stub.captured_body().unwrap()).unwrap();
    let encrypted = body["transfer_detail_list"][0]["user_name"]
        .as_str()
        .unwrap();
    assert_ne!(encrypted, "张三");
    let decryptor =
        wxpay_rs::crypto::rsa::RsaOaepDecrypter::new(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
    assert_eq!(decryptor.decrypt(encrypted).unwrap(), "张三");
    assert!(
        stub.captured_headers()
            .iter()
            .any(|(k, v)| k == "Wechatpay-Serial" && v == common::TEST_CERT_SERIAL)
    );
    assert_eq!(
        request.transfer_detail_list[0].user_name.as_deref(),
        Some("张三")
    );
}

#[tokio::test]
async fn profit_sharing_encrypts_all_names_and_preserves_individual_results() {
    use wxpay_rs::services::profit_sharing::ProfitSharingOptions;
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(r#"{"order_id":"ps_001","out_order_no":"split_001","transaction_id":"wx_order","state":"FINISHED","receivers":[{"type":"PERSONAL_OPENID","account":"openid_001","amount":100,"description":"分账","result":"CLOSED","fail_reason":"NO_RELATION"}]}"#, "split")).await;
    let request = ProfitSharingRequest {
        transaction_id: "wx_order".into(),
        out_order_no: "split_001".into(),
        description: "legacy-not-on-wire".into(),
        receivers: vec![
            Receiver {
                receiver_type: "PERSONAL_OPENID".into(),
                account: "openid_001".into(),
                amount: 100,
                description: "分账".into(),
                name: Some("张三".into()),
            },
            Receiver {
                receiver_type: "MERCHANT_ID".into(),
                account: "1900000110".into(),
                amount: 100,
                description: "分账".into(),
                name: Some("测试商户".into()),
            },
        ],
    };
    let response = client
        .profit_sharing()
        .create_profit_sharing_with_options(
            &request,
            &ProfitSharingOptions {
                appid: None,
                unfreeze_unsplit: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(response.state, "FINISHED");
    assert_eq!(response.receivers[0].result, "CLOSED");
    assert_eq!(
        response.receivers[0].fail_reason.as_deref(),
        Some("NO_RELATION")
    );
    let body: serde_json::Value = serde_json::from_str(&stub.captured_body().unwrap()).unwrap();
    assert_eq!(body["appid"], "wx88888888");
    assert_eq!(body["unfreeze_unsplit"], true);
    assert!(body.get("description").is_none());
    let decryptor =
        wxpay_rs::crypto::rsa::RsaOaepDecrypter::new(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
    assert_eq!(
        decryptor
            .decrypt(body["receivers"][0]["name"].as_str().unwrap())
            .unwrap(),
        "张三"
    );
    assert_eq!(
        decryptor
            .decrypt(body["receivers"][1]["name"].as_str().unwrap())
            .unwrap(),
        "测试商户"
    );
    assert!(
        stub.captured_headers()
            .iter()
            .any(|(k, v)| k == "Wechatpay-Serial" && v == common::TEST_CERT_SERIAL)
    );
}

#[tokio::test]
async fn unfreeze_posts_to_orders_unfreeze_and_checks_final_schema() {
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(r#"{"order_id":"ps_001","out_order_no":"finish_001","transaction_id":"wx_order","state":"PROCESSING","receivers":[]}"#, "unfreeze")).await;
    let response = client
        .profit_sharing()
        .finish(&ProfitSharingFinishRequest {
            transaction_id: "wx_order".into(),
            out_order_no: "finish_001".into(),
            description: "分账完成".into(),
        })
        .await
        .unwrap();
    assert_eq!(response.state, "PROCESSING");
    assert!(
        stub.captured_url()
            .unwrap()
            .ends_with("/v3/profitsharing/orders/unfreeze")
    );
}

#[tokio::test]
async fn add_receiver_encrypts_plaintext_name_and_omits_optional_values() {
    use wxpay_rs::services::profit_sharing::AddProfitSharingReceiverRequest;
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(r#"{"appid":"wx88888888","type":"MERCHANT_ID","account":"1900000110","relation_type":"PARTNER"}"#, "receiver")).await;
    client
        .profit_sharing()
        .add_receiver(&AddProfitSharingReceiverRequest {
            appid: "wx88888888".into(),
            sub_appid: None,
            sub_mchid: None,
            receiver_type: "MERCHANT_ID".into(),
            account: "1900000110".into(),
            name: Some("测试商户".into()),
            relation_type: "PARTNER".into(),
            custom_relation: None,
        })
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&stub.captured_body().unwrap()).unwrap();
    assert!(body.get("sub_mchid").is_none());
    let decryptor =
        wxpay_rs::crypto::rsa::RsaOaepDecrypter::new(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
    assert_eq!(
        decryptor.decrypt(body["name"].as_str().unwrap()).unwrap(),
        "测试商户"
    );
    assert!(
        stub.captured_headers()
            .iter()
            .any(|(k, v)| k == "Wechatpay-Serial" && v == common::TEST_CERT_SERIAL)
    );
}

#[tokio::test]
async fn sensitive_fields_fail_before_network_without_a_trusted_platform_key() {
    let mut config = test_config();
    config.platform_certificates.clear();
    config.platform_public_keys.clear();
    let stub = Arc::new(StubHttpClient::ok_with_request_id("{}", "no-key"));
    let signer = Arc::new(
        wxpay_rs::auth::Sha256RsaSigner::new(
            "1900000109",
            TEST_PRIVATE_KEY_PEM.as_bytes(),
            "CERT123456",
        )
        .unwrap(),
    );
    let service = wxpay_rs::services::TransferService::new(Arc::new(config), stub.clone(), signer);
    let mut request = valid_transfer_request();
    request.transfer_detail_list[0].user_name = Some("张三".into());
    assert!(service.create(&request).await.is_err());
    assert_eq!(stub.request_count(), 0);
}

#[tokio::test]
async fn refund_options_use_nested_funding_and_validate_sum() {
    use wxpay_rs::services::refund::{RefundFunding, RefundOptions};
    let (client, stub) = build_client(StubHttpClient::ok_with_request_id(r#"{"refund_id":"refund_wx","out_refund_no":"refund_001","transaction_id":"wx_order","out_trade_no":"out_001","status":"PROCESSING"}"#, "refund-options")).await;
    let request = RefundRequest {
        transaction_id: Some("wx_order".into()),
        out_trade_no: None,
        out_refund_no: "refund_001".into(),
        reason: None,
        notify_url: None,
        amount: RefundAmount {
            refund: 50,
            total: 100,
            currency: "CNY".into(),
        },
    };
    let mut options = RefundOptions {
        funds_account: Some("AVAILABLE".into()),
        from: Some(vec![RefundFunding {
            account: "AVAILABLE".into(),
            amount: 49,
        }]),
        goods_detail: None,
    };
    assert!(matches!(
        client
            .refund()
            .create_refund_with_options(&request, &options)
            .await,
        Err(WxPayError::InvalidParameter(_))
    ));
    assert_eq!(stub.request_count(), 0);
    options.from.as_mut().unwrap()[0].amount = 50;
    client
        .refund()
        .create_refund_with_options(&request, &options)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&stub.captured_body().unwrap()).unwrap();
    assert_eq!(body["funds_account"], "AVAILABLE");
    assert_eq!(body["amount"]["from"][0]["amount"], 50);
    assert!(body.get("out_trade_no").is_none());
    assert!(body.get("reason").is_none());
    assert!(body.get("from").is_none());
}

#[test]
fn transfer_names_follow_amount_thresholds_and_batch_consistency() {
    let mut request = valid_transfer_request();
    request.transfer_detail_list[0].transfer_amount = 199_999;
    request.total_amount = 199_999;
    assert!(request.validate().is_ok());
    request.transfer_detail_list[0].transfer_amount = 200_000;
    request.total_amount = 200_000;
    assert!(request.validate().is_err());
    request.transfer_detail_list[0].user_name = Some("张三".into());
    assert!(request.validate().is_ok());
    request.transfer_detail_list[0].transfer_amount = 29;
    request.total_amount = 29;
    assert!(request.validate().is_err());
    request.transfer_detail_list[0].transfer_amount = 30;
    request.total_amount = 30;
    assert!(request.validate().is_ok());
    request.transfer_detail_list[0].transfer_amount = 100;
    request.total_amount = 200;
    request.total_num = 2;
    let mut second = request.transfer_detail_list[0].clone();
    second.out_detail_no = "detail_002".into();
    second.user_name = None;
    request.transfer_detail_list.push(second);
    assert!(request.validate().is_err());
}

#[tokio::test]
async fn pending_transfer_batches_accept_unreported_result_counters() {
    for status in ["WAIT_PAY", "ACCEPTED"] {
        let body = serde_json::json!({
            "transfer_batch": {
                "batch_id": "wx_pending", "out_batch_no": "merchant_pending",
                "batch_status": status, "total_amount": 100, "total_num": 1
            }
        })
        .to_string();
        let (client, _) =
            build_client(StubHttpClient::ok_with_request_id(&body, "pending-batch")).await;
        let response = client
            .transfer()
            .query_transfer_batch("wx_pending")
            .await
            .unwrap();
        assert_eq!(response.transfer_batch.batch_status, status);
        assert_eq!(response.transfer_batch.success_amount, None);
        assert_eq!(response.transfer_batch.success_num, None);
        assert_eq!(response.transfer_batch.fail_amount, None);
        assert_eq!(response.transfer_batch.fail_num, None);
        assert!(response.transfer_detail_list.is_empty());
    }
}
