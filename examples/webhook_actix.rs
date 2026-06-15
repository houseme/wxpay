use std::{collections::HashMap, sync::Arc};

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, post, web};
use dotenvy::dotenv;
use serde_json::json;
use wxpay_rs::{WxPayClient, WxPayConfig, WxPayError, WxPayResult, notify::handler::NotifyRequest};

#[derive(Clone)]
struct AppState {
    client: Arc<WxPayClient>,
}

fn actix_headers_to_hash_map(req: &HttpRequest) -> HashMap<String, String> {
    req.headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

async fn build_client() -> WxPayResult<WxPayClient> {
    let _ = dotenv();

    let config = WxPayConfig::builder()
        .app_id(required_env("WXPAY_APP_ID")?)
        .merchant_id(required_env("WXPAY_MERCHANT_ID")?)
        .api_v3_key(required_env("WXPAY_API_V3_KEY")?)
        .private_key_from_file(required_env("WXPAY_PRIVATE_KEY_PATH")?)
        .cert_serial_number(required_env("WXPAY_CERT_SERIAL_NUMBER")?)
        .build()?;

    WxPayClient::new(config).await
}

fn required_env(name: &str) -> WxPayResult<String> {
    std::env::var(name)
        .map_err(|_| WxPayError::missing_config(format!("{name} environment variable is required")))
}

fn server_bind_addr() -> String {
    std::env::var("WXPAY_WEBHOOK_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string())
}

#[post("/wxpay/payment-notify")]
async fn payment_notify_handler(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<NotifyRequest>,
) -> impl Responder {
    let headers = actix_headers_to_hash_map(&req);

    match handle_payment_notify_inner(&state.client, &payload, &headers).await {
        Ok(()) => HttpResponse::Ok().json(json!({ "code": "SUCCESS", "message": "成功" })),
        Err(err) => {
            tracing::error!("wxpay payment notify failed: {}", err);
            HttpResponse::BadRequest().json(json!({ "code": "FAIL", "message": "失败" }))
        }
    }
}

#[post("/wxpay/refund-notify")]
async fn refund_notify_handler(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<NotifyRequest>,
) -> impl Responder {
    let headers = actix_headers_to_hash_map(&req);

    match handle_refund_notify_inner(&state.client, &payload, &headers).await {
        Ok(()) => HttpResponse::Ok().json(json!({ "code": "SUCCESS", "message": "成功" })),
        Err(err) => {
            tracing::error!("wxpay refund notify failed: {}", err);
            HttpResponse::BadRequest().json(json!({ "code": "FAIL", "message": "失败" }))
        }
    }
}

async fn handle_payment_notify_inner(
    client: &WxPayClient,
    request: &NotifyRequest,
    headers: &HashMap<String, String>,
) -> WxPayResult<()> {
    let handler = client.notify_handler()?;
    verify_signature_if_present(&handler, request, headers).await?;

    let transaction = handler.handle_payment_notify(request).await?;
    tracing::info!(
        transaction_id = %transaction.transaction_id,
        trade_state = %transaction.trade_state,
        "wxpay payment notify success"
    );
    Ok(())
}

async fn handle_refund_notify_inner(
    client: &WxPayClient,
    request: &NotifyRequest,
    headers: &HashMap<String, String>,
) -> WxPayResult<()> {
    let handler = client.notify_handler()?;
    verify_signature_if_present(&handler, request, headers).await?;

    let refund = handler.handle_refund_notify(request).await?;
    tracing::info!(
        refund_id = %refund.refund_id,
        out_refund_no = %refund.out_refund_no,
        refund_status = %refund.refund_status,
        "wxpay refund notify success"
    );
    Ok(())
}

async fn verify_signature_if_present(
    handler: &wxpay_rs::notify::NotifyHandler,
    request: &NotifyRequest,
    headers: &HashMap<String, String>,
) -> WxPayResult<()> {
    if let (Some(timestamp), Some(nonce), Some(signature)) = (
        headers.get("wechatpay-timestamp"),
        headers.get("wechatpay-nonce"),
        headers.get("wechatpay-signature"),
    ) {
        let body = serde_json::to_string(request)?;
        let is_valid = handler
            .verify_notify_signature(timestamp, nonce, &body, signature)
            .await?;
        if !is_valid {
            return Err(WxPayError::NotifySignatureVerificationFailed);
        }
    }

    Ok(())
}

async fn run_server(client: WxPayClient) -> std::io::Result<()> {
    let state = AppState {
        client: Arc::new(client),
    };
    let bind = server_bind_addr();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(payment_notify_handler)
            .service(refund_notify_handler)
    })
    .bind(&bind)?
    .run()
    .await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = build_client()
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    run_server(client).await
}
