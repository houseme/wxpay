use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::State,
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use dotenvy::dotenv;
use serde_json::json;
use wxpay_rs::{
    notify::handler::NotifyRequest,
    WxPayClient, WxPayConfig, WxPayResult,
};

#[derive(Clone)]
struct AppState {
    client: Arc<WxPayClient>,
}

fn header_map_to_hash_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
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
    std::env::var(name).map_err(|_| {
        wxpay_rs::WxPayError::missing_config(format!(
            "{name} environment variable is required"
        ))
    })
}

fn server_bind_addr() -> String {
    std::env::var("WXPAY_WEBHOOK_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string())
}

async fn payment_notify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NotifyRequest>,
) -> Json<serde_json::Value> {
    let header_map = header_map_to_hash_map(&headers);

    match handle_payment_notify_inner(&state.client, &request, &header_map).await {
        Ok(()) => Json(json!({ "code": "SUCCESS", "message": "成功" })),
        Err(err) => {
            tracing::error!("wxpay payment notify failed: {}", err);
            Json(json!({ "code": "FAIL", "message": "失败" }))
        }
    }
}

async fn refund_notify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NotifyRequest>,
) -> Json<serde_json::Value> {
    let header_map = header_map_to_hash_map(&headers);

    match handle_refund_notify_inner(&state.client, &request, &header_map).await {
        Ok(()) => Json(json!({ "code": "SUCCESS", "message": "成功" })),
        Err(err) => {
            tracing::error!("wxpay refund notify failed: {}", err);
            Json(json!({ "code": "FAIL", "message": "失败" }))
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
            return Err(wxpay_rs::WxPayError::NotifySignatureVerificationFailed);
        }
    }

    Ok(())
}

fn build_router(client: WxPayClient) -> Router {
    let state = AppState {
        client: Arc::new(client),
    };

    Router::new()
        .route("/wxpay/payment-notify", post(payment_notify_handler))
        .route("/wxpay/refund-notify", post(refund_notify_handler))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = build_client().await?;
    let app = build_router(client);
    let bind = server_bind_addr();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("axum webhook listening on {}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
