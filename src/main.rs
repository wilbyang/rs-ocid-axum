use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use tokio::net::TcpListener;

use rs_ocid_axum::{OidcBuilder, OidcCallback, OidcConfig, OidcError, OidcTokenSet};

#[derive(Clone)]
struct MyCallback;

#[async_trait::async_trait]
impl OidcCallback for MyCallback {
    async fn on_success(&self, tokens: OidcTokenSet) -> Response {
        (StatusCode::OK, Json(json!(tokens))).into_response()
    }

    async fn on_error(&self, error: OidcError) -> Response {
        (StatusCode::UNAUTHORIZED, format!("Auth failed: {}", error)).into_response()
    }
}

#[tokio::main]
async fn main() {
    let config = OidcConfig {
        issuer_url: "https://accounts.google.com".to_string(),
        client_id: "your-client-id".to_string(),
        client_secret: "your-client-secret".to_string(),
        redirect_url: "http://localhost:3000/auth/callback".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        login_path: "/auth/login".to_string(),
        callback_path: "/auth/callback".to_string(),
    };

    let oidc_router = OidcBuilder::new(config, MyCallback)
        .build()
        .await
        .expect("Failed to initialize OIDC");

    let app = Router::new()
        .route("/", get(|| async { "Hello, Public World!" }))
        .route("/protected", get(|| async { "Hello, Protected World!" }))
        .merge(oidc_router.into_axum_router());

    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("failed to bind 127.0.0.1:3000");

    println!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.expect("server failed");
}
