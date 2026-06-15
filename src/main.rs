use axum::{Router, response::{Response, IntoResponse}, http::StatusCode};
use serde_json::json;
use std::net::SocketAddr;
use tower::ServiceBuilder;

// 引入刚才写的模块
mod oidc_wrapper;
use oidc_wrapper::{OidcBuilder, OidcConfig, OidcCallback, OidcError};

// ==========================================
// 1. 定义你自己的回调处理器
// ==========================================
#[derive(Clone)]
struct MyCallback;

#[async_trait::async_trait]
impl OidcCallback for MyCallback {
    async fn on_success(&self, id_token: String, access_token: String) -> Response {
        // 在这里写你的业务逻辑：比如设置 Cookie，或者把 Token 返回给前端
        println!("Login Success! Access Token: {}", access_token);
        
        // 示例：直接将 token 以 JSON 形式返回
        (StatusCode::OK, axum::Json(json!({
            "id_token": id_token,
            "access_token": access_token
        }))).into_response()
    }

    async fn on_error(&self, error: OidcError) -> Response {
        eprintln!("OIDC Error: {:?}", error);
        (StatusCode::UNAUTHORIZED, format!("Auth failed: {}", error)).into_response()
    }
}

#[tokio::main]
async fn main() {
    // ==========================================
    // 2. 提供配置和回调
    // ==========================================
    let config = OidcConfig {
        issuer_url: "https://accounts.google.com".to_string(), // 替换为你的 OIDC Provider
        client_id: "your-client-id".to_string(),
        client_secret: "your-client-secret".to_string(),
        redirect_url: "http://localhost:3000/auth/callback".to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        login_path: "/auth/login".to_string(),
        callback_path: "/auth/callback".to_string(),
    };

    // 构建 OIDC 路由（会自动去 Provider 拉取 Discovery 文档）
    let oidc_router = OidcBuilder::new(config, MyCallback)
        .build()
        .await
        .expect("Failed to initialize OIDC");

    // ==========================================
    // 3. Merge 到主路由
    // ==========================================
    let app = Router::new()
        .route("/", get(|| async { "Hello, Public World!" }))
        .route("/protected", get(|| async { "Hello, Protected World!" }))
        .merge(oidc_router.into_axum_router()); // 在这里 Merge!

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on http://{}", addr);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}