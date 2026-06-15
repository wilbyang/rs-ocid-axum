use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use dashmap::DashMap;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AccessToken, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use thiserror::Error;

// ==========================================
// 1. 错误定义
// ==========================================
#[derive(Debug, Error)]
pub enum OidcError {
    #[error("OIDC Provider discovery failed: {0}")]
    Discovery(#[from] openidconnect::DiscoveryError<openidconnect::reqwest::Error<reqwest::Error>>),
    #[error("Token exchange failed: {0}")]
    TokenExchange(#[from] openidconnect::RequestTokenError<openidconnect::reqwest::Error<reqwest::Error>, openidconnect::StandardErrorResponse<openidconnect::EndpointNotSet>>),
    #[error("Invalid state parameter")]
    InvalidState,
    #[error("Missing code in callback")]
    MissingCode,
    #[error("ID Token verification failed")]
    IdTokenVerification,
}

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

// ==========================================
// 2. 配置与回调 Trait
// ==========================================
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub login_path: String,
    pub callback_path: String,
}

/// 消费端只需实现此 Trait 即可处理业务逻辑
#[async_trait]
pub trait OidcCallback: Clone + Send + Sync + 'static {
    /// 登录成功时的回调，消费端在此写 Cookie 或创建 Session
    async fn on_success(&self, id_token: String, access_token: String) -> Response;
    
    /// 登录失败时的回调
    async fn on_error(&self, error: OidcError) -> Response;
}

// ==========================================
// 3. 内部状态管理 (State, PKCE 等)
// ==========================================
#[derive(Debug)]
struct AuthSession {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
}

#[derive(Clone)]
pub struct OidcState<C: OidcCallback> {
    client: CoreClient,
    sessions: Arc<DashMap<String, AuthSession>>,
    callback_handler: C,
}

// ==========================================
// 4. 路由 Handler
// ==========================================
#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

// 发起登录请求
async fn login_handler<C: OidcCallback>(
    State(state): State<Arc<OidcState<C>>>,
) -> impl IntoResponse {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let nonce = Nonce::new_random();
    let csrf_token = CsrfToken::new_random();
    
    // 保存 State 和对应的 PKCE/Nonce
    state.sessions.insert(
        csrf_token.secret().clone(),
        AuthSession {
            pkce_verifier,
            nonce,
        },
    );

    let mut auth_url = state.client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        || csrf_token,
        || Nonce::new_random(), // 此处的 nonce 会被覆盖，我们使用自己保存的
    )
    .set_pkce_challenge(pkce_challenge)
    .url();

    // 手动附加 Scopes
    for scope in &state.client.scopes() {
        auth_url.0.query_pairs_mut().append_pair("scope", scope.as_str());
    }

    Redirect::temporary(auth_url.0.as_str()).into_response()
}

// 处理 OIDC 提供商的回调
async fn callback_handler<C: OidcCallback>(
    State(state): State<Arc<OidcState<C>>>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    // 1. 检查错误
    if let Some(err) = query.error {
        return state.callback_handler.on_error(OidcError::TokenExchange(
            openidconnect::RequestTokenError::ServerResponse(
                openidconnect::StandardErrorResponse::new(
                    openidconnect::StandardError::from_str(&err).unwrap_or(openidconnect::StandardError::ServerError),
                    None, None, None
                )
            )
        )).await;
    }

    // 2. 提取 Code 和 State
    let code = query.code.ok_or_else(|| OidcError::MissingCode);
    let csrf_state = query.state.ok_or_else(|| OidcError::InvalidState);

    let code = match code {
        Ok(c) => c,
        Err(e) => return state.callback_handler.on_error(e).await,
    };
    let csrf_state = match csrf_state {
        Ok(s) => s,
        Err(e) => return state.callback_handler.on_error(e).await,
    };

    // 3. 验证 State 并取出 PKCE 和 Nonce
    let auth_session = state.sessions.remove(&csrf_state).ok_or_else(|| OidcError::InvalidState);
    let auth_session = match auth_session {
        Ok(s) => s,
        Err(e) => return state.callback_handler.on_error(e).await,
    };

    // 4. 使用 Code 换取 Token
    // 注意：openidconnect 的 token 交换目前是同步的，为了不阻塞 tokio，使用 spawn_blocking
    let token_response = tokio::task::spawn_blocking(move || {
        let code = openidconnect::AuthorizationCode::new(code);
        state.client.exchange_code(code)
            .set_pkce_verifier(auth_session.pkce_verifier)
            .request(&openidconnect::reqwest::http_client())
    }).await;

    let token_response = match token_response {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return state.callback_handler.on_error(OidcError::TokenExchange(e)).await,
        Err(_) => return state.callback_handler.on_error(OidcError::TokenExchange("Task join error".into())).await,
    };

    // 5. 提取 Tokens
    let id_token_str = token_response.id_token()
        .map(|t| t.to_string())
        .unwrap_or_default();
        
    let access_token_str = token_response.access_token().secret().clone();

    // 6. 调用消费端的回调
    state.callback_handler.on_success(id_token_str, access_token_str).await
}

// ==========================================
// 5. Builder 与 Router 集成
// ==========================================
pub struct OidcBuilder<C: OidcCallback> {
    config: OidcConfig,
    callback_handler: C,
}

impl<C: OidcCallback> OidcBuilder<C> {
    pub fn new(config: OidcConfig, callback_handler: C) -> Self {
        Self { config, callback_handler }
    }

    /// 初始化 OIDC 客户端并发现 Provider 元数据
    pub async fn build(self) -> Result<OidcRouter<C>, OidcError> {
        let issuer_url = IssuerUrl::new(self.config.issuer_url.clone())
            .expect("Invalid issuer URL");
        
        // 异步发现 Provider 元数据
        let provider_metadata = CoreProviderMetadata::discover_async(
            issuer_url,
            &openidconnect::reqwest::async_http_client,
        )
        .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(self.config.redirect_url.clone()).expect("Invalid redirect URL"));

        let state = Arc::new(OidcState {
            client,
            sessions: Arc::new(DashMap::new()),
            callback_handler: self.callback_handler,
        });

        let login_path = self.config.login_path.clone();
        let callback_path = self.config.callback_path.clone();

        // 构建 Axum 路由
        let router = Router::new()
            .route(&login_path, get(login_handler::<C>))
            .route(&callback_path, get(callback_handler::<C>))
            .with_state(state);

        Ok(OidcRouter(router))
    }
}

/// 包裹 axum::Router，使其可以直接 merge
pub struct OidcRouter<C: OidcCallback>(Router<Arc<OidcState<C>>>);

impl<C: OidcCallback> OidcRouter<C> {
    pub fn into_axum_router(self) -> Router {
        // 将内部状态类型转换为通用的 Router 以便 merge
        self.0
    }
}