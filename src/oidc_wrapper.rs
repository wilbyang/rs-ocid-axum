use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use dashmap::DashMap;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    EndpointMaybeSet, EndpointNotSet, EndpointSet,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("OIDC provider discovery failed: {0}")]
    Discovery(String),
    #[error("token exchange failed: {0}")]
    TokenExchange(String),
    #[error("ID token verification failed: {0}")]
    IdTokenVerification(String),
    #[error("invalid issuer URL: {0}")]
    InvalidIssuerUrl(String),
    #[error("invalid redirect URL: {0}")]
    InvalidRedirectUrl(String),
    #[error("invalid state parameter")]
    InvalidState,
    #[error("missing code in callback")]
    MissingCode,
    #[error("provider returned an authorization error: {0}")]
    ProviderError(String),
}

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            self.to_string(),
        )
            .into_response()
    }
}

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

#[derive(Clone, Debug, Serialize)]
pub struct OidcTokenSet {
    pub id_token: String,
    pub access_token: String,
}

#[async_trait]
pub trait OidcCallback: Clone + Send + Sync + 'static {
    async fn on_success(&self, tokens: OidcTokenSet) -> Response;
    async fn on_error(&self, error: OidcError) -> Response;
}

#[derive(Debug)]
struct AuthSession {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
}

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
struct OidcState<C: OidcCallback> {
    client: OidcClient,
    http_client: openidconnect::reqwest::Client,
    scopes: Arc<[Scope]>,
    sessions: Arc<DashMap<String, AuthSession>>,
    callback_handler: C,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn login_handler<C: OidcCallback>(State(state): State<OidcState<C>>) -> Response {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = state.client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    for scope in state.scopes.iter().cloned() {
        request = request.add_scope(scope);
    }

    let (authorize_url, csrf_token, nonce) = request.set_pkce_challenge(pkce_challenge).url();
    state.sessions.insert(
        csrf_token.secret().clone(),
        AuthSession {
            pkce_verifier,
            nonce,
        },
    );

    Redirect::temporary(authorize_url.as_ref()).into_response()
}

async fn callback_handler<C: OidcCallback>(
    State(state): State<OidcState<C>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if let Some(error) = query.error {
        return state
            .callback_handler
            .on_error(OidcError::ProviderError(error))
            .await;
    }

    let code = match query.code {
        Some(code) => AuthorizationCode::new(code),
        None => return state.callback_handler.on_error(OidcError::MissingCode).await,
    };
    let state_token = match query.state {
        Some(state_token) => state_token,
        None => return state.callback_handler.on_error(OidcError::InvalidState).await,
    };
    let (_, auth_session) = match state.sessions.remove(&state_token) {
        Some(session) => session,
        None => return state.callback_handler.on_error(OidcError::InvalidState).await,
    };

    let token_response = match state
        .client
        .exchange_code(code)
        .map_err(|error| OidcError::TokenExchange(error.to_string()))
        .and_then(|request| Ok(request.set_pkce_verifier(auth_session.pkce_verifier)))
    {
        Ok(request) => match request.request_async(&state.http_client).await {
            Ok(response) => response,
            Err(error) => {
                return state
                    .callback_handler
                    .on_error(OidcError::TokenExchange(error.to_string()))
                    .await;
            }
        },
        Err(error) => return state.callback_handler.on_error(error).await,
    };

    let id_token = match token_response.extra_fields().id_token() {
        Some(token) => token,
        None => {
            return state
                .callback_handler
                .on_error(OidcError::IdTokenVerification(
                    "provider did not return an ID token".to_string(),
                ))
                .await;
        }
    };

    if let Err(error) = id_token.claims(&state.client.id_token_verifier(), &auth_session.nonce) {
        return state
            .callback_handler
            .on_error(OidcError::IdTokenVerification(error.to_string()))
            .await;
    }

    state
        .callback_handler
        .on_success(OidcTokenSet {
            id_token: id_token.to_string(),
            access_token: token_response.access_token().secret().clone(),
        })
        .await
}

pub struct OidcBuilder<C: OidcCallback> {
    config: OidcConfig,
    callback_handler: C,
}

impl<C: OidcCallback> OidcBuilder<C> {
    pub fn new(config: OidcConfig, callback_handler: C) -> Self {
        Self {
            config,
            callback_handler,
        }
    }

    pub async fn build(self) -> Result<OidcRouter, OidcError> {
        let issuer_url = IssuerUrl::new(self.config.issuer_url.clone())
            .map_err(|error| OidcError::InvalidIssuerUrl(error.to_string()))?;
        let redirect_url = RedirectUrl::new(self.config.redirect_url.clone())
            .map_err(|error| OidcError::InvalidRedirectUrl(error.to_string()))?;
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| OidcError::Discovery(error.to_string()))?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            issuer_url,
            &http_client,
        )
        .await
        .map_err(|error| OidcError::Discovery(error.to_string()))?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.config.client_id),
            Some(ClientSecret::new(self.config.client_secret)),
        )
        .set_redirect_uri(redirect_url);

        let scopes: Arc<[Scope]> = self
            .config
            .scopes
            .into_iter()
            .filter(|scope| scope != "openid")
            .map(Scope::new)
            .collect::<Vec<_>>()
            .into();

        let state = OidcState {
            client,
            http_client,
            scopes,
            sessions: Arc::new(DashMap::new()),
            callback_handler: self.callback_handler,
        };

        let router = Router::new()
            .route(&self.config.login_path, get(login_handler::<C>))
            .route(&self.config.callback_path, get(callback_handler::<C>))
            .with_state(state);

        Ok(OidcRouter(router))
    }
}

pub struct OidcRouter(Router);

impl OidcRouter {
    pub fn into_axum_router(self) -> Router {
        self.0
    }
}
