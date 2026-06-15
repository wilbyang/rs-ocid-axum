# rs-ocid-axum

`rs-ocid-axum` is a small Rust crate that builds Axum routes for an OpenID Connect authorization-code flow with PKCE.

It exposes a reusable library API so applications can:

- mount `/login` and `/callback` style routes into an existing `axum::Router`
- validate the OIDC `state` and ID token nonce
- handle success and failure with application-defined callbacks

## Installation

```toml
[dependencies]
rs-ocid-axum = "0.1.0"
```

## Dependency baseline

This crate is currently tested against the following direct dependency versions:

- `axum 0.8.9`
- `openidconnect 4.0.1`
- `tokio 1.52.3`
- `serde 1.0.228`
- `serde_json 1.0.150`
- `dashmap 5.5.3`
- `async-trait 0.1.89`
- `thiserror 2.0.18`

`dashmap`'s crates.io latest entry is currently `7.0.0-rc2`, which is a release candidate rather than a stable release, so this crate stays on the latest stable `5.5.3`.

## Example

```rust
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rs_ocid_axum::{OidcBuilder, OidcCallback, OidcConfig, OidcError, OidcTokenSet};
use serde_json::json;

#[derive(Clone)]
struct Callback;

#[async_trait::async_trait]
impl OidcCallback for Callback {
    async fn on_success(&self, tokens: OidcTokenSet) -> Response {
        (StatusCode::OK, Json(json!(tokens))).into_response()
    }

    async fn on_error(&self, error: OidcError) -> Response {
        (StatusCode::UNAUTHORIZED, error.to_string()).into_response()
    }
}

# async fn demo() -> Result<(), OidcError> {
let oidc_router = OidcBuilder::new(
    OidcConfig {
        issuer_url: "https://accounts.google.com".into(),
        client_id: "client-id".into(),
        client_secret: "client-secret".into(),
        redirect_url: "http://localhost:3000/auth/callback".into(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        login_path: "/auth/login".into(),
        callback_path: "/auth/callback".into(),
    },
    Callback,
)
.build()
.await?;

let app = Router::new()
    .route("/", get(|| async { "ok" }))
    .merge(oidc_router.into_axum_router());
# let _ = app;
# Ok(())
# }
```

The example above matches the current crate implementation and the dependency baseline listed above, including `axum 0.8.x` and `openidconnect 4.x`.

## Development checks

```bash
cargo check
cargo test
cargo publish --dry-run --allow-dirty
```
