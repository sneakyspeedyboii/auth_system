use axum::{
    extract::{ConnectInfo, FromRef},
    http::{header::HeaderName, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::Key;
use error_stack::{IntoReport, Result, ResultExt};
use sea_orm::{Database, DatabaseConnection};
use std::{env::var, net::SocketAddr};
use tower_http::cors::{AllowOrigin, CorsLayer};

mod database;

mod auth_routes;
use crate::auth_routes::*;

mod error_handling;
use crate::error_handling::auth::AuthBuildError;

/*
Todo:
- Captcha
- OAuth2 support
- MFA support
- Still need to make email parsing less shitty
- Use relation or what ever its called for online users
- Maybe refractor and rewrite the authenticate extractor or something idk im not fixing that soon
- Peppering: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#peppering
- Make stuff like timeouts .env ed
 */

#[tokio::main]
async fn main() -> Result<(), AuthBuildError> {
    dotenv::dotenv()
        .into_report()
        .change_context(AuthBuildError)?;

    if !std::path::Path::new("key").exists() {
        std::fs::write("key", Key::generate().master())
            .into_report()
            .change_context(AuthBuildError)?;
    }

    let state = AppState {
        key: Key::from(
            &std::fs::read("key")
                .into_report()
                .change_context(AuthBuildError)?,
        ),
        database_connection: Database::connect(
            var("DATABASE_URL")
                .into_report()
                .change_context(AuthBuildError)
                .attach_printable("Might be the DATABASE_URL env variable")?,
        )
        .await
        .into_report()
        .change_context(AuthBuildError)?,
        ip_login_timeout: var("IP_LOGIN_TIMEOUT")
            .into_report()
            .change_context(AuthBuildError)
            .attach_printable("Might be the IP_LOGIN_TIMEOUT env variable")?
            .parse()
            .into_report()
            .change_context(AuthBuildError)
            .attach_printable("IP_LOGIN_TIMEOUT env variable: not a valid format?")?,
        ip_register_timeout: var("REGISTER_LOGIN_TIMEOUT")
            .into_report()
            .change_context(AuthBuildError)
            .attach_printable("Might be the REGISTER_LOGIN_TIMEOUT env variable")?
            .parse()
            .into_report()
            .change_context(AuthBuildError)
            .attach_printable("REGISTER_LOGIN_TIMEOUT env variable: not a valid format?")?,
    };

    let cors = CorsLayer::new()
        .allow_methods([Method::POST])
        .allow_origin(AllowOrigin::mirror_request())
        .allow_headers(vec![HeaderName::from_lowercase(b"content-type").unwrap()])
        .allow_credentials(true);

    let router = Router::new()
        .route("/", get(no_coffee))
        .route("/register", post(register::route))
        .route("/login", post(login::route))
        .route("/auth_test", get(authenticate::route))
        .route("/logout", get(logout::route))
        .layer(cors)
        .with_state(state);

    let addr = var("TARGET_ADDRESS")
        .into_report()
        .change_context(AuthBuildError)
        .attach_printable("Might be the TARGET_ADDRESS env variable")?
        .parse::<SocketAddr>()
        .into_report()
        .change_context(AuthBuildError)?;

    println!("Serving on {}", addr);
    axum::Server::bind(&addr)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .into_report()
        .change_context(AuthBuildError)?;

    Ok(())
}

async fn no_coffee(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Response {
    (StatusCode::IM_A_TEAPOT, addr.to_string()).into_response()
}

#[derive(Clone)]
pub struct AppState {
    key: Key,
    database_connection: DatabaseConnection,
    ip_login_timeout: i64,
    ip_register_timeout: i64,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}
