use std::{net::SocketAddr, str::FromStr};

use argon2::{
    password_hash::errors::Error as PasswordError, Argon2, PasswordHash, PasswordVerifier,
};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::{
    cookie::{Cookie, Expiration},
    PrivateCookieJar,
};
use chrono::{Duration, FixedOffset, TimeZone};
use error_stack::{IntoReport, Report, ResultExt};
use sea_orm::{
    ActiveModelTrait, ActiveValue::NotSet, ColumnTrait, DatabaseConnection, EntityTrait,
    IntoActiveModel, ModelTrait, QueryFilter, Set,
};
use serde::{Deserialize, Serialize};

use crate::database::{ip_throttling, online_users, users};
use crate::error_handling::auth::{AuthRuntimeError, ErrorResponse};
use crate::AppState;

pub async fn route(
    State(appstate): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: PrivateCookieJar,
    Json(credentials): Json<UserCreds>,
) -> Result<Response, ErrorResponse<AuthRuntimeError>> {
    match ip_throttling::Entity::find()
        .filter(ip_throttling::Column::Ip.eq(addr.ip().to_string()))
        .one(&appstate.database_connection)
        .await
        .into_report()
        .change_context(AuthRuntimeError)?
    {
        Some(ip_model) => {
            let offset = FixedOffset::east_opt(3600).unwrap(); //3600 = 1 hour offset
            let current = offset
                .timestamp_opt(chrono::Utc::now().timestamp(), 0)
                .unwrap();

            match ip_model.login_reset_time >= current {
                true => match ip_model.login_attempts >= appstate.ip_login_timeout {
                    true => Ok(StatusCode::FORBIDDEN.into_response()),
                    false => cookie_check(appstate, jar, credentials, addr).await,
                },
                false => {
                    let expiry = current + Duration::days(1);

                    let mut ip_model: ip_throttling::ActiveModel = ip_model.into();

                    ip_model.login_reset_time = Set(expiry);
                    ip_model.login_attempts = Set(0);

                    ip_model
                        .update(&appstate.database_connection)
                        .await
                        .into_report()
                        .change_context(AuthRuntimeError)?;

                    cookie_check(appstate, jar, credentials, addr).await
                }
            }
        }
        None => {
            let offset = FixedOffset::east_opt(3600).unwrap(); //3600 = 1 hour offset
            let current = offset
                .timestamp_opt(chrono::Utc::now().timestamp(), 0)
                .unwrap();

            let expiry = current + Duration::days(1);

            let ip_model = ip_throttling::ActiveModel {
                id: NotSet,
                ip: Set(addr.ip().to_string()),
                login_attempts: Set(0),
                register_attempts: Set(0),
                register_reset_time: Set(expiry),
                login_reset_time: Set(expiry),
            };

            ip_throttling::Entity::insert(ip_model)
                .exec(&appstate.database_connection)
                .await
                .into_report()
                .change_context(AuthRuntimeError)?;

            cookie_check(appstate, jar, credentials, addr).await
        }
    }
}

async fn cookie_check(
    appstate: AppState,
    jar: PrivateCookieJar,
    credentials: UserCreds,
    addr: SocketAddr,
) -> Result<Response, ErrorResponse<AuthRuntimeError>> {
    match jar.get("session") {
        Some(mut cookie) => {
            let uuid = uuid::Uuid::from_str(cookie.value())
                .into_report()
                .change_context(AuthRuntimeError)?;

            match online_users::Entity::find()
                .filter(online_users::Column::CookieId.eq(uuid))
                .one(&appstate.database_connection)
                .await
                .into_report()
                .change_context(AuthRuntimeError)?
            {
                Some(online_user_model) => {
                    let offset = FixedOffset::east_opt(3600).unwrap(); //3600 = 1 hour offset
                    let current = offset
                        .timestamp_opt(chrono::Utc::now().timestamp(), 0)
                        .unwrap();

                    match online_user_model.expires_at <= current {
                        false => Ok(StatusCode::OK.into_response()),
                        true => {
                            online_user_model
                                .delete(&appstate.database_connection)
                                .await
                                .into_report()
                                .change_context(AuthRuntimeError)?;

                            cookie.set_path("/");

                            credential_login(
                                credentials,
                                appstate.database_connection,
                                jar.remove(cookie),
                                addr,
                            )
                            .await
                        }
                    }
                }
                None => {
                    cookie.set_path("/");

                    credential_login(
                        credentials,
                        appstate.database_connection,
                        jar.remove(cookie),
                        addr,
                    )
                    .await
                }
            }
        }
        None => credential_login(credentials, appstate.database_connection, jar, addr).await,
    }
}

async fn credential_login(
    mut credentials: UserCreds,
    database_connection: DatabaseConnection,
    jar: PrivateCookieJar,
    addr: SocketAddr,
) -> Result<Response, ErrorResponse<AuthRuntimeError>> {
    match ip_throttling::Entity::find()
        .filter(ip_throttling::Column::Ip.eq(addr.ip().to_string()))
        .one(&database_connection)
        .await
        .into_report()
        .change_context(AuthRuntimeError)?
    {
        Some(ip_model) => {
            credentials.email = credentials.email.trim().to_lowercase();

            let regex =
                regex::Regex::new(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$").unwrap();

            match regex.is_match(&credentials.email) {
                true => {
                    match users::Entity::find()
                        .filter(users::Column::Email.eq(&credentials.email))
                        .one(&database_connection)
                        .await
                        .into_report()
                        .change_context(AuthRuntimeError)?
                    {
                        Some(user_model) => {
                            let argon = Argon2::default();

                            let hash = PasswordHash::new(&user_model.password)
                                .into_report()
                                .change_context(AuthRuntimeError)?;

                            match argon.verify_password(credentials.password.as_bytes(), &hash) {
                                Ok(_) => {
                                    match online_users::Entity::find()
                                        .filter(online_users::Column::UserId.eq(user_model.user_id))
                                        .one(&database_connection)
                                        .await
                                        .into_report()
                                        .change_context(AuthRuntimeError)?
                                    {
                                        Some(online_user_model) => {
                                            online_users::Entity::delete(
                                                online_user_model.into_active_model(),
                                            )
                                            .exec(&database_connection)
                                            .await
                                            .into_report()
                                            .change_context(AuthRuntimeError)?;

                                            insert_cookie(database_connection, jar, user_model)
                                                .await
                                        }
                                        None => {
                                            insert_cookie(database_connection, jar, user_model)
                                                .await
                                        }
                                    }
                                }
                                Err(error) => {
                                    if error == PasswordError::Password {
                                        login_attempt_increment(ip_model, database_connection)
                                            .await?;
                                        Ok((jar, StatusCode::UNAUTHORIZED).into_response())
                                    } else {
                                        Err(ErrorResponse(
                                            Report::from(error).change_context(AuthRuntimeError),
                                        ))
                                    }
                                }
                            }
                        }
                        None => {
                            login_attempt_increment(ip_model, database_connection).await?;
                            Ok((jar, StatusCode::NOT_FOUND).into_response())
                        }
                    }
                }
                false => Ok((jar, StatusCode::UNPROCESSABLE_ENTITY).into_response()),
            }
        }
        None => Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    }
}

async fn login_attempt_increment(
    model: ip_throttling::Model,
    database_connection: DatabaseConnection,
) -> Result<(), ErrorResponse<AuthRuntimeError>> {
    let login_amount = model.login_attempts;
    let mut ip_model: ip_throttling::ActiveModel = model.into();
    ip_model.login_attempts = Set(login_amount + 1);

    ip_model
        .update(&database_connection)
        .await
        .into_report()
        .change_context(AuthRuntimeError)?;

    Ok(())
}

async fn insert_cookie(
    database_connection: DatabaseConnection,
    jar: PrivateCookieJar,
    user_model: users::Model,
) -> Result<Response, ErrorResponse<AuthRuntimeError>> {
    let token = uuid::Uuid::new_v4();

    let offset = FixedOffset::east_opt(3600).unwrap(); //3600 = 1 hour offset
    let current = offset
        .timestamp_opt(chrono::Utc::now().timestamp(), 0)
        .unwrap();

    let expiry = current + Duration::days(1);

    let token_model = online_users::ActiveModel {
        id: NotSet,
        user_id: Set(user_model.user_id),
        cookie_id: Set(token),
        expires_at: Set(expiry),
    };

    online_users::Entity::insert(token_model)
        .exec(&database_connection)
        .await
        .into_report()
        .change_context(AuthRuntimeError)?;

    let mut cookie = Cookie::new("session", token.to_string());

    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_path("/");

    let expiry: time::OffsetDateTime =
        time::OffsetDateTime::from_unix_timestamp(expiry.timestamp())
            .into_report()
            .change_context(AuthRuntimeError)?;

    cookie.set_expires(Expiration::DateTime(expiry));

    Ok(jar.add(cookie).into_response())
}

#[derive(Serialize, Deserialize)]
pub struct UserCreds {
    email: String,
    password: String,
}
