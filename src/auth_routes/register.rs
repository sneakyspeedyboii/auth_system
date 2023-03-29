use std::net::SocketAddr;

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, FixedOffset, TimeZone, Utc};
use error_stack::{IntoReport, ResultExt};
use rand_core::OsRng;
use sea_orm::{ActiveModelTrait, ActiveValue::NotSet, ColumnTrait, EntityTrait, QueryFilter, Set};

use serde::{Deserialize, Serialize};

use crate::database::{ip_throttling, users};
use crate::error_handling::auth::{AuthRuntimeError, ErrorResponse};
use crate::AppState;

pub async fn route(
    State(appstate): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
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

            match ip_model.register_reset_time >= current {
                true => {
                    match ip_model.register_attempts >= appstate.ip_register_timeout {
                        true => Ok(StatusCode::FORBIDDEN.into_response()),
                        false => register(appstate, addr, credentials).await,
                    }
                }
                false => {
                    let expiry = current + Duration::days(1);

                    let mut ip_model: ip_throttling::ActiveModel = ip_model.into();

                    ip_model.register_reset_time = Set(expiry);
                    ip_model.register_attempts = Set(0);

                    ip_model.update(&appstate.database_connection).await.into_report().change_context(AuthRuntimeError)?;

                    register(appstate, addr, credentials).await
                },
            }   
        },
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

            register(appstate, addr, credentials).await
        }
    }
}

async fn register(
    appstate: AppState,
    addr: SocketAddr,
    mut credentials: UserCreds,
) -> Result<Response, ErrorResponse<AuthRuntimeError>> {
    match ip_throttling::Entity::find()
        .filter(ip_throttling::Column::Ip.eq(addr.ip().to_string()))
        .one(&appstate.database_connection)
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
                        .one(&appstate.database_connection)
                        .await
                        .into_report()
                        .change_context(AuthRuntimeError)?
                    {
                        None => {
                            let argon = Argon2::default();
                            let salt = SaltString::generate(&mut OsRng);

                            let hash = argon
                                .hash_password(credentials.password.as_bytes(), &salt)
                                .into_report()
                                .change_context(AuthRuntimeError)?;

                            credentials.password = hash.to_string();

                            let offset = FixedOffset::east_opt(3600).unwrap(); //3600 = 1 hour offset
                            let current = offset.timestamp_opt(Utc::now().timestamp(), 0).unwrap();

                            let user_model = users::ActiveModel {
                                id: NotSet,
                                user_id: Set(uuid::Uuid::new_v4()),
                                email: Set(credentials.email),
                                name: Set(credentials.name),
                                password: Set(credentials.password),
                                data: Set(None),
                                created_at: Set(current),
                            };

                            users::Entity::insert(user_model)
                                .exec(&appstate.database_connection)
                                .await
                                .into_report()
                                .change_context(AuthRuntimeError)?;

                            let register_amount = ip_model.register_attempts;
                            let mut ip_model: ip_throttling::ActiveModel = ip_model.into();
                            ip_model.register_attempts = Set(register_amount + 1);

                            ip_model
                                .update(&appstate.database_connection)
                                .await
                                .into_report()
                                .change_context(AuthRuntimeError)?;

                            Ok(StatusCode::CREATED.into_response())
                        }

                        Some(_) => Ok(StatusCode::CONFLICT.into_response()),
                    }
                }
                false => Ok(StatusCode::UNPROCESSABLE_ENTITY.into_response()),
            }
        }
        None => Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserCreds {
    email: String,
    name: String,
    password: String,
}
