use std::str::FromStr;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};

use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use chrono::{FixedOffset, TimeZone};
use error_stack::{Context, Report};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};

use crate::{
    database::{online_users, users},
    error_handling::auth::AuthRuntimeError,
    AppState,
};

pub async fn route(Authenticate(_user_model): Authenticate) -> StatusCode {
    StatusCode::OK
}

pub struct Authenticate(pub users::Model);

#[axum::async_trait]
impl<S> FromRequestParts<S> for Authenticate
where
    S: Send + Sync,
    AppState: FromRef<S>,
    Key: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let appstate = AppState::from_ref(state);

        let jar = PrivateCookieJar::<Key>::from_request_parts(parts, state)
            .await
            .unwrap();

        match jar.get("session") {
            Some(mut cookie) => match uuid::Uuid::from_str(cookie.value()) {
                Ok(uuid) => match online_users::Entity::find()
                    .filter(online_users::Column::CookieId.eq(uuid))
                    .one(&appstate.database_connection)
                    .await
                {
                    Ok(option_online_user_model) => match option_online_user_model {
                        Some(online_user_model) => {
                            let offset = FixedOffset::east_opt(3600).unwrap(); //3600 = 1 hour offset
                            let current = offset
                                .timestamp_opt(chrono::Utc::now().timestamp(), 0)
                                .unwrap();

                            match online_user_model.expires_at <= current {
                                false => {
                                    match users::Entity::find()
                                        .filter(users::Column::UserId.eq(online_user_model.user_id))
                                        .one(&appstate.database_connection)
                                        .await
                                    {
                                        Ok(option_user_model) => match option_user_model {
                                            Some(user_model) => Ok(Authenticate(user_model)),
                                            None => {
                                                println!("USER NOT FOUND IN DATABASE SOMETHING BROKE OR SOMEONE MODIFED USER ID IN THE TABLE ITSELF IDK");
                                                Err(StatusCode::INTERNAL_SERVER_ERROR
                                                    .into_response())
                                            }
                                        },
                                        Err(error) => Err(error_to_response(error)),
                                    }
                                }
                                true => {
                                    match online_user_model
                                        .delete(&appstate.database_connection)
                                        .await
                                    {
                                        Ok(_) => {
                                            cookie.set_path("/");

                                            Err((jar.remove(cookie), StatusCode::UNAUTHORIZED).into_response())
                                        }
                                        Err(error) => Err(error_to_response(error)),
                                    }
                                }
                            }
                        }
                        None => {
                            cookie.set_path("/"); 

                            Err((jar.remove(cookie), StatusCode::UNAUTHORIZED).into_response())
                        }
                    },
                    Err(error) => Err(error_to_response(error)),
                },
                Err(error) => Err(error_to_response(error)),
            },
            None => Err(StatusCode::NOT_FOUND.into_response()),
        }
    }
}

fn error_to_response<C: Context>(error: C) -> Response {
    let report = Report::from(error).change_context(AuthRuntimeError);
    println!("{:?}", report);
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
