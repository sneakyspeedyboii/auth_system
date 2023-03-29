use std::str::FromStr;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::PrivateCookieJar;
use error_stack::{IntoReport, ResultExt};
use sea_orm::{ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter};

use crate::database::online_users;
use crate::error_handling::auth::{AuthRuntimeError, ErrorResponse};
use crate::AppState;

pub async fn route(
    State(appstate): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<Response, ErrorResponse<AuthRuntimeError>> {
    match jar.get("session") {
        Some(mut cookie) => {
            match online_users::Entity::find()
                .filter(
                    online_users::Column::CookieId.eq(uuid::Uuid::from_str(cookie.value())
                        .into_report()
                        .change_context(AuthRuntimeError)?),
                )
                .one(&appstate.database_connection)
                .await
                .into_report()
                .change_context(AuthRuntimeError)?
            {
                Some(online_user_model) => {
                    online_users::Entity::delete(online_user_model.into_active_model())
                        .exec(&appstate.database_connection)
                        .await
                        .into_report()
                        .change_context(AuthRuntimeError)?;
                    cookie.set_path("/");
                    Ok((jar.remove(cookie), StatusCode::OK).into_response())
                }
                None => {
                    cookie.set_path("/");
                    Ok((jar.remove(cookie), StatusCode::NOT_FOUND).into_response())
                }
            }
        }
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}
