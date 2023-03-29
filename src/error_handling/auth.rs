use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use error_stack::{Context, Report};
use std::fmt::Display;

#[derive(Debug)]
pub struct AuthBuildError;
#[derive(Debug)]
pub struct AuthRuntimeError;

impl Context for AuthRuntimeError {}
impl Context for AuthBuildError {}

impl Display for AuthBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Faild to build this auth system!")
    }
}
impl Display for AuthRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Faild to run something within this auth system!")
    }
}

pub struct ErrorResponse<C>(pub Report<C>);

impl<T, C> From<T> for ErrorResponse<C>
where
    T: Into<Report<C>>,
{
    fn from(err: T) -> Self {
        let parsed = err.into();

        println!("{:?}", parsed);

        Self(parsed)
    }
}

impl<T> IntoResponse for ErrorResponse<T> {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}
