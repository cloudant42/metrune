use axum::{
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use metrune_core::release::{ClientUnsupportedResponse, CLIENT_UNSUPPORTED_ERROR_CODE};
use sha2::{Digest, Sha256};

pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::unauthorized("missing bearer token"))
}

pub(crate) fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    message: String,
    code: Option<&'static str>,
    minimum_client_version: Option<String>,
}

impl ApiError {
    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub(crate) fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }

    pub(crate) fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    pub(crate) fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, message)
    }

    pub(crate) fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    pub(crate) fn client_unsupported(
        message: impl Into<String>,
        minimum_client_version: Option<String>,
    ) -> Self {
        Self {
            status: StatusCode::UPGRADE_REQUIRED,
            message: message.into(),
            code: Some(CLIENT_UNSUPPORTED_ERROR_CODE),
            minimum_client_version,
        }
    }

    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code: None,
            minimum_client_version: None,
        }
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(error: E) -> Self {
        tracing::error!(
            error = %format!("{:#}", error),
            error_type = std::any::type_name::<E>(),
            "request failed with an internal error"
        );
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = match self.code {
            Some(code) => serde_json::to_value(ClientUnsupportedResponse {
                error: self.message,
                code: code.into(),
                minimum_client_version: self.minimum_client_version,
            })
            .expect("serialize the compatibility error contract"),
            None => serde_json::json!({"error": self.message}),
        };
        (self.status, Json(body)).into_response()
    }
}
