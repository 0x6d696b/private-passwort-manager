use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);
pub type Result<T> = std::result::Result<T, ApiError>;

impl ApiError {
    pub fn invalid() -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid request")
    }
    pub fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "authentication required")
    }
    pub fn forbidden() -> Self {
        Self(StatusCode::FORBIDDEN, "request forbidden")
    }
    pub fn missing() -> Self {
        Self(StatusCode::NOT_FOUND, "not found")
    }
    pub fn conflict() -> Self {
        Self(StatusCode::CONFLICT, "revision conflict")
    }
    pub fn busy() -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
    }
    pub fn limited() -> Self {
        Self(StatusCode::TOO_MANY_REQUESTS, "request limit exceeded")
    }
    pub fn internal() -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        // Never emit SQL, bound values, or database paths to logs/responses.
        match &error {
            sqlx::Error::Database(e) if e.is_unique_violation() => Self::conflict(),
            sqlx::Error::Database(e) if sqlite_storage_unavailable(e.as_ref()) => {
                tracing::warn!("database storage unavailable");
                Self::busy()
            }
            sqlx::Error::PoolTimedOut => Self::busy(),
            _ => {
                tracing::error!("database operation failed");
                Self::internal()
            }
        }
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self::internal()
    }
}

fn sqlite_storage_unavailable(error: &dyn sqlx::error::DatabaseError) -> bool {
    // SQLite extended codes retain the primary result in their lowest eight bits.
    // Never expose database messages (which can contain SQL/values) to clients.
    matches!(
        error
            .code()
            .and_then(|code| code.parse::<i32>().ok())
            .map(|code| code & 0xff),
        Some(5 | 6 | 8 | 10 | 13) // BUSY, LOCKED, READONLY, IOERR, FULL
    )
}
