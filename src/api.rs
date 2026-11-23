use crate::{
    auth::{self, AuthContext, FlowKind, Memory, RegistrationAuthority, SessionInfo},
    config::Config,
    db,
    error::{ApiError, Result},
    vault,
};
use axum::{
    extract::{DefaultBodyLimit, Extension, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;
use webauthn_rs::{
    prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential},
    Webauthn, WebauthnBuilder,
};

pub struct AppState {
    pub pool: SqlitePool,
    pub config: Config,
    pub memory: Mutex<Memory>,
    webauthn: Webauthn,
    requests: Mutex<VecDeque<Instant>>,
    slots: Semaphore,
    health_slots: Semaphore,
}
impl AppState {
    pub fn new(config: Config, pool: SqlitePool) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.origin)?
            .rp_name("Private Vault")
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(Duration::from_secs(180))
            .build()?;
        Ok(Arc::new(Self {
            config,
            pool,
            webauthn,
            memory: Mutex::new(Memory::default()),
            requests: Mutex::new(VecDeque::new()),
            slots: Semaphore::new(32),
            health_slots: Semaphore::new(2),
        }))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/v1/auth/session", get(session))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/credentials", get(credentials))
        .route(
            "/api/v1/auth/credentials/{id}",
            axum::routing::delete(remove_credential),
        )
        .route("/api/v1/auth/register/begin", post(register_begin))
        .route("/api/v1/auth/register/finish", post(register_finish))
        .route(
            "/api/v1/vault",
            get(get_vault).put(put_vault).delete(delete_vault),
        )
        .route("/api/v1/entries", get(list_entries))
        .route(
            "/api/v1/entries/{id}",
            get(get_entry).put(put_entry).delete(delete_entry),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Router::new()
        .merge(protected)
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route("/api/v1/auth/login/begin", post(login_begin))
        .route("/api/v1/auth/login/finish", post(login_finish))
        .route("/api/v1/auth/bootstrap/begin", post(bootstrap_begin))
        .route("/api/v1/auth/bootstrap/finish", post(bootstrap_finish))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}

fn one_cookie(headers: &HeaderMap, name: &str) -> Result<String> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE).iter() {
        for part in value.to_str().map_err(|_| ApiError::invalid())?.split(';') {
            if let Some((key, value)) = part.trim().split_once('=') {
                if key == name {
                    if found.is_some() {
                        return Err(ApiError::invalid());
                    }
                    found = Some(value.to_owned());
                }
            }
        }
    }
    found.ok_or_else(ApiError::unauthorized)
}
fn set_cookie(response: &mut Response, value: String) -> Result<()> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value).map_err(|_| ApiError::internal())?,
    );
    Ok(())
}
async fn boundary(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let result = async {
        // The reverse proxy preserves Host; forwarded headers are never authentication inputs.
        let expected = state
            .config
            .origin_string()
            .trim_start_matches("https://")
            .to_owned();
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok());
        if host != Some(expected.as_str()) {
            return Err(ApiError::forbidden());
        }
        if let Some(origin) = request.headers().get(header::ORIGIN) {
            if origin.to_str().ok() != Some(state.config.origin_string().as_str()) {
                return Err(ApiError::forbidden());
            }
        } else if !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) {
            return Err(ApiError::forbidden());
        }
        if request
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|v| v != "same-origin" && v != "none")
        {
            return Err(ApiError::forbidden());
        }
        // Health has a small independent budget so stalled database requests cannot
        // consume all liveness capacity. Health still passes Host/Origin validation.
        let slots = if request.uri().path() == "/health" {
            &state.health_slots
        } else {
            &state.slots
        };
        let _permit = slots.try_acquire().map_err(|_| ApiError::busy())?;
        if request.uri().path() != "/health" {
            let mut requests = state.requests.lock().await;
            while requests
                .front()
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(60))
            {
                requests.pop_front();
            }
            if requests.len() >= 240 {
                return Err(ApiError::limited());
            }
            requests.push_back(Instant::now());
        }
        tokio::time::timeout(Duration::from_secs(10), next.run(request))
            .await
            .map_err(|_| ApiError::busy())
    }
    .await;
    let mut response = match result {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    response
}
async fn authenticate(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    let raw = one_cookie(request.headers(), auth::COOKIE)?;
    let context = state.memory.lock().await.authenticate(&raw)?;
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        let csrf = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::forbidden)?;
        if !auth::same_secret(csrf, &context.session.csrf) {
            return Err(ApiError::forbidden());
        }
    }
    request.extensions_mut().insert(context);
    Ok(next.run(request).await)
}
async fn session(Extension(auth): Extension<AuthContext>) -> Json<SessionInfo> {
    Json(SessionInfo {
        owner: auth.session.owner,
        csrf_token: auth.session.csrf,
    })
}
async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Response> {
    // Revoke before the audit attempt, even if persistence fails.
    state.memory.lock().await.revoke(&auth.key);
    let result = auth::record_event(&state.pool, "session.logout", &auth.session.owner).await;
    let mut response = match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    };
    set_cookie(&mut response, auth::cookie(auth::COOKIE, "", 0))?;
    Ok(response)
}

#[derive(Serialize)]
struct Begin {
    options: Value,
}
async fn begin_response(options: impl Serialize, flow: String) -> Result<Response> {
    let mut response = Json(Begin {
        options: serde_json::to_value(options)?,
    })
    .into_response();
    set_cookie(&mut response, auth::cookie(auth::FLOW_COOKIE, &flow, 180))?;
    Ok(response)
}
async fn login_begin(State(state): State<Arc<AppState>>) -> Result<Response> {
    state.memory.lock().await.throttle_auth()?;
    let owner = db::account(&state.pool).await?;
    let passkeys = auth::passkeys(&state.pool, &owner).await?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized());
    }
    let (options, ceremony) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError::unauthorized())?;
    let flow = state
        .memory
        .lock()
        .await
        .put_flow(owner, FlowKind::Login(ceremony))?;
    begin_response(options, flow).await
}
async fn login_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<PublicKeyCredential>,
) -> Result<Response> {
    let raw = one_cookie(&headers, auth::FLOW_COOKIE)?;
    let mut memory = state.memory.lock().await;
    memory.throttle_auth()?;
    let flow = memory.take_flow(&raw)?; // Consume before verification, including failed attempts.
    let FlowKind::Login(ceremony) = flow.kind else {
        return Err(ApiError::unauthorized());
    };
    let result = state
        .webauthn
        .finish_passkey_authentication(&input, &ceremony)
        .map_err(|_| ApiError::unauthorized())?;
    if !result.user_verified() {
        return Err(ApiError::unauthorized());
    }
    let mut tx = state.pool.begin().await?;
    let id = URL_SAFE_NO_PAD.encode(result.cred_id());
    let encoded: String =
        sqlx::query_scalar("SELECT passkey FROM credentials WHERE owner = ? AND id = ?")
            .bind(&flow.owner)
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
    let mut passkey: Passkey = serde_json::from_str(&encoded)?;
    passkey
        .update_credential(&result)
        .ok_or_else(ApiError::unauthorized)?;
    sqlx::query("UPDATE credentials SET passkey = ? WHERE owner = ? AND id = ?")
        .bind(serde_json::to_string(&passkey)?)
        .bind(&flow.owner)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    db::audit(&mut tx, "session.login", &flow.owner, None).await?;
    tx.commit().await?;
    // Rotate an existing browser session rather than retaining its token or authentication age.
    if let Ok(old) = one_cookie(&headers, auth::COOKIE) {
        memory.revoke(&auth::digest(&old));
    }
    let (token, info) = memory.issue(flow.owner)?;
    let mut response = Json(info).into_response();
    set_cookie(
        &mut response,
        auth::cookie(auth::COOKIE, &token, 8 * 60 * 60),
    )?;
    set_cookie(&mut response, auth::cookie(auth::FLOW_COOKIE, "", 0))?;
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    enrollment_token: String,
}
async fn bootstrap_begin(
    State(state): State<Arc<AppState>>,
    Json(input): Json<Bootstrap>,
) -> Result<Response> {
    state.memory.lock().await.throttle_auth()?;
    if !auth::valid_token(&input.enrollment_token) {
        return Err(ApiError::unauthorized());
    }
    let hash = auth::digest(&input.enrollment_token);
    let owner: String = sqlx::query_scalar(
        "SELECT id FROM accounts WHERE enrollment_hash = ? AND enrollment_expires > ?",
    )
    .bind(&hash)
    .bind(db::now())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    start_registration(
        &state,
        owner,
        RegistrationAuthority::Bootstrap {
            enrollment_hash: hash,
        },
    )
    .await
}
async fn register_begin(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Response> {
    auth.session.fresh()?;
    state.memory.lock().await.throttle_auth()?;
    start_registration(
        &state,
        auth.session.owner,
        RegistrationAuthority::Session {
            session_key: auth.key,
        },
    )
    .await
}
async fn start_registration(
    state: &AppState,
    owner: String,
    authority: RegistrationAuthority,
) -> Result<Response> {
    let keys = auth::passkeys(&state.pool, &owner).await?;
    if keys.len() >= 16 {
        return Err(ApiError::limited());
    }
    let exclude = Some(keys.iter().map(|p| p.cred_id().clone()).collect());
    let (options, ceremony) = state
        .webauthn
        .start_passkey_registration(
            Uuid::parse_str(&owner).map_err(|_| ApiError::internal())?,
            "owner",
            "Vault owner",
            exclude,
        )
        .map_err(|_| ApiError::invalid())?;
    let flow = state.memory.lock().await.put_flow(
        owner,
        FlowKind::Registration {
            state: ceremony,
            authority,
        },
    )?;
    begin_response(options, flow).await
}
async fn bootstrap_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<RegisterPublicKeyCredential>,
) -> Result<Response> {
    finish_registration(&state, headers, input, None).await
}
async fn register_finish(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(input): Json<RegisterPublicKeyCredential>,
) -> Result<Response> {
    finish_registration(&state, headers, input, Some(auth)).await
}
async fn finish_registration(
    state: &AppState,
    headers: HeaderMap,
    input: RegisterPublicKeyCredential,
    auth: Option<AuthContext>,
) -> Result<Response> {
    let raw = one_cookie(&headers, auth::FLOW_COOKIE)?;
    let mut memory = state.memory.lock().await;
    memory.throttle_auth()?;
    let flow = memory.take_flow(&raw)?;
    let FlowKind::Registration {
        state: ceremony,
        authority,
    } = flow.kind
    else {
        return Err(ApiError::unauthorized());
    };
    match (&authority, &auth) {
        (RegistrationAuthority::Bootstrap { .. }, None) => (),
        (RegistrationAuthority::Session { session_key }, Some(context))
            if session_key == &context.key && flow.owner == context.session.owner =>
        {
            memory.session_is_fresh(session_key, &flow.owner)?;
        }
        _ => return Err(ApiError::forbidden()),
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(&input, &ceremony)
        .map_err(|_| ApiError::unauthorized())?;
    let mut tx = state.pool.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials WHERE owner = ?")
        .bind(&flow.owner)
        .fetch_one(&mut *tx)
        .await?;
    if count >= 16 {
        return Err(ApiError::limited());
    }
    if let RegistrationAuthority::Bootstrap { enrollment_hash } = authority {
        let consumed = sqlx::query("UPDATE accounts SET enrollment_hash = NULL, enrollment_expires = NULL WHERE id = ? AND enrollment_hash = ? AND enrollment_expires > ?")
            .bind(&flow.owner).bind(enrollment_hash).bind(db::now()).execute(&mut *tx).await?.rows_affected();
        if consumed != 1 {
            return Err(ApiError::unauthorized());
        }
    }
    let credential_bytes: &[u8] = passkey.cred_id().as_ref();
    let id = URL_SAFE_NO_PAD.encode(credential_bytes);
    sqlx::query("INSERT INTO credentials(id, owner, passkey) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(&flow.owner)
        .bind(serde_json::to_string(&passkey)?)
        .execute(&mut *tx)
        .await?;
    db::audit(&mut tx, "credential.add", &id, None).await?;
    tx.commit().await?;
    let mut response = StatusCode::CREATED.into_response();
    set_cookie(&mut response, auth::cookie(auth::FLOW_COOKIE, "", 0))?;
    Ok(response)
}
async fn credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<String>>> {
    Ok(Json(
        sqlx::query_scalar("SELECT id FROM credentials WHERE owner = ? ORDER BY id")
            .bind(auth.session.owner)
            .fetch_all(&state.pool)
            .await?,
    ))
}
async fn remove_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    auth.session.fresh()?;
    if id.len() > 2048 {
        return Err(ApiError::invalid());
    }
    // Serialize against in-flight ceremonies and session issuance.
    let mut memory = state.memory.lock().await;
    memory.session_is_fresh(&auth.key, &auth.session.owner)?;
    let mut tx = state.pool.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials WHERE owner = ?")
        .bind(&auth.session.owner)
        .fetch_one(&mut *tx)
        .await?;
    if count <= 1 {
        return Err(ApiError::forbidden());
    }
    let deleted = sqlx::query("DELETE FROM credentials WHERE owner = ? AND id = ?")
        .bind(&auth.session.owner)
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ApiError::missing());
    }
    db::audit(&mut tx, "credential.remove", &id, None).await?;
    tx.commit().await?;
    // Revoking all sessions/flows prevents reuse of assertions for the removed credential.
    *memory = Memory::default();
    Ok(StatusCode::NO_CONTENT)
}

async fn get_vault(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
) -> Result<Json<vault::Vault>> {
    Ok(Json(vault::get_vault(&s.pool, &a.session.owner).await?))
}
async fn put_vault(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
    Json(input): Json<vault::PutVault>,
) -> Result<Json<vault::Mutation>> {
    a.session.fresh()?;
    Ok(Json(
        vault::put_vault(&s.pool, &a.session.owner, input).await?,
    ))
}
async fn delete_vault(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
    Json(input): Json<vault::Delete>,
) -> Result<Json<vault::Mutation>> {
    a.session.fresh()?;
    Ok(Json(
        vault::delete_vault(&s.pool, &a.session.owner, input.expected_revision).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
    #[serde(default = "page_size")]
    limit: u32,
}
fn page_size() -> u32 {
    100
}
async fn list_entries(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
    Query(p): Query<Page>,
) -> Result<Json<Vec<vault::Entry>>> {
    Ok(Json(
        vault::list(&s.pool, &a.session.owner, p.after, p.limit).await?,
    ))
}
async fn get_entry(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<vault::Entry>> {
    Ok(Json(vault::get_entry(&s.pool, &a.session.owner, id).await?))
}
async fn put_entry(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(input): Json<vault::PutEntry>,
) -> Result<Json<vault::Mutation>> {
    Ok(Json(
        vault::put_entry(&s.pool, &a.session.owner, id, input).await?,
    ))
}
async fn delete_entry(
    State(s): State<Arc<AppState>>,
    Extension(a): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(input): Json<vault::Delete>,
) -> Result<Json<vault::Mutation>> {
    Ok(Json(
        vault::delete_entry(&s.pool, &a.session.owner, id, input.expected_revision).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_session_cookies_are_rejected() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-session=a; __Host-session=b"),
        );
        assert!(one_cookie(&h, auth::COOKIE).is_err());
    }
}
