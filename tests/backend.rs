use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::BodyExt;
use private_vault::{
    api::{self, AppState},
    config::Config,
    db, vault,
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

struct Fixture {
    _directory: TempDir,
    state: Arc<AppState>,
    owner: String,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.sqlite");
        let pool = db::connect(&path, true).await.unwrap();
        db::MIGRATOR.run(&pool).await.unwrap();
        let owner = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO accounts(id) VALUES (?)")
            .bind(&owner)
            .execute(&pool)
            .await
            .unwrap();
        let config = Config {
            database: path,
            bind: "127.0.0.1:8080".parse().unwrap(),
            origin: "https://vault.test".parse().unwrap(),
            rp_id: "vault.test".into(),
        };
        let state = AppState::new(config, pool).unwrap();
        Self {
            _directory: directory,
            state,
            owner,
        }
    }
    fn app(&self) -> Router {
        api::router(self.state.clone())
    }
    async fn session(&self, owner: &str) -> (String, String) {
        let (raw, info) = self.state.memory.lock().await.issue(owner.into()).unwrap();
        (raw, info.csrf_token)
    }
    async fn vault(&self) -> Uuid {
        let id = Uuid::new_v4();
        vault::put_vault(
            &self.state.pool,
            &self.owner,
            vault::PutVault {
                id,
                expected_revision: 0,
                envelope: envelope(),
            },
        )
        .await
        .unwrap();
        id
    }
}
fn envelope() -> vault::Envelope {
    vault::Envelope {
        version: 1,
        salt: URL_SAFE_NO_PAD.encode([1; 16]),
        nonce: URL_SAFE_NO_PAD.encode([2; 24]),
        wrapped_key: URL_SAFE_NO_PAD.encode([3; 48]),
        kdf: vault::Kdf {
            algorithm: "argon2id".into(),
            version: 19,
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        },
    }
}
fn entry(expected: i64) -> vault::PutEntry {
    vault::PutEntry {
        expected_revision: expected,
        ciphertext: URL_SAFE_NO_PAD.encode([4; 32]),
        nonce: URL_SAFE_NO_PAD.encode([5; 24]),
    }
}
fn request(
    method: &str,
    path: &str,
    token: Option<&str>,
    csrf: Option<&str>,
    body: Value,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "vault.test")
        .header("origin", "https://vault.test")
        .header("content-type", "application/json");
    if let Some(raw) = token {
        builder = builder.header("cookie", format!("__Host-session={raw}"));
    }
    if let Some(value) = csrf {
        builder = builder.header("x-csrf-token", value);
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn every_vault_route_requires_authentication() {
    let fixture = Fixture::new().await;
    for (method, path) in [
        ("GET", "/api/v1/vault"),
        ("PUT", "/api/v1/vault"),
        ("DELETE", "/api/v1/vault"),
        ("GET", "/api/v1/entries"),
        (
            "GET",
            "/api/v1/entries/00000000-0000-0000-0000-000000000001",
        ),
        (
            "PUT",
            "/api/v1/entries/00000000-0000-0000-0000-000000000001",
        ),
        (
            "DELETE",
            "/api/v1/entries/00000000-0000-0000-0000-000000000001",
        ),
    ] {
        let response = fixture
            .app()
            .oneshot(request(method, path, None, None, json!({})))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}
#[tokio::test]
async fn browser_mutations_require_origin_and_csrf() {
    let f = Fixture::new().await;
    let (token, csrf) = f.session(&f.owner).await;
    let response = f
        .app()
        .oneshot(request(
            "POST",
            "/api/v1/auth/logout",
            Some(&token),
            None,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let mut wrong_origin = request(
        "POST",
        "/api/v1/auth/logout",
        Some(&token),
        Some(&csrf),
        json!({}),
    );
    wrong_origin
        .headers_mut()
        .insert("origin", "https://evil.test".parse().unwrap());
    assert_eq!(
        f.app().oneshot(wrong_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut no_origin = request(
        "POST",
        "/api/v1/auth/logout",
        Some(&token),
        Some(&csrf),
        json!({}),
    );
    no_origin.headers_mut().remove("origin");
    assert_eq!(
        f.app().oneshot(no_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.app()
            .oneshot(request(
                "POST",
                "/api/v1/auth/logout",
                Some(&token),
                Some(&csrf),
                json!({})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.app()
            .oneshot(request(
                "GET",
                "/api/v1/auth/session",
                Some(&token),
                None,
                json!(null)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn owner_constraints_cover_reads_updates_deletes_and_lists() {
    let f = Fixture::new().await;
    f.vault().await;
    let id = Uuid::new_v4();
    vault::put_entry(&f.state.pool, &f.owner, id, entry(0))
        .await
        .unwrap();
    let intruder = Uuid::new_v4().to_string();
    assert!(vault::get_vault(&f.state.pool, &intruder).await.is_err());
    assert!(vault::get_entry(&f.state.pool, &intruder, id)
        .await
        .is_err());
    assert!(vault::list(&f.state.pool, &intruder, None, 100)
        .await
        .unwrap()
        .is_empty());
    assert!(vault::put_entry(&f.state.pool, &intruder, id, entry(1))
        .await
        .is_err());
    assert!(vault::delete_entry(&f.state.pool, &intruder, id, 1)
        .await
        .is_err());
    assert!(vault::delete_vault(&f.state.pool, &intruder, 1)
        .await
        .is_err());
    // Injection-shaped owner input is treated as an ordinary bound value.
    assert!(vault::get_vault(&f.state.pool, "' OR 1=1 --")
        .await
        .is_err());
    assert_eq!(
        vault::get_entry(&f.state.pool, &f.owner, id)
            .await
            .unwrap()
            .revision,
        1
    );
}
#[tokio::test]
async fn concurrent_writes_have_one_winner_and_tombstones_cannot_be_replayed() {
    let f = Fixture::new().await;
    f.vault().await;
    let id = Uuid::new_v4();
    vault::put_entry(&f.state.pool, &f.owner, id, entry(0))
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        vault::put_entry(&f.state.pool, &f.owner, id, entry(1)),
        vault::put_entry(&f.state.pool, &f.owner, id, entry(1))
    );
    assert_ne!(left.is_ok(), right.is_ok());
    vault::delete_entry(&f.state.pool, &f.owner, id, 2)
        .await
        .unwrap();
    let deleted = vault::get_entry(&f.state.pool, &f.owner, id).await.unwrap();
    assert!(deleted.deleted);
    assert!(deleted.ciphertext.is_empty());
    assert!(vault::put_entry(&f.state.pool, &f.owner, id, entry(0))
        .await
        .is_err());
    assert!(vault::put_entry(&f.state.pool, &f.owner, id, entry(3))
        .await
        .is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_outbox")
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    assert_eq!(count, 4); // vault creation, entry creation, one update, deletion
}
#[tokio::test]
async fn audit_failure_rolls_back_the_entire_write() {
    let f = Fixture::new().await;
    f.vault().await;
    sqlx::query("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_outbox BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        .execute(&f.state.pool).await.unwrap();
    let id = Uuid::new_v4();
    assert!(vault::put_entry(&f.state.pool, &f.owner, id, entry(0))
        .await
        .is_err());
    assert!(vault::get_entry(&f.state.pool, &f.owner, id).await.is_err());
    assert_eq!(
        vault::get_vault(&f.state.pool, &f.owner)
            .await
            .unwrap()
            .sequence,
        1
    );
}
#[tokio::test]
async fn rejects_bad_ciphertext_unknown_fields_and_oversized_requests() {
    let f = Fixture::new().await;
    f.vault().await;
    let id = Uuid::new_v4();
    let mut invalid = entry(0);
    invalid.nonce = "wrong".into();
    assert!(vault::put_entry(&f.state.pool, &f.owner, id, invalid)
        .await
        .is_err());
    let mut bad_envelope = envelope();
    bad_envelope.kdf.memory_kib = u32::MAX;
    assert!(bad_envelope.validate().is_err());
    assert!(serde_json::from_value::<vault::PutEntry>(
        json!({"expected_revision": 0, "ciphertext": "a", "nonce": "b", "password": "plaintext"})
    )
    .is_err());
    let (token, csrf) = f.session(&f.owner).await;
    let response = f.app().oneshot(request("PUT", &format!("/api/v1/entries/{id}"), Some(&token), Some(&csrf),
        json!({"expected_revision": 0, "ciphertext": "a".repeat(300000), "nonce": URL_SAFE_NO_PAD.encode([0;24])}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
#[tokio::test]
async fn health_is_minimal_and_no_session_does_not_leak_data() {
    let f = Fixture::new().await;
    let response = f
        .app()
        .oneshot(request("GET", "/health", None, None, json!(null)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"status": "ok"})
    );
}
#[test]
fn unsafe_network_configuration_is_rejected() {
    let mut c = Config {
        database: PathBuf::from("data/test.sqlite"),
        bind: "0.0.0.0:8080".parse().unwrap(),
        origin: "https://vault.test".parse().unwrap(),
        rp_id: "vault.test".into(),
    };
    assert!(c.validate().is_err());
    c.bind = "127.0.0.1:8080".parse().unwrap();
    assert!(c.validate().is_ok());
    c.origin = "http://vault.test".parse().unwrap();
    assert!(c.validate().is_err());
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}
fn ceremony_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("__Host-ceremony="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn webauthn_bootstrap_login_replay_and_wrong_origin() {
    use private_vault::auth;
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, AuthenticatorBackend};
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};
    let f = Fixture::new().await;
    let bootstrap = auth::token();
    sqlx::query("UPDATE accounts SET enrollment_hash = ?, enrollment_expires = ? WHERE id = ?")
        .bind(auth::digest(&bootstrap))
        .bind(db::now() + 600)
        .bind(&f.owner)
        .execute(&f.state.pool)
        .await
        .unwrap();
    let begin = f
        .app()
        .oneshot(request(
            "POST",
            "/api/v1/auth/bootstrap/begin",
            None,
            None,
            json!({"enrollment_token": bootstrap}),
        ))
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let cookie = ceremony_cookie(&begin);
    let options: CreationChallengeResponse =
        serde_json::from_value(json_body(begin).await["options"].clone()).unwrap();
    // Test-only software authenticator; never included in the production binary.
    let mut authenticator = SoftPasskey::new(true);
    let registration = authenticator
        .perform_register(f.state.config.origin.clone(), options.public_key, 60000)
        .unwrap();
    let encoded = serde_json::to_value(registration).unwrap();
    let mut finish = request(
        "POST",
        "/api/v1/auth/bootstrap/finish",
        None,
        None,
        encoded.clone(),
    );
    finish
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        f.app().oneshot(finish).await.unwrap().status(),
        StatusCode::CREATED
    );
    let mut replay = request("POST", "/api/v1/auth/bootstrap/finish", None, None, encoded);
    replay
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        f.app().oneshot(replay).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let reused = f
        .app()
        .oneshot(request(
            "POST",
            "/api/v1/auth/bootstrap/begin",
            None,
            None,
            json!({"enrollment_token": bootstrap}),
        ))
        .await
        .unwrap();
    assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);

    let begin = f
        .app()
        .oneshot(request(
            "POST",
            "/api/v1/auth/login/begin",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();
    let cookie = ceremony_cookie(&begin);
    let options: RequestChallengeResponse =
        serde_json::from_value(json_body(begin).await["options"].clone()).unwrap();
    let assertion = authenticator
        .perform_auth(f.state.config.origin.clone(), options.public_key, 60000)
        .unwrap();
    let encoded = serde_json::to_value(assertion).unwrap();
    let mut finish = request(
        "POST",
        "/api/v1/auth/login/finish",
        None,
        None,
        encoded.clone(),
    );
    finish
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    let response = f.app().oneshot(finish).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("__Host-session=")));
    assert!(json_body(response).await["csrf_token"].is_string());
    let mut replay = request("POST", "/api/v1/auth/login/finish", None, None, encoded);
    replay
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        f.app().oneshot(replay).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let begin = f
        .app()
        .oneshot(request(
            "POST",
            "/api/v1/auth/login/begin",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();
    let cookie = ceremony_cookie(&begin);
    let options: RequestChallengeResponse =
        serde_json::from_value(json_body(begin).await["options"].clone()).unwrap();
    let assertion = authenticator
        .perform_auth(
            "https://evil.test".parse().unwrap(),
            options.public_key,
            60000,
        )
        .unwrap();
    let mut finish = request(
        "POST",
        "/api/v1/auth/login/finish",
        None,
        None,
        serde_json::to_value(assertion).unwrap(),
    );
    finish
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    assert_eq!(
        f.app().oneshot(finish).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
