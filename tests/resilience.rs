//! Fault injection uses temporary databases; it never fills the host filesystem.
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
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio::{sync::Barrier, task::JoinSet};
use tower::ServiceExt;
use uuid::Uuid;

struct Fixture {
    state: Arc<AppState>,
    owner: String,
    _directory: TempDir,
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
        vault::put_vault(
            &state.pool,
            &owner,
            vault::PutVault {
                id: Uuid::new_v4(),
                expected_revision: 0,
                envelope: vault::Envelope {
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
                },
            },
        )
        .await
        .unwrap();
        Self {
            state,
            owner,
            _directory: directory,
        }
    }
    fn app(&self) -> Router {
        api::router(self.state.clone())
    }
    async fn session(&self) -> (String, String) {
        let (token, info) = self
            .state
            .memory
            .lock()
            .await
            .issue(self.owner.clone())
            .unwrap();
        (token, info.csrf_token)
    }
    async fn audit_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_outbox")
            .fetch_one(&self.state.pool)
            .await
            .unwrap()
    }
    async fn integrity(&self) {
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
                .fetch_one(&self.state.pool)
                .await
                .unwrap(),
            "ok"
        );
        assert!(sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&self.state.pool)
            .await
            .unwrap()
            .is_empty());
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
    if let Some(token) = token {
        builder = builder.header("cookie", format!("__Host-session={token}"));
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}
fn entry(revision: i64, bytes: usize) -> vault::PutEntry {
    vault::PutEntry {
        expected_revision: revision,
        ciphertext: URL_SAFE_NO_PAD.encode(vec![4; bytes]),
        nonce: URL_SAFE_NO_PAD.encode([5; 24]),
    }
}
fn body(revision: i64, bytes: usize) -> Value {
    let input = entry(revision, bytes);
    json!({"expected_revision":input.expected_revision,"ciphertext":input.ciphertext,"nonce":input.nonce})
}

#[tokio::test]
async fn sqlite_full_rolls_back_and_recovers_after_space_is_available() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    vault::put_entry(&f.state.pool, &f.owner, id, entry(0, 32))
        .await
        .unwrap();
    let before = f.audit_count().await;
    let sequence = vault::get_vault(&f.state.pool, &f.owner)
        .await
        .unwrap()
        .sequence;
    let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(&f.state.pool)
        .await
        .unwrap();
    sqlx::query(&format!("PRAGMA max_page_count={pages}"))
        .execute(&f.state.pool)
        .await
        .unwrap();
    // Verify this is a genuine SQLite FULL result, not a mocked application error.
    let error = sqlx::query("CREATE TABLE capacity_probe (payload BLOB); INSERT INTO capacity_probe VALUES (zeroblob(1048576))")
        .execute(&f.state.pool).await.unwrap_err();
    let code: i32 = error
        .as_database_error()
        .unwrap()
        .code()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(code & 0xff, 13);
    let (token, csrf) = f.session().await;
    let response = f
        .app()
        .oneshot(request(
            "PUT",
            &format!("/api/v1/entries/{id}"),
            Some(&token),
            Some(&csrf),
            body(1, 65536),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let message = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&message).unwrap(),
        json!({"error":"temporarily unavailable"})
    );
    assert_eq!(
        vault::get_entry(&f.state.pool, &f.owner, id)
            .await
            .unwrap()
            .revision,
        1
    );
    assert_eq!(f.audit_count().await, before);
    assert_eq!(
        vault::get_vault(&f.state.pool, &f.owner)
            .await
            .unwrap()
            .sequence,
        sequence
    );
    f.integrity().await;
    sqlx::query("PRAGMA max_page_count=1000000")
        .execute(&f.state.pool)
        .await
        .unwrap();
    vault::put_entry(&f.state.pool, &f.owner, id, entry(1, 65536))
        .await
        .unwrap();
    assert_eq!(f.audit_count().await, before + 1);
    f.integrity().await;
}

#[tokio::test]
async fn read_only_storage_rejects_writes_without_mutating_records_or_audit() {
    let f = Fixture::new().await;
    let before = f.audit_count().await;
    sqlx::query("PRAGMA query_only=ON")
        .execute(&f.state.pool)
        .await
        .unwrap();
    let error = vault::put_entry(&f.state.pool, &f.owner, Uuid::new_v4(), entry(0, 32))
        .await
        .err()
        .unwrap();
    assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.audit_count().await, before);
    sqlx::query("PRAGMA query_only=OFF")
        .execute(&f.state.pool)
        .await
        .unwrap();
    assert!(vault::list(&f.state.pool, &f.owner, None, 100)
        .await
        .unwrap()
        .is_empty());
    f.integrity().await;
}

#[tokio::test]
async fn rate_limit_never_turns_anonymous_requests_into_authorized_access() {
    let f = Fixture::new().await;
    for _ in 0..240 {
        let response = f
            .app()
            .oneshot(request("GET", "/api/v1/vault", None, None, json!(null)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for _ in 0..32 {
        let response = f
            .app()
            .oneshot(request("GET", "/api/v1/vault", None, None, json!(null)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(
        f.app()
            .oneshot(request("GET", "/health", None, None, json!(null)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(f.audit_count().await, 1);
}

#[tokio::test]
async fn saturated_api_rejects_excess_work_and_reserves_health_capacity() {
    let f = Fixture::new().await;
    let (token, _) = f.session().await;
    let connection = f.state.pool.acquire().await.unwrap(); // Keep all database reads waiting.
    let barrier = Arc::new(Barrier::new(65));
    let mut tasks = JoinSet::new();
    for _ in 0..64 {
        let app = f.app();
        let token = token.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            app.oneshot(request(
                "GET",
                "/api/v1/vault",
                Some(&token),
                None,
                json!(null),
            ))
            .await
            .unwrap()
            .status()
        });
    }
    barrier.wait().await;
    let rejected = tokio::time::timeout(Duration::from_secs(2), tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(rejected, StatusCode::SERVICE_UNAVAILABLE);
    let health = tokio::time::timeout(
        Duration::from_secs(2),
        f.app()
            .oneshot(request("GET", "/health", None, None, json!(null))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    drop(connection);
    while let Some(result) = tasks.join_next().await {
        assert!(matches!(
            result.unwrap(),
            StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
        ));
    }
    let response = f
        .app()
        .oneshot(request(
            "GET",
            "/api/v1/vault",
            Some(&token),
            None,
            json!(null),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn concurrent_revision_burst_has_one_commit_and_no_lost_audit_event() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    vault::put_entry(&f.state.pool, &f.owner, id, entry(0, 32))
        .await
        .unwrap();
    let (token, csrf) = f.session().await;
    let barrier = Arc::new(Barrier::new(65));
    let mut tasks = JoinSet::new();
    for _ in 0..64 {
        let app = f.app();
        let token = token.clone();
        let csrf = csrf.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            app.oneshot(request(
                "PUT",
                &format!("/api/v1/entries/{id}"),
                Some(&token),
                Some(&csrf),
                body(1, 32),
            ))
            .await
            .unwrap()
            .status()
        });
    }
    barrier.wait().await;
    let mut committed = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            StatusCode::OK => committed += 1,
            StatusCode::CONFLICT | StatusCode::SERVICE_UNAVAILABLE => (),
            status => panic!("unexpected response: {status}"),
        }
    }
    assert_eq!(committed, 1);
    assert_eq!(
        vault::get_entry(&f.state.pool, &f.owner, id)
            .await
            .unwrap()
            .revision,
        2
    );
    assert_eq!(f.audit_count().await, 3);
    f.integrity().await;
}

#[tokio::test]
async fn cancelled_write_rolls_back_and_releases_database_capacity() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    vault::put_entry(&f.state.pool, &f.owner, id, entry(0, 32))
        .await
        .unwrap();
    let pool = f.state.pool.clone();
    let (ready, signal) = tokio::sync::oneshot::channel();
    let writer = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE entries SET revision=99 WHERE id=?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        db::audit(&mut tx, "entry.put", &id.to_string(), Some(99))
            .await
            .unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
        tx.commit().await.unwrap();
    });
    signal.await.unwrap();
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    assert_eq!(
        vault::get_entry(&f.state.pool, &f.owner, id)
            .await
            .unwrap()
            .revision,
        1
    );
    assert_eq!(f.audit_count().await, 2);
    vault::put_entry(&f.state.pool, &f.owner, id, entry(1, 32))
        .await
        .unwrap();
    f.integrity().await;
}

// Run only as a child of the crash test. Normal test discovery does no work here.
#[test]
fn crash_worker() {
    let Some(directory) = std::env::var_os("VAULT_CRASH_FIXTURE") else {
        return;
    };
    let directory = Path::new(&directory);
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let pool = db::connect(&directory.join("vault.sqlite"), false).await.unwrap();
        let owner = db::account(&pool).await.unwrap();
        let committed = Uuid::from_u128(1);
        vault::put_entry(&pool, &owner, committed, entry(0,32)).await.unwrap();
        sqlx::query("PRAGMA cache_size=5").execute(&pool).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        // Force dirty-page spill into WAL, then stop before committing.
        for number in 2..34 {
            sqlx::query("INSERT INTO entries(id,vault,owner,ciphertext,nonce,revision,updated_at) SELECT ?,id,owner,?, ?,1,0 FROM vaults WHERE owner=?")
                .bind(Uuid::from_u128(number).to_string()).bind(URL_SAFE_NO_PAD.encode(vec![6;65536]))
                .bind(URL_SAFE_NO_PAD.encode([7;24])).bind(&owner).execute(&mut *tx).await.unwrap();
        }
        db::audit(&mut tx,"entry.put","pending",Some(1)).await.unwrap();
        sqlx::query("UPDATE vaults SET sequence=999").execute(&mut *tx).await.unwrap();
        std::fs::write(directory.join("ready"), b"uncommitted transaction open").unwrap();
        std::future::pending::<()>().await;
    });
}
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
async fn forced_process_kill_preserves_commits_and_discards_uncommitted_wal() {
    let f = Fixture::new().await;
    let path = f.state.config.database.clone();
    let directory = path.parent().unwrap();
    f.state.pool.close().await;
    let mut worker = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_worker", "--nocapture"])
            .env("VAULT_CRASH_FIXTURE", directory)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !directory.join("ready").exists() {
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "crash worker exited before fault injection"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "crash worker readiness timed out"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        std::fs::metadata(directory.join("vault.sqlite-wal"))
            .unwrap()
            .len()
            > 1024 * 1024,
        "fault must occur after dirty pages have reached WAL"
    );
    worker.0.kill().unwrap();
    assert!(!worker.0.wait().unwrap().success());
    let pool = db::connect(&path, false).await.unwrap();
    assert_eq!(
        vault::get_entry(&pool, &f.owner, Uuid::from_u128(1))
            .await
            .unwrap()
            .revision,
        1
    );
    assert_eq!(
        vault::list(&pool, &f.owner, None, 100).await.unwrap().len(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(vault::get_vault(&pool, &f.owner).await.unwrap().sequence, 2);
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "ok"
    );
    vault::put_entry(&pool, &f.owner, Uuid::from_u128(2), entry(0, 32))
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
async fn request_deadline_releases_capacity_without_bypassing_authentication() {
    let f = Fixture::new().await;
    let (token, _) = f.session().await;
    let stalled = f.state.memory.lock().await;
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        f.app().oneshot(request(
            "GET",
            "/api/v1/vault",
            Some(&token),
            None,
            json!(null),
        )),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(stalled);
    let response = f
        .app()
        .oneshot(request(
            "GET",
            "/api/v1/vault",
            Some(&token),
            None,
            json!(null),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let anonymous = f
        .app()
        .oneshot(request("GET", "/api/v1/vault", None, None, json!(null)))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(f.audit_count().await, 1);
}

#[tokio::test]
async fn write_lock_contention_is_bounded_and_recovers_without_partial_state() {
    let f = Fixture::new().await;
    let blocker = db::connect(&f.state.config.database, false).await.unwrap();
    let mut connection = blocker.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        vault::put_entry(&f.state.pool, &f.owner, id, entry(0, 32)),
    )
    .await
    .unwrap();
    assert_eq!(outcome.err().unwrap().0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.audit_count().await, 1);
    assert!(vault::get_entry(&f.state.pool, &f.owner, id).await.is_err());
    sqlx::query("ROLLBACK")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    blocker.close().await;
    vault::put_entry(&f.state.pool, &f.owner, id, entry(0, 32))
        .await
        .unwrap();
    f.integrity().await;
}

#[tokio::test]
async fn exhausted_audit_capacity_blocks_the_entire_mutation() {
    let f = Fixture::new().await;
    sqlx::query("WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n < ?) INSERT INTO audit_outbox(event_id,operation,subject,created_at) SELECT 'capacity-' || n,'test','fixture',0 FROM numbers")
        .bind(db::MAX_AUDIT_EVENTS-1).execute(&f.state.pool).await.unwrap();
    let id = Uuid::new_v4();
    let outcome = vault::put_entry(&f.state.pool, &f.owner, id, entry(0, 32)).await;
    assert_eq!(outcome.err().unwrap().0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(vault::get_entry(&f.state.pool, &f.owner, id).await.is_err());
    assert_eq!(f.audit_count().await, db::MAX_AUDIT_EVENTS);
    assert_eq!(
        vault::get_vault(&f.state.pool, &f.owner)
            .await
            .unwrap()
            .sequence,
        1
    );
    f.integrity().await;
}
