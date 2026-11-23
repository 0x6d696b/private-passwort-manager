use crate::error::{ApiError, Result};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Sqlite, SqlitePool, Transaction,
};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
pub const MAX_AUDIT_EVENTS: i64 = 100_000;

pub async fn connect(path: &Path, create: bool) -> std::result::Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(3));
    // One connection serializes write transactions; the service is initially single-user.
    SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(4))
        .connect_with(options)
        .await
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub async fn audit(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &str,
    subject: &str,
    revision: Option<i64>,
) -> Result<i64> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_outbox")
        .fetch_one(&mut **tx)
        .await?;
    // Fail closed rather than fill the disk if independent collection/retention is neglected.
    if count >= MAX_AUDIT_EVENTS {
        return Err(ApiError::busy());
    }
    let sequence = sqlx::query("INSERT INTO audit_outbox(event_id, operation, subject, revision, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string()).bind(operation).bind(subject).bind(revision).bind(now())
        .execute(&mut **tx).await?.last_insert_rowid();
    Ok(sequence)
}
pub async fn account(pool: &SqlitePool) -> Result<String> {
    sqlx::query_scalar("SELECT id FROM accounts")
        .fetch_optional(pool)
        .await?
        .ok_or_else(ApiError::unauthorized)
}
