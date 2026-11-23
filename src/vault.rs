use crate::{
    db,
    error::{ApiError, Result},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

const MAX_ENTRIES: i64 = 10_000;
const MAX_STORED_BYTES: i64 = 64 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    pub algorithm: String,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub salt: String,
    pub nonce: String,
    pub wrapped_key: String,
    pub kdf: Kdf,
}
pub fn decode(value: &str, min: usize, max: usize) -> Result<()> {
    if value.len() > (max * 4).div_ceil(3) {
        return Err(ApiError::invalid());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::invalid())?;
    if bytes.len() < min || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ApiError::invalid());
    }
    Ok(())
}
impl Envelope {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.kdf.algorithm != "argon2id"
            || self.kdf.version != 19
            || !matches!(self.kdf.memory_kib, 65536 | 131072 | 262144)
            || self.kdf.iterations != 3
            || self.kdf.parallelism != 1
        {
            return Err(ApiError::invalid());
        }
        decode(&self.salt, 16, 16)?;
        decode(&self.nonce, 24, 24)?;
        decode(&self.wrapped_key, 48, 48)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutVault {
    pub id: Uuid,
    pub expected_revision: i64,
    pub envelope: Envelope,
}
#[derive(Serialize)]
pub struct Vault {
    pub id: String,
    pub revision: i64,
    pub sequence: i64,
    pub envelope: Envelope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutEntry {
    pub expected_revision: i64,
    pub ciphertext: String,
    pub nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delete {
    pub expected_revision: i64,
}
#[derive(Serialize, FromRow)]
pub struct Entry {
    pub id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: i64,
}
#[derive(Serialize)]
pub struct Mutation {
    pub revision: i64,
    pub sequence: i64,
}

fn revision(value: i64) -> Result<()> {
    if !(0..i64::MAX).contains(&value) {
        return Err(ApiError::invalid());
    }
    Ok(())
}
async fn active_vault(tx: &mut Transaction<'_, Sqlite>, owner: &str) -> Result<String> {
    sqlx::query_scalar("SELECT id FROM vaults WHERE owner = ? AND deleted = 0")
        .bind(owner)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::missing)
}
async fn bump(
    tx: &mut Transaction<'_, Sqlite>,
    owner: &str,
    operation: &str,
    subject: &str,
    rev: i64,
) -> Result<i64> {
    let seq = db::audit(tx, operation, subject, Some(rev)).await?;
    sqlx::query("UPDATE vaults SET sequence = ? WHERE owner = ?")
        .bind(seq)
        .bind(owner)
        .execute(&mut **tx)
        .await?;
    Ok(seq)
}
pub async fn get_vault(pool: &SqlitePool, owner: &str) -> Result<Vault> {
    let row: Option<(String, i64, i64, String)> = sqlx::query_as(
        "SELECT id, revision, sequence, envelope FROM vaults WHERE owner = ? AND deleted = 0",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let (id, revision, sequence, envelope) = row.ok_or_else(ApiError::missing)?;
    Ok(Vault {
        id,
        revision,
        sequence,
        envelope: serde_json::from_str(&envelope)?,
    })
}
pub async fn put_vault(pool: &SqlitePool, owner: &str, input: PutVault) -> Result<Mutation> {
    revision(input.expected_revision)?;
    input.envelope.validate()?;
    let envelope = serde_json::to_string(&input.envelope)?;
    let id = input.id.to_string();
    let mut tx = pool.begin().await?;
    let current: Option<(String, i64, bool)> =
        sqlx::query_as("SELECT id, revision, deleted FROM vaults WHERE owner = ?")
            .bind(owner)
            .fetch_optional(&mut *tx)
            .await?;
    match current {
        None if input.expected_revision == 0 => {
            sqlx::query("INSERT INTO vaults(id, owner, envelope, revision, sequence) VALUES (?, ?, ?, 1, 0)")
                .bind(&id).bind(owner).bind(envelope).execute(&mut *tx).await?;
        }
        Some((existing, rev, false)) if existing == id && rev == input.expected_revision => {
            sqlx::query("UPDATE vaults SET envelope = ?, revision = revision + 1 WHERE owner = ? AND id = ? AND revision = ? AND deleted = 0")
                .bind(envelope).bind(owner).bind(&id).bind(rev).execute(&mut *tx).await?;
        }
        _ => return Err(ApiError::conflict()),
    }
    let rev = input.expected_revision + 1;
    let seq = bump(&mut tx, owner, "vault.put", &id, rev).await?;
    tx.commit().await?;
    Ok(Mutation {
        revision: rev,
        sequence: seq,
    })
}
pub async fn delete_vault(pool: &SqlitePool, owner: &str, expected: i64) -> Result<Mutation> {
    revision(expected)?;
    let mut tx = pool.begin().await?;
    let id = active_vault(&mut tx, owner).await?;
    let changed = sqlx::query("UPDATE vaults SET envelope = '', deleted = 1, revision = revision + 1 WHERE owner = ? AND revision = ? AND deleted = 0")
        .bind(owner).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::conflict());
    }
    sqlx::query("UPDATE entries SET ciphertext = '', deleted = 1, revision = revision + 1, updated_at = ? WHERE owner = ?")
        .bind(db::now()).bind(owner).execute(&mut *tx).await?;
    let seq = bump(&mut tx, owner, "vault.delete", &id, expected + 1).await?;
    tx.commit().await?;
    Ok(Mutation {
        revision: expected + 1,
        sequence: seq,
    })
}
pub async fn list(
    pool: &SqlitePool,
    owner: &str,
    after: Option<Uuid>,
    limit: u32,
) -> Result<Vec<Entry>> {
    if !(1..=100).contains(&limit) {
        return Err(ApiError::invalid());
    }
    Ok(sqlx::query_as("SELECT e.id, e.ciphertext, e.nonce, e.revision, e.deleted, e.updated_at FROM entries e JOIN vaults v ON e.vault = v.id AND e.owner = v.owner WHERE e.owner = ? AND v.deleted = 0 AND e.id > ? ORDER BY e.id LIMIT ?")
        .bind(owner).bind(after.map(|id| id.to_string()).unwrap_or_default()).bind(limit)
        .fetch_all(pool).await?)
}
pub async fn get_entry(pool: &SqlitePool, owner: &str, id: Uuid) -> Result<Entry> {
    sqlx::query_as("SELECT e.id, e.ciphertext, e.nonce, e.revision, e.deleted, e.updated_at FROM entries e JOIN vaults v ON e.vault = v.id AND e.owner = v.owner WHERE e.owner = ? AND e.id = ? AND v.deleted = 0")
        .bind(owner).bind(id.to_string()).fetch_optional(pool).await?.ok_or_else(ApiError::missing)
}
pub async fn put_entry(
    pool: &SqlitePool,
    owner: &str,
    id: Uuid,
    input: PutEntry,
) -> Result<Mutation> {
    revision(input.expected_revision)?;
    decode(&input.nonce, 24, 24)?;
    decode(&input.ciphertext, 16, 64 * 1024)?;
    let id = id.to_string();
    let mut tx = pool.begin().await?;
    let vault = active_vault(&mut tx, owner).await?;
    let current: Option<(i64, i64, bool)> = sqlx::query_as("SELECT revision, length(ciphertext), deleted FROM entries WHERE owner = ? AND vault = ? AND id = ?")
        .bind(owner).bind(&vault).bind(&id).fetch_optional(&mut *tx).await?;
    let old_size = match current {
        None if input.expected_revision == 0 => 0,
        Some((rev, size, false)) if rev == input.expected_revision => size,
        _ => return Err(ApiError::conflict()),
    };
    let (count, bytes): (i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(length(ciphertext)), 0) FROM entries WHERE owner = ?",
    )
    .bind(owner)
    .fetch_one(&mut *tx)
    .await?;
    if (current.is_none() && count >= MAX_ENTRIES)
        || bytes - old_size + input.ciphertext.len() as i64 > MAX_STORED_BYTES
    {
        return Err(ApiError::limited());
    }
    let rev = input.expected_revision + 1;
    if current.is_none() {
        sqlx::query("INSERT INTO entries(id, vault, owner, ciphertext, nonce, revision, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?)")
            .bind(&id).bind(&vault).bind(owner).bind(input.ciphertext).bind(input.nonce).bind(db::now()).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE entries SET ciphertext = ?, nonce = ?, revision = ?, updated_at = ? WHERE owner = ? AND vault = ? AND id = ? AND revision = ? AND deleted = 0")
            .bind(input.ciphertext).bind(input.nonce).bind(rev).bind(db::now()).bind(owner).bind(&vault).bind(&id).bind(input.expected_revision)
            .execute(&mut *tx).await?;
    }
    let seq = bump(&mut tx, owner, "entry.put", &id, rev).await?;
    tx.commit().await?;
    Ok(Mutation {
        revision: rev,
        sequence: seq,
    })
}
pub async fn delete_entry(
    pool: &SqlitePool,
    owner: &str,
    id: Uuid,
    expected: i64,
) -> Result<Mutation> {
    revision(expected)?;
    let mut tx = pool.begin().await?;
    active_vault(&mut tx, owner).await?;
    let changed = sqlx::query("UPDATE entries SET ciphertext = '', deleted = 1, revision = revision + 1, updated_at = ? WHERE owner = ? AND id = ? AND revision = ? AND deleted = 0")
        .bind(db::now()).bind(owner).bind(id.to_string()).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::conflict());
    }
    let seq = bump(
        &mut tx,
        owner,
        "entry.delete",
        &id.to_string(),
        expected + 1,
    )
    .await?;
    tx.commit().await?;
    Ok(Mutation {
        revision: expected + 1,
        sequence: seq,
    })
}
