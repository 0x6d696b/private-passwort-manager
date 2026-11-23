#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use private_vault::{
    api::{self, AppState},
    auth,
    config::Config,
    db,
};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Parser)]
#[command(about = "Private-network encrypted vault backend")]
struct Cli {
    #[arg(long, global = true)]
    database: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create/update the schema. Stop the server and verify a backup first.
    Migrate,
    /// Start HTTPS-proxy-only API service; schema must already be current.
    Serve,
    /// Provision the single account and write its enrollment token to a new 0600 file.
    Init {
        #[arg(long)]
        token_file: PathBuf,
    },
    /// Replace authentication credentials after stopping the server. Does not decrypt the vault.
    Recover {
        #[arg(long)]
        token_file: PathBuf,
    },
}

fn secure_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn check_permissions(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("symlinks are not allowed for database paths");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            bail!("database directory and files must be owner-only");
        }
    }
    Ok(())
}
fn lock_database(path: &Path, create: bool) -> Result<File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("use a database inside a dedicated private directory")?;
    if create && !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    check_permissions(parent)?;
    if create && !path.exists() {
        secure_file(path)?.sync_all()?;
    }
    check_permissions(path)?;
    let lock_path = path.with_extension("process.lock");
    let lock = if lock_path.exists() {
        check_permissions(&lock_path)?;
        OpenOptions::new().read(true).write(true).open(&lock_path)?
    } else {
        secure_file(&lock_path)?
    };
    lock.try_lock_exclusive()
        .context("another server or maintenance command holds the database lock")?;
    Ok(lock)
}
async fn validate_schema(pool: &sqlx::SqlitePool) -> Result<()> {
    let rows: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .context("run the migrate command before serving")?;
    let migrations: Vec<_> = db::MIGRATOR.iter().collect();
    if rows.len() != migrations.len() {
        bail!("schema is not current; run migrate while stopped");
    }
    for ((version, success, checksum), migration) in rows.iter().zip(migrations) {
        if *version != migration.version
            || !*success
            || checksum.as_slice() != migration.checksum.as_ref()
        {
            bail!("schema checksum mismatch or failed migration");
        }
    }
    Ok(())
}
async fn enroll(pool: &sqlx::SqlitePool, token_path: &Path, recovery: bool) -> Result<()> {
    // Exclusive process lock guarantees no server is using sessions during maintenance.
    let mut token_file = secure_file(token_path).context("token file must not already exist")?;
    let token = auth::token();
    let mut tx = pool.begin().await?;
    let owner = if recovery {
        let owner: String = sqlx::query_scalar("SELECT id FROM accounts")
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM credentials WHERE owner = ?")
            .bind(&owner)
            .execute(&mut *tx)
            .await?;
        owner
    } else {
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO accounts(id) VALUES (?)")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        id
    };
    sqlx::query("UPDATE accounts SET enrollment_hash = ?, enrollment_expires = ? WHERE id = ?")
        .bind(auth::digest(&token))
        .bind(db::now() + 600)
        .bind(&owner)
        .execute(&mut *tx)
        .await?;
    db::audit(
        &mut tx,
        if recovery {
            "account.recovery"
        } else {
            "account.init"
        },
        &owner,
        None,
    )
    .await
    .map_err(|_| anyhow::anyhow!("cannot persist account audit event"))?;
    // Persist the token before commit: a crash cannot activate an unrecorded token.
    writeln!(token_file, "{token}")?;
    token_file.sync_all()?;
    tx.commit().await?;
    tracing::info!("enrollment file created; token expires in ten minutes");
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let path = cli
        .database
        .or_else(|| std::env::var_os("VAULT_DATABASE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("data/vault.sqlite"));
    let _lock = lock_database(&path, matches!(&cli.command, Command::Migrate))?;
    let pool = db::connect(&path, false).await?;
    if matches!(&cli.command, Command::Migrate) {
        db::MIGRATOR.run(&pool).await?;
        tracing::info!("database migrations complete");
    } else {
        validate_schema(&pool).await?;
        match cli.command {
            Command::Init { token_file } => enroll(&pool, &token_file, false).await?,
            Command::Recover { token_file } => enroll(&pool, &token_file, true).await?,
            Command::Serve => {
                let mut config = Config::from_env()?;
                config.database = path;
                let listener = tokio::net::TcpListener::bind(config.bind).await?;
                let state = AppState::new(config, pool.clone())?;
                tracing::info!("API ready; private reverse proxy with HTTPS required");
                axum::serve(listener, api::router(state))
                    .with_graceful_shutdown(shutdown())
                    .await?;
            }
            Command::Migrate => unreachable!(),
        }
    }
    pool.close().await;
    Ok(())
}
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
