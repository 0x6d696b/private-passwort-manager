//! Exercise the exact integration surfaces touched by temporary dependency backports.
use crypto_glue::{
    rsa::{self, RS256PublicKey, RS256SigningKey, RS256VerifyingKey},
    traits::{SignatureEncoding, Signer, Verifier},
};
use private_vault::db;

#[test]
fn stable_rsa_adapter_accepts_valid_signatures_and_rejects_tampering() {
    // Ephemeral test key, never a fixture or production credential.
    let private_key = rsa::new_key(2048).unwrap();
    let public_key = RS256PublicKey::from(&private_key);
    let signing_key = RS256SigningKey::new(private_key.clone());
    let verifying_key = RS256VerifyingKey::new(public_key.clone());
    let message = b"private-vault dependency compatibility test";
    let signature = signing_key.sign(message);
    verifying_key.verify(message, &signature).unwrap();
    assert!(verifying_key
        .verify(b"tampered message", &signature)
        .is_err());
    let mut bytes = signature.to_vec();
    bytes[0] ^= 1;
    let corrupted = rsa::RS256Signature::try_from(bytes.as_slice()).unwrap();
    assert!(verifying_key.verify(message, &corrupted).is_err());

    // OAEP remains available through the adapter; no change of padding or digest.
    let ciphertext = rsa::oaep_sha256_encrypt(&public_key, message).unwrap();
    assert_eq!(
        rsa::oaep_sha256_decrypt(&private_key, &ciphertext).unwrap(),
        message
    );
    // The disabled MySQL adapter must preserve its protocol-required OAEP SHA-1 digest.
    let mysql_ciphertext = public_key
        .oaep_encrypt::<crypto_glue::sha1::Sha1>(message)
        .unwrap();
    assert_eq!(
        private_key
            .oaep_decrypt::<crypto_glue::sha1::Sha1>(&mysql_ciphertext)
            .unwrap(),
        message
    );
    let mut corrupted = ciphertext;
    corrupted[0] ^= 1;
    assert!(rsa::oaep_sha256_decrypt(&private_key, &corrupted).is_err());
}

#[tokio::test]
async fn sqlite_uses_fixed_bundled_engine_and_reopens_committed_wal_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("compatibility.sqlite");
    let pool = db::connect(&path, true).await.unwrap();
    let version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let components: Vec<u32> = version.split('.').map(|s| s.parse().unwrap()).collect();
    assert!(
        components.as_slice() >= [3, 54, 1].as_slice(),
        "unexpected SQLite version: {version}"
    );
    db::MIGRATOR.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO accounts(id) VALUES ('compatibility-owner')")
        .execute(&pool)
        .await
        .unwrap();
    // Open independently while the writer is alive: committed WAL state must be visible.
    let reader = db::connect(&path, false).await.unwrap();
    let owner: String = sqlx::query_scalar("SELECT id FROM accounts")
        .fetch_one(&reader)
        .await
        .unwrap();
    assert_eq!(owner, "compatibility-owner");
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
            .fetch_one(&reader)
            .await
            .unwrap(),
        "ok"
    );
    reader.close().await;
    pool.close().await;
    let reopened = db::connect(&path, false).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT id FROM accounts")
            .fetch_one(&reopened)
            .await
            .unwrap(),
        "compatibility-owner"
    );
    reopened.close().await;
}
