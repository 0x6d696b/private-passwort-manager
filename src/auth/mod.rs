use crate::{
    db,
    error::{ApiError, Result},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

pub const COOKIE: &str = "__Host-session";
pub const FLOW_COOKIE: &str = "__Host-ceremony";
const IDLE: Duration = Duration::from_secs(15 * 60);
const ABSOLUTE: Duration = Duration::from_secs(8 * 60 * 60);
const FRESH: Duration = Duration::from_secs(5 * 60);
const CEREMONY: Duration = Duration::from_secs(180);
const MAX_SESSIONS: usize = 32;
const MAX_FLOWS: usize = 32;

pub fn token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}
pub fn valid_token(value: &str) -> bool {
    value.len() == 43 && URL_SAFE_NO_PAD.decode(value).is_ok_and(|b| b.len() == 32)
}
pub fn same_secret(left: &str, right: &str) -> bool {
    Sha256::digest(left.as_bytes())
        .ct_eq(&Sha256::digest(right.as_bytes()))
        .into()
}
pub fn cookie(name: &str, value: &str, seconds: u32) -> String {
    format!("{name}={value}; Path=/; Max-Age={seconds}; Secure; HttpOnly; SameSite=Strict")
}

#[derive(Clone)]
pub struct Session {
    pub owner: String,
    pub csrf: String,
    created: Instant,
    last_seen: Instant,
}
impl Session {
    pub fn fresh(&self) -> Result<()> {
        if self.created.elapsed() > FRESH {
            Err(ApiError::forbidden())
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
pub struct AuthContext {
    pub key: String,
    pub session: Session,
}

pub enum RegistrationAuthority {
    Bootstrap { enrollment_hash: String },
    Session { session_key: String },
}
pub enum FlowKind {
    Login(PasskeyAuthentication),
    Registration {
        state: PasskeyRegistration,
        authority: RegistrationAuthority,
    },
}
pub struct Flow {
    pub owner: String,
    pub kind: FlowKind,
    created: Instant,
}

#[derive(Default)]
pub struct Memory {
    sessions: HashMap<String, Session>,
    flows: HashMap<String, Flow>,
    auth_attempts: VecDeque<Instant>,
}
#[derive(Serialize)]
pub struct SessionInfo {
    pub owner: String,
    pub csrf_token: String,
}

impl Memory {
    fn clean(&mut self) {
        self.sessions
            .retain(|_, s| s.created.elapsed() < ABSOLUTE && s.last_seen.elapsed() < IDLE);
        self.flows.retain(|_, f| f.created.elapsed() < CEREMONY);
        while self
            .auth_attempts
            .front()
            .is_some_and(|t| t.elapsed() >= Duration::from_secs(60))
        {
            self.auth_attempts.pop_front();
        }
    }
    pub fn throttle_auth(&mut self) -> Result<()> {
        self.clean();
        // Global bound intentionally covers a single-user deployment and spoofed source addresses.
        if self.auth_attempts.len() >= 20 {
            return Err(ApiError::limited());
        }
        self.auth_attempts.push_back(Instant::now());
        Ok(())
    }
    pub fn issue(&mut self, owner: String) -> Result<(String, SessionInfo)> {
        self.clean();
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(ApiError::limited());
        }
        let raw = token();
        let session = Session {
            owner: owner.clone(),
            csrf: token(),
            created: Instant::now(),
            last_seen: Instant::now(),
        };
        let info = SessionInfo {
            owner,
            csrf_token: session.csrf.clone(),
        };
        self.sessions.insert(digest(&raw), session);
        Ok((raw, info))
    }
    pub fn authenticate(&mut self, raw: &str) -> Result<AuthContext> {
        self.clean();
        if !valid_token(raw) {
            return Err(ApiError::unauthorized());
        }
        let key = digest(raw);
        let session = self
            .sessions
            .get_mut(&key)
            .ok_or_else(ApiError::unauthorized)?;
        session.last_seen = Instant::now();
        Ok(AuthContext {
            key,
            session: session.clone(),
        })
    }
    pub fn revoke(&mut self, key: &str) {
        self.sessions.remove(key);
    }
    pub fn session_is_fresh(&mut self, key: &str, owner: &str) -> Result<()> {
        self.clean();
        let s = self.sessions.get(key).ok_or_else(ApiError::unauthorized)?;
        if s.owner != owner {
            return Err(ApiError::forbidden());
        }
        s.fresh()
    }
    pub fn put_flow(&mut self, owner: String, kind: FlowKind) -> Result<String> {
        self.clean();
        if self.flows.len() >= MAX_FLOWS {
            return Err(ApiError::limited());
        }
        let raw = token();
        self.flows.insert(
            digest(&raw),
            Flow {
                owner,
                kind,
                created: Instant::now(),
            },
        );
        Ok(raw)
    }
    pub fn take_flow(&mut self, raw: &str) -> Result<Flow> {
        self.clean();
        if !valid_token(raw) {
            return Err(ApiError::unauthorized());
        }
        self.flows
            .remove(&digest(raw))
            .ok_or_else(ApiError::unauthorized)
    }
}

pub async fn passkeys(
    pool: &sqlx::SqlitePool,
    owner: &str,
) -> Result<Vec<webauthn_rs::prelude::Passkey>> {
    let values: Vec<String> =
        sqlx::query_scalar("SELECT passkey FROM credentials WHERE owner = ? ORDER BY id LIMIT 16")
            .bind(owner)
            .fetch_all(pool)
            .await?;
    values
        .into_iter()
        .map(|s| serde_json::from_str(&s).map_err(Into::into))
        .collect()
}
pub async fn record_event(pool: &sqlx::SqlitePool, operation: &str, owner: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    db::audit(&mut tx, operation, owner, None).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sessions_are_hashed_revocable_and_restart_local() {
        let mut memory = Memory::default();
        let (raw, _) = memory.issue("alice".into()).unwrap();
        assert!(!memory.sessions.contains_key(&raw));
        let context = memory.authenticate(&raw).unwrap();
        assert_eq!(context.session.owner, "alice");
        assert!(Memory::default().authenticate(&raw).is_err());
        memory.revoke(&context.key);
        assert!(memory.authenticate(&raw).is_err());
    }
    #[test]
    fn sessions_expire_and_fresh_authentication_is_required() {
        let mut memory = Memory::default();
        let (raw, _) = memory.issue("alice".into()).unwrap();
        let session = memory.sessions.get_mut(&digest(&raw)).unwrap();
        session.created = Instant::now() - FRESH - Duration::from_secs(1);
        assert!(session.fresh().is_err());
        session.last_seen = Instant::now() - IDLE - Duration::from_secs(1);
        assert!(memory.authenticate(&raw).is_err());
        let (raw, _) = memory.issue("alice".into()).unwrap();
        memory.sessions.get_mut(&digest(&raw)).unwrap().created = Instant::now() - ABSOLUTE;
        assert!(memory.authenticate(&raw).is_err());
    }
    #[test]
    fn ceremony_cookie_is_single_use_and_expiration_is_enforced() {
        use webauthn_rs::prelude::*;
        let origin = Url::parse("https://vault.test").unwrap();
        let webauthn = WebauthnBuilder::new("vault.test", &origin)
            .unwrap()
            .build()
            .unwrap();
        let (_, state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "owner", "Owner", None)
            .unwrap();
        let mut memory = Memory::default();
        let raw = memory
            .put_flow(
                "owner".into(),
                FlowKind::Registration {
                    state,
                    authority: RegistrationAuthority::Bootstrap {
                        enrollment_hash: "hash".into(),
                    },
                },
            )
            .unwrap();
        assert!(memory.take_flow(&raw).is_ok());
        assert!(memory.take_flow(&raw).is_err());
        let (options, state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "owner", "Owner", None)
            .unwrap();
        let json = serde_json::to_value(options).unwrap();
        assert_eq!(
            json["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        let raw = memory
            .put_flow(
                "owner".into(),
                FlowKind::Registration {
                    state,
                    authority: RegistrationAuthority::Bootstrap {
                        enrollment_hash: "hash".into(),
                    },
                },
            )
            .unwrap();
        memory.flows.get_mut(&digest(&raw)).unwrap().created = Instant::now() - CEREMONY;
        assert!(memory.take_flow(&raw).is_err());
    }
    #[test]
    fn guessing_and_unbounded_sessions_are_rejected() {
        let mut memory = Memory::default();
        assert!(memory.authenticate("bad").is_err());
        for _ in 0..MAX_SESSIONS {
            memory.issue("alice".into()).unwrap();
        }
        assert!(memory.issue("alice".into()).is_err());
        for _ in 0..20 {
            memory.throttle_auth().unwrap();
        }
        assert!(memory.throttle_auth().is_err());
        assert!(!same_secret("csrf1", "csrf2"));
    }
}
