use anyhow::{bail, Context, Result};
use std::{env, net::SocketAddr, path::PathBuf};
use url::Url;

#[derive(Clone)]
pub struct Config {
    pub database: PathBuf,
    pub bind: SocketAddr,
    pub origin: Url,
    pub rp_id: String,
}
impl Config {
    pub fn from_env() -> Result<Self> {
        let origin = Url::parse(&env::var("VAULT_ORIGIN").context("VAULT_ORIGIN is required")?)?;
        let config = Self {
            database: env::var_os("VAULT_DATABASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("data/vault.sqlite")),
            bind: env::var("VAULT_BIND")
                .unwrap_or_else(|_| "127.0.0.1:8080".into())
                .parse()?,
            rp_id: env::var("VAULT_RP_ID").context("VAULT_RP_ID is required")?,
            origin,
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.origin.scheme() != "https"
            || self.origin.host_str().is_none()
            || !self.origin.username().is_empty()
            || self.origin.password().is_some()
            || self.origin.query().is_some()
            || self.origin.fragment().is_some()
            || self.origin.path() != "/"
        {
            bail!("VAULT_ORIGIN must be a bare HTTPS origin");
        }
        // Restrict to the exact host rather than allowing a parent-domain RP ID.
        if self.origin.host_str() != Some(self.rp_id.as_str()) {
            bail!("VAULT_RP_ID must equal the origin host");
        }
        let ip = self.bind.ip();
        let private = match ip {
            std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback(),
            std::net::IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00 == 0xfc00),
        };
        if !private || self.bind.port() == 0 {
            bail!("bind must be a specific private or loopback address");
        }
        Ok(())
    }
    pub fn origin_string(&self) -> String {
        self.origin.origin().ascii_serialization()
    }
}
