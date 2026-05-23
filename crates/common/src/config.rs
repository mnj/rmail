use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Global {
    pub mail_root: String,
    pub listen_addrs: Option<Vec<String>>,
    pub smtps_port: Option<u16>,
    pub submission_port: Option<u16>,
    pub imaps_port: Option<u16>,
    pub imap_port: Option<u16>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub log_level: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Mailbox {
    pub address: String,
    pub password_hash: Option<String>,
    pub maildir: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub global: Global,
    pub mailboxes: Option<Vec<Mailbox>>,
    pub catchalls: Option<HashMap<String, String>>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
        let s = fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&s)?;
        Ok(cfg)
    }
}
