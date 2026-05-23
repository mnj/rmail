use clap::{Parser, Subcommand};
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use rmail_common::{config::Config, maildir};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use rand::rngs::OsRng;

/// rmail_ctl: minimal control CLI for managing mailboxes and generating password hashes.
#[derive(Parser)]
#[command(name = "rmail_ctl")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Argon2 password hash from plaintext password
    Hash {
        /// Password to hash (avoid passing on command line in production)
        password: String,
    },
    /// Initialize the SQLite database schema
    InitDb {
        /// optional db path (defaults to config global.db_path)
        #[arg(long)]
        db_path: Option<String>,
        /// optional config path
        #[arg(long)]
        config: Option<String>,
    },
    /// Add a mailbox to the configured DB or fallback to TOML
    AddMailbox {
        /// mailbox address, e.g., user@example.com
        address: String,
        /// plaintext password (will be hashed). Prefer passing a precomputed --password-hash instead.
        #[arg(long)]
        password: Option<String>,
        /// precomputed password hash (PHC string) — use instead of --password
        #[arg(long)]
        password_hash: Option<String>,
        /// optional explicit maildir path
        #[arg(long)]
        maildir: Option<String>,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// List configured mailboxes (DB or TOML)
    List {
        /// optional config path
        #[arg(long)]
        config: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hash { password } => {
            let mut rng = OsRng;
            let salt = SaltString::generate(&mut rng);
            let argon2 = Argon2::default();
            let ph = argon2.hash_password(password.as_bytes(), &salt).map_err(|e| anyhow::anyhow!(e.to_string()))?.to_string();
            println!("{}", ph);
        },
        Commands::InitDb { db_path, config } => {
            let dbp = if let Some(p) = db_path { p } else {
                let cfg_path = config.unwrap_or_else(|| std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string()));
                let cfg = Config::from_file(&cfg_path)?;
                cfg.global.db_path.ok_or_else(|| anyhow::anyhow!("No db_path configured"))?
            };
            rmail_common::db::init_db(&dbp)?;
            println!("Initialized DB at {}", dbp);
        }
        Commands::AddMailbox { address, password, password_hash, maildir: maildir_opt, config } => {
            let cfg_path = config.unwrap_or_else(|| std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string()));
            let cfg = Config::from_file(&cfg_path)?;
            // determine password_hash: either provided precomputed, or hash the plaintext password
            let ph = if let Some(h) = password_hash {
                h
            } else if let Some(p) = password {
                let mut rng = OsRng;
                let salt = SaltString::generate(&mut rng);
                Argon2::default().hash_password(p.as_bytes(), &salt).map_err(|e| anyhow::anyhow!(e.to_string()))?.to_string()
            } else {
                String::new()
            };

            if let Some(at) = address.find('@') {
                let local = &address[..at];
                let domain = &address[at+1..];
                let mail_root = cfg.global.mail_root.clone();
                let maildir_path = if let Some(md) = maildir_opt {
                    md
                } else {
                    format!("{}/{}/{}/Maildir", mail_root, domain, local)
                };
                // ensure directories exist
                maildir::ensure_maildir(Path::new(&maildir_path))?;

                // If db_path configured, insert into SQLite, otherwise fallback to TOML append
                if let Some(dbp) = cfg.global.db_path.as_ref() {
                    // ensure DB initialized
                    rmail_common::db::init_db(dbp)?;
                    rmail_common::db::add_mailbox(dbp, &address.to_ascii_lowercase(), if ph.is_empty() { None } else { Some(&ph) }, Some(&maildir_path))?;
                    println!("Added mailbox {} into DB at {}", address, dbp);
                } else {
                    // append mailbox to config file (simple append — robust editing can be added later)
                    let snippet = format!("\n[[mailboxes]]\naddress = \"{}\"\npassword_hash = \"{}\"\nmaildir = \"{}\"\n", address.to_ascii_lowercase(), ph, maildir_path);
                    let mut f = OpenOptions::new().append(true).create(true).open(&cfg_path)?;
                    f.write_all(snippet.as_bytes())?;
                    println!("Added mailbox {} (config file)", address);
                }
            } else {
                eprintln!("Invalid address '{}'", address);
            }
        }
        Commands::List { config } => {
            let cfg_path = config.unwrap_or_else(|| std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string()));
            let cfg = Config::from_file(&cfg_path)?;
            if let Some(dbp) = cfg.global.db_path.as_ref() {
                // list from DB
                for m in rmail_common::db::list_mailboxes(dbp)? {
                    println!("{}", m.address);
                }
            } else {
                if let Some(mboxes) = cfg.mailboxes {
                    for m in mboxes {
                        println!("{}", m.address);
                    }
                } else {
                    println!("No mailboxes configured");
                }
            }
        }
    }
    Ok(())
}
