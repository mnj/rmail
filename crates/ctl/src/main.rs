use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rmail_common::{config::Config, maildir};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RMAIL_SYSTEMD_UNITS: &[&str] = &[
    "rmail_smtpd.service",
    "rmail_imapd.service",
    "rmail_web.service",
    "rmail_webmail.service",
    "rmail_outbound.service",
    "rmail_classifier.service",
];

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
    /// Add a mailbox to the database
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
        /// storage quota in MiB; zero removes the limit
        #[arg(long)]
        quota_mib: Option<u64>,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// List mailboxes
    List {
        /// optional config path
        #[arg(long)]
        config: Option<String>,
    },
    /// Automatic TLS certificates (ACME / Let's Encrypt), configured with the acme.* settings
    Acme {
        #[command(subcommand)]
        action: AcmeAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Delivery routes: send a domain's mail (or, with `*`, all mail) via a
    /// relay host instead of its MX hosts, or refuse it
    Transport {
        #[command(subcommand)]
        action: TransportAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Sharing: which folders (IMAP ACL), calendars and address books an
    /// account shares, and with whom
    Share {
        #[command(subcommand)]
        action: ShareAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// DKIM signing keys and the ARC sealing key, stored in the database
    Dkim {
        #[command(subcommand)]
        action: DkimAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Aggregate and enqueue DMARC RUA reports for unreported events in the DB
    SendDmarcReports {
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// Show or change database-managed settings (the same ones the admin UI edits)
    Settings {
        #[command(subcommand)]
        action: SettingsAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Discard the full-text search index so the next search rebuilds it
    SearchReindex {
        /// Account address; omit when using --all
        address: Option<String>,
        /// Reset every account
        #[arg(long)]
        all: bool,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// Set the admin console username and password
    AdminPassword {
        /// Admin username
        #[arg(long, default_value = "admin")]
        user: String,
        /// Password; read from standard input when omitted
        #[arg(long)]
        password: Option<String>,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// Control rMail systemd services
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Watch live inbound and outbound SMTP activity
    Watch {
        /// Mail root (defaults to RMAIL_MAIL_ROOT or ./mail)
        #[arg(long)]
        mail_root: Option<String>,
        /// Print a stream instead of opening the full-screen interface
        #[arg(long)]
        plain: bool,
        /// Number of durable events to load initially
        #[arg(long, default_value_t = 250)]
        history: usize,
    },
    /// Show durable tracking events for a message ID
    Track {
        message_id: String,
        /// Mail root (defaults to RMAIL_MAIL_ROOT or ./mail)
        #[arg(long)]
        mail_root: Option<String>,
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum SettingsAction {
    /// List every setting with its stored value or default
    List,
    /// Print one setting as JSON
    Get { key: String },
    /// Store a setting. VALUE is JSON (e.g. 42, true, ["[::]:25"]) or plain text
    Set { key: String, value: String },
    /// Remove a stored setting so its default applies
    Unset { key: String },
}

#[derive(Subcommand)]
enum TransportAction {
    /// List routes
    List,
    /// Send mail for DOMAIN (or `*` for every domain without its own route)
    /// to a relay host
    Relay {
        domain: String,
        /// host or host:port (port 25 by default, 465 with --implicit-tls)
        relay: String,
        /// TLS from the first byte instead of STARTTLS
        #[arg(long)]
        implicit_tls: bool,
        /// Authenticate with AUTH PLAIN (only ever sent over TLS)
        #[arg(long)]
        user: Option<String>,
        /// Password for --user; read from standard input when omitted
        #[arg(long)]
        password: Option<String>,
    },
    /// Refuse mail for DOMAIN with REPLY, e.g. "550 5.1.2 No such domain"
    Reject { domain: String, reply: String },
    /// Remove DOMAIN's route; its mail goes to the MX hosts again
    Remove { domain: String },
}

#[derive(Subcommand)]
enum ShareAction {
    /// Folders, calendars and address books ADDRESS shares, and those
    /// shared with it
    List { address: String },
    /// Give GRANTEE ACCESS (read, read-write or none to stop sharing) to
    /// OWNER's calendar NAME (its URL segment, e.g. default)
    Calendar {
        owner: String,
        name: String,
        grantee: String,
        access: String,
    },
    /// Give GRANTEE ACCESS (read, read-write or none to stop sharing) to
    /// OWNER's address book NAME (its URL segment, e.g. default)
    Addressbook {
        owner: String,
        name: String,
        grantee: String,
        access: String,
    },
    /// Give GRANTEE exactly RIGHTS (RFC 4314 letters, e.g. lr to read, lrswite
    /// to read and change) on OWNER's FOLDER; `none` stops sharing
    Set {
        owner: String,
        folder: String,
        grantee: String,
        rights: String,
    },
}

#[derive(Subcommand)]
enum DkimAction {
    /// List keys with the DNS records to publish
    List,
    /// Add a key for DOMAIN under SELECTOR; generated unless --private-key is given.
    /// Every key of a domain signs its mail, so RSA and Ed25519 can run side by side.
    Add {
        domain: String,
        selector: String,
        /// rsa (2048-bit) or ed25519
        #[arg(long, default_value = "rsa")]
        algorithm: String,
        /// Import this PEM private key file instead of generating one
        #[arg(long)]
        private_key: Option<String>,
    },
    /// Delete a key; mail stops being signed with it at once
    Remove { domain: String, selector: String },
    /// Seal mail forwarded by aliases and Sieve redirects with this RSA key (ARC)
    SetArc { domain: String, selector: String },
    /// Stop ARC sealing
    ClearArc,
}

#[derive(Subcommand)]
enum AcmeAction {
    /// Request a certificate now and install it; services reload it automatically
    Issue {
        /// Test against Let's Encrypt staging (or the configured CA) without installing anything
        #[arg(long)]
        test: bool,
    },
    /// Renew the certificate if it is due (rmail_web also does this hourly)
    Renew,
    /// Show the installed certificate and the last ACME run
    Status,
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Start rMail services
    Start(ServiceCommandOptions),
    /// Stop rMail services
    Stop(ServiceCommandOptions),
    /// Restart rMail services
    Restart(ServiceCommandOptions),
    /// Reload rMail services, falling back to restart when reload is unsupported
    Reload(ServiceCommandOptions),
    /// Show rMail service status
    Status(ServiceCommandOptions),
    /// Restart the services named in a request file written by the admin console
    /// (run by rmail_restart.service; the file is consumed)
    ApplyRequest {
        /// Request file, normally <mail_root>/restart-request
        #[arg(long)]
        file: String,
    },
}

#[derive(clap::Args, Clone)]
struct ServiceCommandOptions {
    /// Restrict operation to one or more unit names or short names, e.g. smtpd or rmail_smtpd.service
    #[arg(long = "unit", value_name = "UNIT")]
    units: Vec<String>,
    /// Print systemctl commands without running them
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hash { password } => {
            let mut rng = OsRng;
            let salt = SaltString::generate(&mut rng);
            let argon2 = Argon2::default();
            let ph = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .to_string();
            println!("{}", ph);
        }
        Commands::Settings { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let mut conn = rmail_common::settings::open(&cfg.global.db_path)?;
            run_settings(&mut conn, action)?;
        }
        Commands::AdminPassword {
            user,
            password,
            config,
        } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db_path = cfg.global.db_path.clone();
            let password = match password {
                Some(password) => password,
                None => {
                    eprint!("New admin password: ");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    line.trim_end_matches(['\r', '\n']).to_string()
                }
            };
            let policy = rmail_common::settings::admin_password_policy(
                &rmail_common::settings::open(&db_path)?,
            )?;
            policy
                .check(user.trim(), &password)
                .map_err(|message| anyhow::anyhow!("admin {message}"))?;
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .to_string();
            let mut conn = rmail_common::settings::open(&db_path)?;
            rmail_common::settings::write_raw(
                &mut conn,
                &std::collections::BTreeMap::from([
                    (
                        "global.web_admin_user".to_string(),
                        Some(serde_json::Value::from(user.trim())),
                    ),
                    (
                        "global.web_admin_password_hash".to_string(),
                        Some(serde_json::Value::from(hash)),
                    ),
                ]),
            )?;
            println!("Admin credentials updated for {}", user.trim());
        }
        Commands::InitDb { db_path, config } => {
            let dbp = if let Some(p) = db_path {
                p
            } else {
                let cfg_path = config.unwrap_or_else(|| {
                    std::env::var("RMAIL_CONFIG")
                        .unwrap_or_else(|_| "config/example.toml".to_string())
                });
                let cfg = Config::load(&cfg_path)?;
                cfg.global.db_path
            };
            rmail_common::db::init_db(&dbp)?;
            println!("Initialized DB at {}", dbp);
        }
        Commands::AddMailbox {
            address,
            password,
            password_hash,
            maildir: maildir_opt,
            quota_mib,
            config,
        } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            // determine password_hash: either provided precomputed, or hash the plaintext password
            // Also generate a SCRAM verifier if a plaintext password was provided so SCRAM-SHA-256 can be used.
            let (ph, scram_json) = if let Some(h) = password_hash {
                (h, None)
            } else if let Some(p) = password {
                let mut rng = OsRng;
                let salt = SaltString::generate(&mut rng);
                let phs = Argon2::default()
                    .hash_password(p.as_bytes(), &salt)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
                    .to_string();
                // create SCRAM verifier JSON with a reasonable iteration count
                // SASLprep rejects some passwords (e.g. control characters);
                // those get no SCRAM verifier but can still use PLAIN/LOGIN.
                let scram = rmail_common::auth::create_scram_verifier(&p, 4096).ok();
                (phs, scram)
            } else {
                (String::new(), None)
            };

            if let Some(at) = address.find('@') {
                let local = &address[..at];
                let domain = &address[at + 1..];
                let mail_root = cfg.global.mail_root.clone();
                let maildir_path = if let Some(md) = maildir_opt {
                    md
                } else {
                    format!("{}/{}/{}/Maildir", mail_root, domain, local)
                };
                // ensure directories exist
                maildir::ensure_maildir(Path::new(&maildir_path))?;

                {
                    let dbp = &cfg.global.db_path;
                    // ensure DB initialized
                    rmail_common::db::init_db(dbp)?;
                    rmail_common::db::add_mailbox(
                        dbp,
                        &address.to_ascii_lowercase(),
                        if ph.is_empty() { None } else { Some(&ph) },
                        Some(&maildir_path),
                        scram_json.as_deref(),
                    )?;
                    if let Some(quota_mib) = quota_mib {
                        let quota_bytes = if quota_mib == 0 {
                            None
                        } else {
                            Some(
                                quota_mib
                                    .checked_mul(1024 * 1024)
                                    .ok_or_else(|| anyhow::anyhow!("quota is too large"))?,
                            )
                        };
                        rmail_common::db::set_mailbox_quota(
                            dbp,
                            &address.to_ascii_lowercase(),
                            quota_bytes,
                        )?;
                        rmail_common::imap_state::set_storage_quota(
                            Path::new(&cfg.global.mail_root),
                            domain,
                            local,
                            quota_bytes,
                        )?;
                    }
                    println!("Added mailbox {} into DB at {}", address, dbp);
                }
            } else {
                eprintln!("Invalid address '{}'", address);
            }
        }
        Commands::List { config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            for m in rmail_common::db::list_mailboxes(&cfg.global.db_path)? {
                match m.quota_bytes {
                    Some(limit) => println!("{} quota={} MiB", m.address, limit / 1024 / 1024),
                    None => println!("{} quota=unlimited", m.address),
                }
            }
        }
        Commands::SearchReindex {
            address,
            all,
            config,
        } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let root = Path::new(&cfg.global.mail_root);
            let mut removed = 0usize;
            match (address, all) {
                (Some(address), false) => {
                    let address = rmail_common::domain::canonicalize_mailbox_address(&address)?;
                    let (local, domain) = address
                        .rsplit_once('@')
                        .ok_or_else(|| anyhow::anyhow!("not a mailbox address: {address}"))?;
                    removed += usize::from(rmail_common::search_index::remove_index(
                        root, domain, local,
                    )?);
                }
                (None, true) => {
                    for (domain, local, _) in rmail_common::imap_state::list_accounts(root)? {
                        removed += usize::from(rmail_common::search_index::remove_index(
                            root, &domain, &local,
                        )?);
                    }
                }
                _ => anyhow::bail!("give an account address, or --all (not both)"),
            }
            println!("removed {removed} search index(es); they rebuild on the next search");
        }
        Commands::Watch {
            mail_root,
            plain,
            history,
        } => {
            let root = mail_root
                .or_else(|| std::env::var("RMAIL_MAIL_ROOT").ok())
                .unwrap_or_else(|| "./mail".into());
            #[cfg(unix)]
            rmail_queuectl::watch::run(Path::new(&root), plain, history)?;
            #[cfg(not(unix))]
            anyhow::bail!("watch requires Unix-domain sockets");
        }
        Commands::Track {
            message_id,
            mail_root,
            limit,
        } => {
            let root = mail_root
                .or_else(|| std::env::var("RMAIL_MAIL_ROOT").ok())
                .unwrap_or_else(|| "./mail".into());
            for event in
                rmail_common::tracking::recent_events(Path::new(&root), limit, Some(&message_id))?
            {
                println!("{}", serde_json::to_string(&event)?);
            }
        }
        Commands::SendDmarcReports { config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let dbp = cfg.global.db_path.to_string();
            // Reports are DKIM-signed like other queued mail.
            rmail_common::dkim::use_database(&dbp);
            let domains = rmail_common::db::get_unreported_dmarc_domains(&dbp)?;
            if domains.is_empty() {
                println!("No unreported DMARC events");
            } else {
                for domain in domains {
                    let events =
                        rmail_common::db::fetch_unreported_dmarc_events_for_domain(&dbp, &domain)?;
                    if events.is_empty() {
                        continue;
                    }
                    // Build a simple aggregate XML report
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                    let begin = events.first().map(|e| e.7).unwrap_or(now - 86400);
                    let end = events.last().map(|e| e.7).unwrap_or(now);
                    let report_id = format!("rmail-{}-{}", domain, now);
                    let org_name = "rMail";
                    let org_email = "dmarc-reports@localhost";
                    let policy = rmail_common::mail_auth::get_dmarc_policy(&domain)
                        .await
                        .unwrap_or(None)
                        .unwrap_or_else(|| "none".to_string());

                    let mut records = String::new();
                    for ev in events.iter() {
                        // ev: (id, header_from, envelope_from, source_ip, dkim, spf, dmarc, created_at)
                        let source_ip = ev.3.clone().unwrap_or_else(|| "0.0.0.0".to_string());
                        let header_from = ev.1.clone().unwrap_or_else(|| domain.clone());
                        let dkim_res = ev.4.clone().unwrap_or_else(|| "none".to_string());
                        let spf_res = ev.5.clone().unwrap_or_else(|| "none".to_string());
                        let disposition = ev.6.clone().unwrap_or_else(|| "none".to_string());
                        records.push_str(&format!(
                            r#"  <record>
    <row>
      <source_ip>{}</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>{}</disposition>
        <dkim>{}</dkim>
        <spf>{}</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>{}</header_from>
    </identifiers>
  </record>
"#,
                            source_ip, disposition, dkim_res, spf_res, header_from
                        ));
                    }

                    let xml = format!(
                        r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<feedback>
  <report_metadata>
    <org_name>{}</org_name>
    <email>{}</email>
    <report_id>{}</report_id>
    <date_range>
      <begin>{}</begin>
      <end>{}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>{}</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>{}</p>
    <sp>{}</sp>
    <pct>100</pct>
  </policy_published>
{}
</feedback>
"#,
                        org_name, org_email, report_id, begin, end, domain, policy, policy, records
                    );

                    // enqueue to each rua recipient
                    let ruas = rmail_common::mail_auth::get_dmarc_rua(&domain).await?;
                    if ruas.is_empty() {
                        eprintln!("No rua recipients found for {}", domain);
                        continue;
                    }
                    for rua in ruas.iter() {
                        // Build a simple email with XML body
                        let email = format!(
                            "From: {}\r\nTo: {}\r\nSubject: DMARC aggregate report for {}\r\nMIME-Version: 1.0\r\nContent-Type: application/xml; charset=utf-8\r\n\r\n{}",
                            org_email, rua, domain, xml
                        );
                        // enqueue via on-disk queue (avoid SQLite for queues)
                        let mail_root = cfg.global.mail_root.clone();
                        let _ = rmail_common::outbound::queue_outbound(
                            std::path::Path::new(&mail_root),
                            rua,
                            email.as_bytes(),
                            Some(org_email),
                        )?;
                    }

                    // mark events reported
                    let ids: Vec<i64> = events.iter().map(|e| e.0).collect();
                    rmail_common::db::mark_dmarc_events_reported(&dbp, &ids)?;
                    println!(
                        "Enqueued DMARC report for {} -> {} recipients",
                        domain,
                        ruas.len()
                    );
                }
            }
        }
        Commands::Service { action } => match action {
            ServiceAction::Start(opts) => run_service_action("start", opts)?,
            ServiceAction::Stop(opts) => run_service_action("stop", opts)?,
            ServiceAction::Restart(opts) => run_service_action("restart", opts)?,
            ServiceAction::Reload(opts) => reload_services(opts)?,
            ServiceAction::Status(opts) => run_service_action("status", opts)?,
            ServiceAction::ApplyRequest { file } => apply_restart_request(&file)?,
        },
        Commands::Transport { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            run_transport(action, std::path::Path::new(&cfg.global.db_path))?;
        }
        Commands::Share { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            run_share(
                action,
                std::path::Path::new(&cfg.global.mail_root),
                std::path::Path::new(&cfg.global.db_path),
            )?;
        }
        Commands::Dkim { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db_path = cfg.global.db_path.as_str();
            run_dkim(action, std::path::Path::new(db_path))?;
        }
        Commands::Acme { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            run_acme(action, &cfg).await?;
        }
    }
    Ok(())
}

fn run_share(
    action: ShareAction,
    mail_root: &std::path::Path,
    db_path: &std::path::Path,
) -> Result<()> {
    use rmail_common::dav::{share, store};
    use rmail_common::{acl, imap_state};
    let account = |address: &str| -> Result<(String, String)> {
        let address = rmail_common::domain::canonicalize_mailbox_address(address)?;
        if !rmail_common::db::mailbox_exists(db_path, &address)? {
            anyhow::bail!("no mailbox {address}");
        }
        let (local, domain) = address.split_once('@').context("invalid address")?;
        Ok((local.to_string(), domain.to_string()))
    };
    match action {
        ShareAction::List { address } => {
            let (local, domain) = account(&address)?;
            let folders = imap_state::list_folders(mail_root, &domain, &local)?;
            let grants = acl::granted_by(db_path, &address)?;
            let mut shown = false;
            for (mailbox_id, grantee, rights) in &grants {
                // Grants left on folders that no longer exist are skipped.
                if let Some(folder) = folders.iter().find(|f| &f.mailbox_id == mailbox_id) {
                    println!("shares   {:<24} with {grantee} ({rights})", folder.name);
                    shown = true;
                }
            }
            for shared in acl::shared_mailboxes(mail_root, db_path, &address)? {
                println!(
                    "receives {:<24} from {} ({})",
                    shared.folder.name, shared.owner, shared.rights
                );
                shown = true;
            }
            let collection_label = |collection: &store::Collection| {
                let kind = match collection.kind {
                    store::Kind::Calendar => "calendar",
                    store::Kind::AddressBook => "addressbook",
                };
                format!("{kind} {}", collection.name)
            };
            let granted =
                share::with_collections(mail_root, share::granted_by(db_path, &address)?)?;
            for (grant, collection) in granted {
                println!(
                    "shares   {:<24} with {} ({})",
                    collection_label(&collection),
                    grant.grantee,
                    grant.access.as_str()
                );
                shown = true;
            }
            let received =
                share::with_collections(mail_root, share::shared_with(db_path, &address)?)?;
            for (grant, collection) in received {
                println!(
                    "receives {:<24} from {} ({})",
                    collection_label(&collection),
                    grant.owner,
                    grant.access.as_str()
                );
                shown = true;
            }
            if !shown {
                println!("Nothing shared by or with {address}.");
            }
        }
        ShareAction::Set {
            owner,
            folder,
            grantee,
            rights,
        } => {
            let (local, domain) = account(&owner)?;
            let found = imap_state::find_folder(mail_root, &domain, &local, &folder)?
                .with_context(|| format!("{owner} has no folder {folder}"))?;
            let rights = if rights == "none" {
                acl::Rights::NONE
            } else {
                acl::Rights::parse(&rights)?
            };
            acl::set_rights(db_path, &owner, &found.mailbox_id, &grantee, rights)?;
            if rights.is_empty() {
                println!("{folder} of {owner} is no longer shared with {grantee}");
            } else {
                println!("{grantee} now has {rights} on {folder} of {owner}");
            }
        }
        ShareAction::Calendar {
            owner,
            name,
            grantee,
            access,
        } => share_collection(
            mail_root,
            db_path,
            store::Kind::Calendar,
            &owner,
            &name,
            &grantee,
            &access,
        )?,
        ShareAction::Addressbook {
            owner,
            name,
            grantee,
            access,
        } => share_collection(
            mail_root,
            db_path,
            store::Kind::AddressBook,
            &owner,
            &name,
            &grantee,
            &access,
        )?,
    }
    Ok(())
}

/// `rmail_ctl share calendar|addressbook`: grant or stop sharing one of
/// OWNER's collections.
fn share_collection(
    mail_root: &std::path::Path,
    db_path: &std::path::Path,
    kind: rmail_common::dav::store::Kind,
    owner: &str,
    name: &str,
    grantee: &str,
    access: &str,
) -> Result<()> {
    use rmail_common::dav::share;
    let owner = rmail_common::domain::canonicalize_mailbox_address(owner)?;
    if !rmail_common::db::mailbox_exists(db_path, &owner)? {
        anyhow::bail!("no mailbox {owner}");
    }
    let collection = share::own_collections(mail_root, &owner, kind)?
        .into_iter()
        .find(|collection| collection.name == name)
        .with_context(|| format!("{owner} has no such collection {name}"))?;
    let access = match access {
        "none" => None,
        access => {
            Some(share::Access::parse(access).context("access must be read, read-write or none")?)
        }
    };
    share::set_access(db_path, &owner, collection.id, grantee, access)?;
    match access {
        None => println!("{name} of {owner} is no longer shared with {grantee}"),
        Some(access) => println!(
            "{grantee} now has {} access to {name} of {owner}",
            access.as_str()
        ),
    }
    Ok(())
}

fn run_transport(action: TransportAction, db_path: &std::path::Path) -> Result<()> {
    use rmail_common::transport::{self, RouteAction};
    let describe = |route: &transport::Route| match &route.action {
        RouteAction::Relay {
            host,
            port,
            implicit_tls,
            username,
            ..
        } => format!(
            "{:<24} relay {host}:{port}{}{}",
            route.domain,
            if *implicit_tls { " (implicit TLS)" } else { "" },
            username
                .as_ref()
                .map(|user| format!(" as {user}"))
                .unwrap_or_default()
        ),
        RouteAction::Reject { reply } => format!("{:<24} reject {reply}", route.domain),
    };
    match action {
        TransportAction::List => {
            let routes = transport::list_routes(db_path)?;
            if routes.is_empty() {
                println!("No routes; mail goes to each domain's MX hosts.");
            }
            for route in &routes {
                println!("{}", describe(route));
            }
        }
        TransportAction::Relay {
            domain,
            relay,
            implicit_tls,
            user,
            password,
        } => {
            let (host, port) = match relay.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => (
                    host.to_string(),
                    port.parse::<u16>()
                        .with_context(|| format!("invalid port in {relay}"))?,
                ),
                _ => (relay.clone(), if implicit_tls { 465 } else { 25 }),
            };
            let password = match (&user, password) {
                (Some(_), None) => {
                    eprint!("Relay password: ");
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    Some(line.trim_end_matches(['\r', '\n']).to_string())
                }
                (_, password) => password,
            };
            let route = transport::set_route(
                db_path,
                &domain,
                RouteAction::Relay {
                    host,
                    port,
                    implicit_tls,
                    username: user,
                    password,
                },
            )?;
            println!("{}", describe(&route));
        }
        TransportAction::Reject { domain, reply } => {
            let route = transport::set_route(db_path, &domain, RouteAction::Reject { reply })?;
            println!("{}", describe(&route));
        }
        TransportAction::Remove { domain } => {
            if !transport::delete_route(db_path, &domain)? {
                anyhow::bail!("no route for {domain}");
            }
        }
    }
    Ok(())
}

fn run_dkim(action: DkimAction, db_path: &std::path::Path) -> Result<()> {
    use rmail_common::dkim;
    let print = |key: &dkim::DkimKey| {
        println!(
            "{}  {}{}\n  TXT {}",
            key.dns_name(),
            key.algorithm.as_str(),
            if key.arc { "  (ARC)" } else { "" },
            key.dns_record
        );
    };
    match action {
        DkimAction::List => {
            let keys = dkim::list_keys(db_path)?;
            if keys.is_empty() {
                println!("No DKIM keys; outbound mail is not signed.");
            }
            keys.iter().for_each(print);
        }
        DkimAction::Add {
            domain,
            selector,
            algorithm,
            private_key,
        } => {
            let pem = private_key
                .map(|path| {
                    std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))
                })
                .transpose()?;
            let key = dkim::add_key(
                db_path,
                &domain,
                &selector,
                dkim::Algorithm::parse(&algorithm)?,
                pem.as_deref(),
            )?;
            println!(
                "Publish this record, then mail from {} is signed with it:",
                key.domain
            );
            print(&key);
        }
        DkimAction::Remove { domain, selector } => {
            if !dkim::delete_key(db_path, &domain, &selector)? {
                anyhow::bail!("no key {selector}._domainkey.{domain}");
            }
        }
        DkimAction::SetArc { domain, selector } => {
            dkim::set_arc_key(db_path, Some((&domain, &selector)))?
        }
        DkimAction::ClearArc => dkim::set_arc_key(db_path, None)?,
    }
    Ok(())
}

async fn run_acme(action: AcmeAction, cfg: &Config) -> Result<()> {
    use rmail_common::acme;
    // Progress is printed as text; keep the JSON log for problems only.
    rmail_common::runtime::set_log_level(Some("warn"));
    match action {
        AcmeAction::Issue { test } => {
            if !test && !cfg.acme.enabled {
                anyhow::bail!(
                    "automatic certificates are off; enable them with `rmail_ctl settings set acme.enabled true` (or run with --test)"
                );
            }
            let outcome = acme::run(
                cfg,
                acme::RunOptions {
                    trigger: "cli".into(),
                    dry_run: test,
                    echo: true,
                },
            )
            .await?;
            if outcome.settings_updated {
                restart_for_tls()?;
            }
        }
        AcmeAction::Renew => match acme::renew_if_due(cfg, "cli").await? {
            Some(outcome) => println!(
                "Renewed; valid until {}",
                acme::format_time(outcome.not_after)
            ),
            None if !cfg.acme.enabled => println!("Automatic certificates are off"),
            None => {
                let db_path = cfg.global.db_path.as_str();
                let status = acme::load_status(db_path)?;
                match status.retry_after {
                    Some(at) if at > now_secs() => println!(
                        "Waiting until {} after {} failed attempt(s); use `rmail_ctl acme issue` to retry now",
                        acme::format_time(at),
                        status.consecutive_failures
                    ),
                    _ => println!("Not due: {}", acme::renewal_check(cfg, &status).reason),
                }
            }
        },
        AcmeAction::Status => {
            let (cert_path, key_path, _) = acme::certificate_paths(cfg);
            println!(
                "Automatic certificates: {}",
                if cfg.acme.enabled { "on" } else { "off" }
            );
            match acme::certificate_names(cfg) {
                Ok(names) => println!("Names: {}", names.join(", ")),
                Err(error) => println!("Names: {error:#}"),
            }
            println!("Certificate: {}", cert_path.display());
            println!("Private key: {}", key_path.display());
            match acme::cert::inspect_file(&cert_path) {
                Ok(info) => {
                    println!("  names:   {}", info.names.join(", "));
                    println!("  issuer:  {}", info.issuer);
                    println!("  expires: {}", acme::format_time(info.not_after));
                }
                Err(error) => println!("  {error:#}"),
            }
            let db_path = cfg.global.db_path.as_str();
            let status = acme::load_status(db_path)?;
            if cfg.acme.enabled {
                println!("Renewal: {}", acme::renewal_check(cfg, &status).reason);
            }
            if let Some(run) = status.last_run {
                println!(
                    "Last run ({}{}): {} at {}",
                    run.trigger,
                    if run.dry_run { ", test" } else { "" },
                    match run.ok {
                        Some(true) => "succeeded".to_string(),
                        Some(false) => format!("failed: {}", run.error.unwrap_or_default()),
                        None => "in progress".to_string(),
                    },
                    acme::format_time(run.started_at)
                );
            }
        }
    }
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn selected_units(opts: &ServiceCommandOptions, reverse: bool) -> Result<Vec<&'static str>> {
    let mut units = if opts.units.is_empty() {
        RMAIL_SYSTEMD_UNITS.to_vec()
    } else {
        opts.units
            .iter()
            .map(|u| normalize_unit_name(u))
            .collect::<Result<Vec<_>>>()?
    };
    if reverse {
        units.reverse();
    }
    Ok(units)
}

fn normalize_unit_name(name: &str) -> Result<&'static str> {
    let trimmed = name.trim();
    for unit in RMAIL_SYSTEMD_UNITS {
        if trimmed == *unit {
            return Ok(unit);
        }
        if let Some(short) = unit
            .strip_prefix("rmail_")
            .and_then(|s| s.strip_suffix(".service"))
            && trimmed == short
        {
            return Ok(unit);
        }
    }
    Err(anyhow::anyhow!(
        "unknown rMail service {trimmed:?}; expected one of: {}",
        RMAIL_SYSTEMD_UNITS.join(", ")
    ))
}

/// Consume an admin-console request and return its units in restart order, the
/// web console last so its own restart cannot cut the others short. The file
/// is removed first so a failing unit cannot make the path unit re-trigger.
fn take_restart_request(file: &str) -> Result<Vec<&'static str>> {
    let path = std::path::Path::new(file);
    let services = rmail_common::restart::read_request(path);
    std::fs::remove_file(path).ok();
    let mut units = services?
        .iter()
        .map(|name| normalize_unit_name(name))
        .collect::<Result<Vec<_>>>()?;
    units.sort_by_key(|unit| *unit == "rmail_web.service");
    Ok(units)
}

fn apply_restart_request(file: &str) -> Result<()> {
    for unit in take_restart_request(file)? {
        run_systemctl("restart", unit, false)?;
    }
    Ok(())
}

/// A first certificate needs one restart of the TLS services; offer it
/// (or print the command when there is nobody to ask).
fn restart_for_tls() -> Result<()> {
    use std::io::{IsTerminal, Write};
    let command = "rmail_ctl service restart";
    if !std::io::stdin().is_terminal() {
        println!("Restart the services once to enable TLS: {command}");
        return Ok(());
    }
    print!("Restart the rMail services now to enable TLS? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        run_service_action(
            "restart",
            ServiceCommandOptions {
                units: Vec::new(),
                dry_run: false,
            },
        )
    } else {
        println!("Restart later with: {command}");
        Ok(())
    }
}

fn run_service_action(action: &str, opts: ServiceCommandOptions) -> Result<()> {
    let units = selected_units(&opts, action == "stop")?;
    for unit in units {
        run_systemctl(action, unit, opts.dry_run)?;
    }
    Ok(())
}

fn reload_services(opts: ServiceCommandOptions) -> Result<()> {
    let units = selected_units(&opts, false)?;
    for unit in units {
        if opts.dry_run {
            println!("systemctl reload {unit}");
            println!("systemctl restart {unit} # fallback if reload fails");
            continue;
        }
        let status = Command::new("systemctl").arg("reload").arg(unit).status();
        match status {
            Ok(s) if s.success() => println!("reloaded {unit}"),
            Ok(_) | Err(_) => {
                eprintln!("reload unsupported or failed for {unit}; restarting");
                run_systemctl("restart", unit, false)?;
            }
        }
    }
    Ok(())
}

fn run_systemctl(action: &str, unit: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("systemctl {action} {unit}");
        return Ok(());
    }
    let status = Command::new("systemctl")
        .arg(action)
        .arg(unit)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run systemctl {action} {unit}: {e}"))?;
    if status.success() {
        println!("{action} {unit}: ok");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "systemctl {action} {unit} exited with {status}"
        ))
    }
}

fn run_settings(
    conn: &mut rmail_common::settings::Connection,
    action: SettingsAction,
) -> Result<()> {
    use rmail_common::settings;
    match action {
        SettingsAction::List => {
            let view = settings::describe(conn)?;
            println!("settings revision {}", view.revision);
            for group in view.groups {
                println!("\n[{}]", group.label);
                for setting in view.settings.iter().filter(|s| s.spec.group == group.id) {
                    let shown = match (&setting.value, setting.is_set) {
                        (Some(value), _) => value.to_string(),
                        (None, true) => "<secret set>".to_string(),
                        (None, false) => match &setting.default {
                            Some(default) => format!("{default} (default)"),
                            None => "(unset)".to_string(),
                        },
                    };
                    println!("  {:<48} {}", setting.spec.key, shown);
                }
            }
            for service in &view.services {
                if service.restart_required {
                    println!(
                        "\nrestart {} to apply: {}",
                        service.service,
                        service.pending_changes.join(", ")
                    );
                }
            }
        }
        SettingsAction::Get { key } => {
            if settings::RESERVED_KEYS.contains(&key.as_str())
                || key.starts_with(settings::INTERNAL_PREFIX)
                || settings::spec_for(&key)
                    .is_some_and(|spec| matches!(spec.kind, settings::SettingKind::Secret))
            {
                anyhow::bail!("{key} is write-only");
            }
            match settings::get(conn, &key)? {
                Some(value) => println!("{value}"),
                None => println!("null"),
            }
        }
        SettingsAction::Set { key, value } => {
            let parsed = serde_json::from_str(&value)
                .unwrap_or_else(|_| serde_json::Value::String(value.clone()));
            let revision = settings::update(
                conn,
                &std::collections::BTreeMap::from([(key.clone(), parsed)]),
            )?;
            match settings::spec_for(&key).map(|spec| spec.services) {
                Some([]) => println!("{key} updated (revision {revision}); applies immediately"),
                _ => println!(
                    "{key} updated (revision {revision}); restart affected services to apply"
                ),
            }
        }
        SettingsAction::Unset { key } => {
            let revision = settings::update(
                conn,
                &std::collections::BTreeMap::from([(key.clone(), serde_json::Value::Null)]),
            )?;
            println!("{key} reset to default (revision {revision})");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ServiceCommandOptions, normalize_unit_name, selected_units, take_restart_request};

    #[test]
    fn normalizes_service_short_names() {
        assert_eq!(normalize_unit_name("smtpd").unwrap(), "rmail_smtpd.service");
        assert_eq!(
            normalize_unit_name("rmail_webmail.service").unwrap(),
            "rmail_webmail.service"
        );
        assert!(normalize_unit_name("unknown").is_err());
    }

    #[test]
    fn restart_request_is_consumed_with_web_last() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("restart-request");
        std::fs::write(&file, "web\nsmtpd\nwebmail\n").unwrap();
        let units = take_restart_request(file.to_str().unwrap()).unwrap();
        assert_eq!(
            units,
            [
                "rmail_smtpd.service",
                "rmail_webmail.service",
                "rmail_web.service"
            ]
        );
        assert!(!file.exists());

        // An invalid request is removed too, so it cannot re-trigger the path unit.
        std::fs::write(&file, "sshd\n").unwrap();
        assert!(take_restart_request(file.to_str().unwrap()).is_err());
        assert!(!file.exists());
    }

    #[test]
    fn stop_order_is_reversed() {
        let opts = ServiceCommandOptions {
            units: Vec::new(),
            dry_run: false,
        };
        let units = selected_units(&opts, true).unwrap();
        assert_eq!(units.first().copied(), Some("rmail_classifier.service"));
        assert_eq!(units.last().copied(), Some("rmail_smtpd.service"));
    }
}
