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
    /// Two-factor sign-in: reset a user's, or require it for a domain
    TwoFactor {
        #[command(subcommand)]
        action: TwoFactorAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// How long each domain keeps mail in Trash, Junk and everywhere
    Retention {
        #[command(subcommand)]
        action: RetentionAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Legal hold: nothing in a mailbox can be permanently deleted
    Hold {
        #[command(subcommand)]
        action: HoldAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Journaling: a copy of a domain's mail kept in an archive mailbox
    Journal {
        #[command(subcommand)]
        action: JournalAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Back up or restore the server's data, or one account
    Backup {
        #[command(subcommand)]
        action: BackupAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// Rooms and equipment: mailboxes that answer invitations themselves
    Resource {
        #[command(subcommand)]
        action: ResourceAction,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long, global = true)]
        config: Option<String>,
    },
    /// The global address list, and free-busy visibility across domains
    Directory {
        #[command(subcommand)]
        action: DirectoryAction,
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
    /// Abuse feedback (ARF) reports received at the feedback loop addresses
    /// (security.feedback_addresses)
    Feedback {
        #[command(subcommand)]
        action: FeedbackAction,
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
enum TwoFactorAction {
    /// Whether ADDRESS has two-factor sign-in, and its app passwords
    Status { address: String },
    /// Turn off ADDRESS's two-factor sign-in (a lost phone and no recovery
    /// codes); app passwords stay
    Reset { address: String },
    /// Require two-factor sign-in for every account in DOMAIN
    Require { domain: String },
    /// Stop requiring it for DOMAIN
    Allow { domain: String },
    /// Domains that require it
    Domains,
}

#[derive(Subcommand)]
enum ResourceAction {
    /// Mark ADDRESS as a room or equipment, or as a person again
    Set {
        address: String,
        /// room, equipment or person
        kind: String,
    },
    /// Have APPROVER (a mailbox) approve the bookings of resource ADDRESS
    /// that fit its calendar, or with "none" let it accept them itself
    Approver { address: String, approver: String },
    /// List the resources
    List,
}

#[derive(Subcommand)]
enum RetentionAction {
    /// Set DOMAIN's limits in days (leave one out to keep that mail for good)
    Set {
        domain: String,
        #[arg(long)]
        trash_days: Option<u32>,
        #[arg(long)]
        junk_days: Option<u32>,
        /// delete anything older, in every folder
        #[arg(long)]
        max_age_days: Option<u32>,
    },
    /// Remove DOMAIN's limits
    Clear { domain: String },
    /// List the domains with limits
    List,
    /// Apply the limits now (webmail does so hourly)
    Run,
}

#[derive(Subcommand)]
enum HoldAction {
    /// Put ADDRESS on legal hold
    On { address: String },
    /// Lift ADDRESS's legal hold
    Off { address: String },
    /// Whether ADDRESS is on hold
    Show { address: String },
}

#[derive(Subcommand)]
enum JournalAction {
    /// Journal DOMAIN's mail to ARCHIVE (a mailbox), or "none" to stop
    Set { domain: String, archive: String },
    /// List the journaled domains
    List,
}

#[derive(Subcommand)]
enum BackupAction {
    /// Back up everything (or one account with --account) to FILE (.tar.zst)
    Create {
        file: String,
        #[arg(long)]
        account: Option<String>,
    },
    /// A dated backup in DIR, keeping the newest KEEP (for a nightly timer)
    Rotate {
        dir: String,
        #[arg(long, default_value_t = 7)]
        keep: usize,
    },
    /// What a backup holds
    Show { file: String },
    /// Upload FILE to the configured off-site target (Backup upload settings)
    Upload { file: String },
    /// List the backups at the off-site target
    Remote,
    /// Download backup NAME from the off-site target to FILE
    Fetch { name: String, file: String },
    /// Restore a backup. A full one needs the services stopped; --force
    /// moves existing data aside first. An account backup can go to
    /// another address with --as.
    Restore {
        file: String,
        #[arg(long)]
        force: bool,
        #[arg(long = "as")]
        as_address: Option<String>,
    },
}

#[derive(Subcommand)]
enum DirectoryAction {
    /// Give everyone in DOMAIN a read-only Directory address book of its people
    Enable { domain: String },
    /// Remove it again
    Disable { domain: String },
    /// Let every domain on this server see DOMAIN's free-busy times (on),
    /// or keep them within the domain (off, the default)
    FreeBusy {
        domain: String,
        #[arg(value_parser = ["on", "off"])]
        shared: String,
    },
    /// Domains that have a directory or share free-busy times
    List,
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
enum FeedbackAction {
    /// Newest reports, optionally only those about one account or domain
    List {
        /// account address or domain
        #[arg(long)]
        account: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// one JSON object per line
        #[arg(long)]
        json: bool,
    },
    /// Complaints per sender: who draws the most
    Summary {
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
    /// Delete one report by its id
    Delete { id: i64 },
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

/// The off-site backup target, or an error saying it is not set up.
fn offsite_target(
    cfg: &Config,
    sources: &rmail_common::backup::Sources,
) -> Result<rmail_common::offsite::Target> {
    rmail_common::offsite::target(&cfg.backup_upload, &sources.mail_root)?.ok_or_else(|| {
        anyhow::anyhow!("no backup upload target is set (Backup upload settings in the console)")
    })
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
        Commands::TwoFactor { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            run_two_factor(
                action,
                std::path::Path::new(&cfg.global.db_path),
                &mut std::io::stdout(),
            )?;
        }
        Commands::Retention { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db = std::path::Path::new(&cfg.global.db_path);
            let days = |d: Option<u32>| d.map_or("keep".to_string(), |d| format!("{d} days"));
            match action {
                RetentionAction::Set {
                    domain,
                    trash_days,
                    junk_days,
                    max_age_days,
                } => {
                    let policy = rmail_common::retention::Policy {
                        trash_days,
                        junk_days,
                        max_age_days,
                    };
                    rmail_common::retention::set(db, &domain, &policy)?;
                    println!(
                        "{domain}: Trash {}, Junk {}, all mail {}",
                        days(trash_days),
                        days(junk_days),
                        days(max_age_days)
                    );
                }
                RetentionAction::Clear { domain } => {
                    rmail_common::retention::set(db, &domain, &Default::default())?;
                    println!("{domain} keeps all mail");
                }
                RetentionAction::List => {
                    for (domain, policy) in rmail_common::retention::list(db)? {
                        println!(
                            "{domain}\ttrash {}\tjunk {}\tall mail {}",
                            days(policy.trash_days),
                            days(policy.junk_days),
                            days(policy.max_age_days)
                        );
                    }
                }
                RetentionAction::Run => {
                    let report = rmail_common::retention::sweep(
                        db,
                        std::path::Path::new(&cfg.global.mail_root),
                        chrono::Utc::now().timestamp(),
                    )?;
                    println!(
                        "deleted {} messages; {} accounts on hold left alone",
                        report.deleted, report.held
                    );
                    for error in report.errors {
                        eprintln!("{error}");
                    }
                }
            }
        }
        Commands::Hold { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db = std::path::Path::new(&cfg.global.db_path);
            let root = std::path::Path::new(&cfg.global.mail_root);
            let (address, on) = match &action {
                HoldAction::On { address } => (address.clone(), Some(true)),
                HoldAction::Off { address } => (address.clone(), Some(false)),
                HoldAction::Show { address } => (address.clone(), None),
            };
            let address = address.trim().to_ascii_lowercase();
            if !rmail_common::db::mailbox_exists(db, &address)? {
                anyhow::bail!("no mailbox {address}");
            }
            let (local, domain) = address
                .split_once('@')
                .ok_or_else(|| anyhow::anyhow!("invalid address"))?;
            rmail_common::imap_state::init_account(root, domain, local)?;
            if let Some(on) = on {
                rmail_common::imap_state::set_legal_hold(root, domain, local, on)?;
            }
            let held = rmail_common::imap_state::legal_hold(root, domain, local)?;
            println!(
                "{address} is {}",
                if held { "on legal hold" } else { "not on hold" }
            );
        }
        Commands::Journal { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db = std::path::Path::new(&cfg.global.db_path);
            match action {
                JournalAction::Set { domain, archive } => {
                    let archive = Some(archive.trim()).filter(|a| !a.eq_ignore_ascii_case("none"));
                    rmail_common::journal::set(db, &domain, archive)?;
                    match archive {
                        Some(archive) => println!("{domain}'s mail is journaled to {archive}"),
                        None => println!("{domain}'s mail is not journaled"),
                    }
                }
                JournalAction::List => {
                    for (domain, archive) in rmail_common::journal::list(db)? {
                        println!("{domain}\t{archive}");
                    }
                }
            }
        }
        Commands::Backup { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            // A restore reads the paths from the file alone: loading the
            // configuration would create the database it is about to restore.
            let cfg = if matches!(action, BackupAction::Restore { .. }) {
                let raw: Config = toml::from_str(
                    &std::fs::read_to_string(&cfg_path)
                        .with_context(|| format!("reading {cfg_path}"))?,
                )
                .with_context(|| format!("parsing {cfg_path}"))?;
                raw
            } else {
                Config::load(&cfg_path)?
            };
            let sources = rmail_common::backup::Sources {
                // Files this user cannot read (a root-owned config) are left out.
                config: Some(std::path::PathBuf::from(&cfg_path))
                    .filter(|p| std::fs::File::open(p).is_ok()),
                db: std::path::PathBuf::from(&cfg.global.db_path),
                mail_root: std::path::PathBuf::from(&cfg.global.mail_root),
                // Always certificate then key: a backup's tls/<n> is matched by
                // position, and an unset one is an empty placeholder.
                tls: [&cfg.global.tls_cert, &cfg.global.tls_key]
                    .into_iter()
                    .map(|p| std::path::PathBuf::from(p.as_deref().unwrap_or_default()))
                    .collect(),
            };
            let size = |bytes: u64| format!("{:.1} MB", bytes as f64 / 1_000_000.0);
            match action {
                BackupAction::Create { file, account } => {
                    let out = std::path::Path::new(&file);
                    let summary = match &account {
                        Some(address) => {
                            rmail_common::backup::create_account(&sources.mail_root, address, out)?
                        }
                        None => rmail_common::backup::create_full(&sources, out)?,
                    };
                    println!("{file}: {} files, {}", summary.files, size(summary.bytes));
                }
                BackupAction::Rotate { dir, keep } => {
                    let (out, summary) = rmail_common::backup::create_in_dir(
                        &sources,
                        std::path::Path::new(&dir),
                        keep,
                    )?;
                    println!(
                        "{}: {} files, {}",
                        out.display(),
                        summary.files,
                        size(summary.bytes)
                    );
                    // A copy off the machine, when set up. The local backup
                    // stands even if this fails (the exit status says so).
                    if let Some(target) =
                        rmail_common::offsite::target(&cfg.backup_upload, &sources.mail_root)?
                    {
                        let pruned = target
                            .upload_and_prune(&out, cfg.backup_upload.keep)
                            .await
                            .with_context(|| format!("uploading to {}", target.describe()))?;
                        println!("uploaded to {}", target.describe());
                        for name in pruned {
                            println!("deleted the older {name} there");
                        }
                    }
                }
                BackupAction::Upload { file } => {
                    let target = offsite_target(&cfg, &sources)?;
                    let name = target.upload(std::path::Path::new(&file)).await?;
                    println!("uploaded {name} to {}", target.describe());
                }
                BackupAction::Remote => {
                    let target = offsite_target(&cfg, &sources)?;
                    for name in target.list().await? {
                        println!("{name}");
                    }
                }
                BackupAction::Fetch { name, file } => {
                    let target = offsite_target(&cfg, &sources)?;
                    target.download(&name, std::path::Path::new(&file)).await?;
                    println!("downloaded {name} to {file}");
                }
                BackupAction::Show { file } => {
                    let manifest =
                        rmail_common::backup::read_manifest(std::path::Path::new(&file))?;
                    let when = chrono::DateTime::from_timestamp(manifest.created, 0)
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default();
                    match manifest.account {
                        Some(account) => println!(
                            "account backup of {account}, made {when} by rMail {}",
                            manifest.version
                        ),
                        None => println!("full backup, made {when} by rMail {}", manifest.version),
                    }
                }
                BackupAction::Restore {
                    file,
                    force,
                    as_address,
                } => {
                    let path = std::path::Path::new(&file);
                    let manifest = rmail_common::backup::read_manifest(path)?;
                    let summary = if manifest.kind == "account" {
                        rmail_common::backup::restore_account(
                            path,
                            &sources.mail_root,
                            as_address.as_deref(),
                            force,
                        )?
                    } else {
                        if as_address.is_some() {
                            anyhow::bail!("--as is for account backups");
                        }
                        rmail_common::backup::restore_full(path, &sources, force)?
                    };
                    println!("restored {} files, {}", summary.files, size(summary.bytes));
                }
            }
        }
        Commands::Resource { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db = std::path::Path::new(&cfg.global.db_path);
            match action {
                ResourceAction::Set { address, kind } => {
                    let parsed = match kind.as_str() {
                        "person" | "none" => None,
                        other => Some(
                            rmail_common::resources::ResourceKind::parse(other).ok_or_else(
                                || anyhow::anyhow!("kind must be room, equipment or person"),
                            )?,
                        ),
                    };
                    rmail_common::resources::set(db, &address, parsed)?;
                    println!(
                        "{address} is now a {}",
                        parsed.map_or("person", |k| k.as_str())
                    );
                }
                ResourceAction::Approver { address, approver } => {
                    let approver =
                        Some(approver.trim()).filter(|a| !a.eq_ignore_ascii_case("none"));
                    rmail_common::resources::set_approver(db, &address, approver)?;
                    match approver {
                        Some(approver) => println!("{approver} now approves bookings of {address}"),
                        None => println!("{address} answers its bookings itself"),
                    }
                }
                ResourceAction::List => {
                    let approvers: std::collections::HashMap<String, String> =
                        rmail_common::resources::approvers(db)?
                            .into_iter()
                            .collect();
                    for (address, kind) in rmail_common::resources::list(db, None)? {
                        match approvers.get(&address) {
                            Some(approver) => {
                                println!("{address}\t{}\tapproved by {approver}", kind.as_str())
                            }
                            None => println!("{address}\t{}", kind.as_str()),
                        }
                    }
                }
            }
        }
        Commands::Directory { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db = std::path::Path::new(&cfg.global.db_path);
            let root = std::path::Path::new(&cfg.global.mail_root);
            match action {
                DirectoryAction::Enable { domain } => {
                    rmail_common::directory::set_enabled(db, &domain, true)?;
                    let failed = rmail_common::directory::sync_all(db, root)?;
                    println!("{domain} now has a directory");
                    report_directory_failures(&failed);
                }
                DirectoryAction::Disable { domain } => {
                    rmail_common::directory::set_enabled(db, &domain, false)?;
                    let failed = rmail_common::directory::sync_all(db, root)?;
                    println!("{domain} no longer has a directory");
                    report_directory_failures(&failed);
                }
                DirectoryAction::FreeBusy { domain, shared } => {
                    let shared = shared == "on";
                    let domain = domain.trim().to_ascii_lowercase();
                    rmail_common::directory::set_freebusy_shared(db, &domain, shared)?;
                    if shared {
                        println!("{domain}'s free-busy times are visible to every domain here");
                    } else {
                        println!("{domain}'s free-busy times stay within it");
                    }
                }
                DirectoryAction::List => {
                    let directory = rmail_common::directory::enabled_domains(db)?;
                    let freebusy = rmail_common::directory::freebusy_shared_domains(db)?;
                    let mut domains: Vec<&String> = directory.iter().chain(&freebusy).collect();
                    domains.sort();
                    domains.dedup();
                    for domain in domains {
                        let on = |list: &[String]| if list.contains(domain) { "on" } else { "off" };
                        println!(
                            "{domain}\tdirectory={}\tfree-busy={}",
                            on(&directory),
                            on(&freebusy)
                        );
                    }
                }
            }
        }
        Commands::Feedback { action, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::load(&cfg_path)?;
            let db_path = std::path::Path::new(&cfg.global.db_path);
            // Creates the table on databases from before feedback reports.
            rmail_common::db::init_db(db_path)?;
            run_feedback(action, db_path, &mut std::io::stdout())?;
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

/// Accounts whose directory book a sync could not update; webmail's
/// background sync tries them again.
fn report_directory_failures(failed: &[String]) {
    for account in failed {
        eprintln!("warning: directory not updated for {account}");
    }
    if !failed.is_empty() {
        eprintln!("webmail retries these every 30 minutes");
    }
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

fn run_feedback(
    action: FeedbackAction,
    db_path: &std::path::Path,
    out: &mut impl std::io::Write,
) -> Result<()> {
    use rmail_common::feedback;
    match action {
        FeedbackAction::List {
            account,
            limit,
            json,
        } => {
            let reports = feedback::list(db_path, account.as_deref(), limit.clamp(1, 10_000))?;
            if reports.is_empty() && !json {
                writeln!(out, "No feedback reports")?;
            }
            for report in reports {
                if json {
                    writeln!(out, "{}", serde_json::to_string(&report)?)?;
                    continue;
                }
                let received = chrono::DateTime::from_timestamp(report.received_at, 0)
                    .map(|time| time.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_default();
                let sender = report
                    .account
                    .or(report.domain)
                    .unwrap_or_else(|| "(not local)".to_string());
                writeln!(
                    out,
                    "{:>6}  {received}  {:<12} {sender}  from {}{}  {}",
                    report.id,
                    report.feedback_type,
                    report.reporter.as_deref().unwrap_or("?"),
                    if report.authenticated {
                        ""
                    } else {
                        " (unverified)"
                    },
                    report.original_subject.as_deref().unwrap_or(""),
                )?;
            }
        }
        FeedbackAction::Summary { days } => {
            let days = days.clamp(1, 3650);
            let since = chrono::Utc::now().timestamp() - days * 24 * 3600;
            let senders = feedback::summary(db_path, since)?;
            if senders.is_empty() {
                writeln!(out, "No complaints in the last {days} days")?;
            }
            for row in senders {
                let sender = if row.sender.is_empty() {
                    "(not local)"
                } else {
                    row.sender.as_str()
                };
                writeln!(
                    out,
                    "{sender}  complaints={} unverified={}",
                    row.complaints, row.unverified
                )?;
            }
        }
        FeedbackAction::Delete { id } => {
            if !feedback::delete(db_path, id)? {
                anyhow::bail!("no feedback report {id}");
            }
            writeln!(out, "Deleted feedback report {id}")?;
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

    #[test]
    fn feedback_lists_summarizes_and_deletes_reports() {
        use super::{FeedbackAction, run_feedback};
        use rmail_common::feedback;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("rmail.db");
        rmail_common::db::init_db(&db).unwrap();
        let report = feedback::FeedbackReport {
            feedback_type: "abuse".into(),
            reporter: Some("fbl@provider.example".into()),
            report_message_id: Some("r1@provider.example".into()),
            incidents: 1,
            ..Default::default()
        };
        let attribution = feedback::Attribution {
            account: Some("alice@example.test".into()),
            domain: Some("example.test".into()),
            method: Some("from".into()),
        };
        let now = chrono::Utc::now().timestamp();
        let id = feedback::record(&db, "fbl@example.test", &report, &attribution, false, now)
            .unwrap()
            .unwrap();
        let run = |action| {
            let mut out = Vec::new();
            run_feedback(action, &db, &mut out).map(|()| String::from_utf8(out).unwrap())
        };
        let listed = run(FeedbackAction::List {
            account: None,
            limit: 10,
            json: false,
        })
        .unwrap();
        assert!(listed.contains("alice@example.test"), "{listed}");
        assert!(listed.contains("(unverified)"), "{listed}");
        let summary = run(FeedbackAction::Summary { days: 30 }).unwrap();
        assert_eq!(summary, "alice@example.test  complaints=0 unverified=1\n");
        assert!(run(FeedbackAction::Delete { id }).is_ok());
        assert!(run(FeedbackAction::Delete { id }).is_err());
    }
}

fn run_two_factor(
    action: TwoFactorAction,
    db: &std::path::Path,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    use rmail_common::two_factor;
    match action {
        TwoFactorAction::Status { address } => {
            let status = two_factor::status(db, &address)?;
            writeln!(
                out,
                "two-factor: {}",
                if status.enabled {
                    format!("on, {} recovery codes left", status.recovery_left)
                } else if two_factor::setup_required(db, &address)? {
                    "off (required by its domain; set up at next webmail sign-in)".to_string()
                } else {
                    "off".to_string()
                }
            )?;
            for app in two_factor::app_passwords(db, &address)? {
                writeln!(
                    out,
                    "app password {}: {} (last used {})",
                    app.id,
                    app.name,
                    app.last_used_at
                        .map_or("never".to_string(), |at| at.to_string())
                )?;
            }
        }
        TwoFactorAction::Reset { address } => {
            if two_factor::disable(db, &address)? {
                writeln!(out, "two-factor sign-in turned off for {address}")?;
            } else {
                writeln!(out, "{address} did not have two-factor sign-in")?;
            }
        }
        TwoFactorAction::Require { domain } => {
            two_factor::set_required(db, &domain, true)?;
            writeln!(out, "{domain} now requires two-factor sign-in")?;
        }
        TwoFactorAction::Allow { domain } => {
            two_factor::set_required(db, &domain, false)?;
            writeln!(out, "{domain} no longer requires two-factor sign-in")?;
        }
        TwoFactorAction::Domains => {
            for domain in two_factor::required_domains(db)? {
                writeln!(out, "{domain}")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod two_factor_tests {
    use super::*;

    #[test]
    fn two_factor_commands() {
        let td = tempfile::tempdir().unwrap();
        let db = td.path().join("accounts.sqlite");
        rmail_common::db::init_db(&db).unwrap();
        let run = |action| {
            let mut out = Vec::new();
            run_two_factor(action, &db, &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert!(
            run(TwoFactorAction::Require {
                domain: "Example.test".into()
            })
            .contains("now requires")
        );
        assert_eq!(run(TwoFactorAction::Domains), "example.test\n");
        assert!(
            run(TwoFactorAction::Status {
                address: "ann@example.test".into()
            })
            .contains("required by its domain")
        );
        let secret = rmail_common::two_factor::begin(&db, "ann@example.test").unwrap();
        let key = rmail_common::two_factor::base32_decode(&secret).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let code = format!("{:06}", rmail_common::two_factor::code_at(&key, now / 30));
        rmail_common::two_factor::confirm(&db, "ann@example.test", &code)
            .unwrap()
            .unwrap();
        assert!(
            run(TwoFactorAction::Status {
                address: "ann@example.test".into()
            })
            .contains("on, 10 recovery codes left")
        );
        assert!(
            run(TwoFactorAction::Reset {
                address: "ann@example.test".into()
            })
            .contains("turned off")
        );
        assert!(
            run(TwoFactorAction::Reset {
                address: "ann@example.test".into()
            })
            .contains("did not have")
        );
        run(TwoFactorAction::Allow {
            domain: "example.test".into(),
        });
        assert_eq!(run(TwoFactorAction::Domains), "");
    }
}
