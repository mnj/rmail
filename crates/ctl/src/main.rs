use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rmail_common::{config::Config, maildir};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RMAIL_SYSTEMD_UNITS: &[&str] = &[
    "rmail_smtpd.service",
    "rmail_imapd.service",
    "rmail_web.service",
    "rmail_webmail.service",
    "rmail_outbound.service",
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
    /// Obtain TLS certificates via ACME (Let's Encrypt certbot) using webroot challenge
    ObtainCert {
        /// Domains, comma-separated (e.g. example.com,www.example.com)
        domains: String,
        /// Email address for registration with ACME server
        #[arg(long)]
        email: Option<String>,
        /// Use LetsEncrypt staging endpoint for testing
        #[arg(long)]
        staging: bool,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// Renew certificates via certbot and reload services
    Renew {
        /// Use LetsEncrypt staging endpoint for testing
        #[arg(long)]
        staging: bool,
        /// optional config path (defaults to RMAIL_CONFIG or config/example.toml)
        #[arg(long)]
        config: Option<String>,
    },
    /// Aggregate and enqueue DMARC RUA reports for unreported events in the DB
    SendDmarcReports {
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
        Commands::InitDb { db_path, config } => {
            let dbp = if let Some(p) = db_path {
                p
            } else {
                let cfg_path = config.unwrap_or_else(|| {
                    std::env::var("RMAIL_CONFIG")
                        .unwrap_or_else(|_| "config/example.toml".to_string())
                });
                let cfg = Config::from_file(&cfg_path)?;
                cfg.global
                    .db_path
                    .ok_or_else(|| anyhow::anyhow!("No db_path configured"))?
            };
            rmail_common::db::init_db(&dbp)?;
            println!("Initialized DB at {}", dbp);
        }
        Commands::AddMailbox {
            address,
            password,
            password_hash,
            maildir: maildir_opt,
            config,
        } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::from_file(&cfg_path)?;
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
                let scram = rmail_common::auth::create_scram_verifier(&p, 4096)?;
                (phs, Some(scram))
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

                // If db_path configured, insert into SQLite, otherwise fallback to TOML append
                if let Some(dbp) = cfg.global.db_path.as_ref() {
                    // ensure DB initialized
                    rmail_common::db::init_db(dbp)?;
                    rmail_common::db::add_mailbox(
                        dbp,
                        &address.to_ascii_lowercase(),
                        if ph.is_empty() { None } else { Some(&ph) },
                        Some(&maildir_path),
                        scram_json.as_deref(),
                    )?;
                    println!("Added mailbox {} into DB at {}", address, dbp);
                } else {
                    eprintln!("No db_path configured; SQLite DB is required");
                    std::process::exit(1);
                }
            } else {
                eprintln!("Invalid address '{}'", address);
            }
        }
        Commands::List { config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::from_file(&cfg_path)?;
            if let Some(dbp) = cfg.global.db_path.as_ref() {
                // list from DB
                for m in rmail_common::db::list_mailboxes(dbp)? {
                    println!("{}", m.address);
                }
            } else {
                eprintln!("No db_path configured; SQLite DB is required");
                std::process::exit(1);
            }
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
            let cfg = Config::from_file(&cfg_path)?;
            let dbp = cfg
                .global
                .db_path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("No db_path configured"))?
                .to_string();
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
        },
        Commands::ObtainCert {
            domains,
            email,
            staging,
            config,
        } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::from_file(&cfg_path)?;
            let acme_dir = cfg.global.acme_challenge_dir.clone().ok_or_else(|| {
                anyhow::anyhow!("No acme_challenge_dir configured in global config")
            })?;
            // ensure webroot exists
            if !Path::new(&acme_dir).exists() {
                fs::create_dir_all(&acme_dir)?;
            }
            // Build certbot command
            let mut cmd = Command::new("certbot");
            cmd.arg("certonly")
                .arg("--non-interactive")
                .arg("--agree-tos")
                .arg("--webroot")
                .arg("-w")
                .arg(&acme_dir)
                .arg("--rsa-key-size")
                .arg("2048");
            if staging {
                cmd.arg("--staging");
            }
            if let Some(e) = email.as_ref() {
                cmd.arg("--email").arg(e);
            } else {
                cmd.arg("--register-unsafely-without-email");
            }
            for d in domains
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                cmd.arg("-d").arg(d);
            }
            println!("Running certbot to obtain certificate for {}", domains);
            let status = cmd
                .status()
                .map_err(|e| anyhow::anyhow!(format!("failed to run certbot: {}", e)))?;
            if !status.success() {
                return Err(anyhow::anyhow!(format!(
                    "certbot exited with status {}",
                    status
                )));
            }
            // Copy certs for primary domain
            let primary_domain = domains.split(',').next().unwrap().trim();
            let live_dir = Path::new("/etc/letsencrypt/live").join(primary_domain);
            let fullchain = live_dir.join("fullchain.pem");
            let privkey = live_dir.join("privkey.pem");
            if !fullchain.exists() || !privkey.exists() {
                return Err(anyhow::anyhow!(format!(
                    "expected cert files not found in {}",
                    live_dir.display()
                )));
            }
            let out_cert = cfg
                .global
                .tls_cert
                .clone()
                .unwrap_or(format!("config/certs/{}.crt", primary_domain));
            let out_key = cfg
                .global
                .tls_key
                .clone()
                .unwrap_or(format!("config/certs/{}.key", primary_domain));
            if let Some(parent) = Path::new(&out_cert).parent() {
                fs::create_dir_all(parent)?;
            }
            if let Some(parent) = Path::new(&out_key).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&fullchain, &out_cert)?;
            fs::copy(&privkey, &out_key)?;
            println!(
                "Obtained cert for {} -> {} / {}",
                primary_domain, out_cert, out_key
            );
        }
        Commands::Renew { staging, config } => {
            let cfg_path = config.unwrap_or_else(|| {
                std::env::var("RMAIL_CONFIG").unwrap_or_else(|_| "config/example.toml".to_string())
            });
            let cfg = Config::from_file(&cfg_path)?;
            println!("Running certbot renew...");
            let mut cmd = Command::new("certbot");
            cmd.arg("renew").arg("--non-interactive");
            if staging {
                cmd.arg("--staging");
            }
            let status = cmd
                .status()
                .map_err(|e| anyhow::anyhow!(format!("failed to run certbot renew: {}", e)))?;
            if !status.success() {
                return Err(anyhow::anyhow!(format!(
                    "certbot renew exited with status {}",
                    status
                )));
            }
            // Determine primary domain to copy (prefer tls_cert filename stem)
            let primary_domain_opt = cfg.global.tls_cert.as_ref().and_then(|p| {
                std::path::Path::new(p)
                    .file_stem()
                    .and_then(|os| os.to_str())
                    .map(|s| s.to_string())
            });
            let primary_domain = if let Some(d) = primary_domain_opt {
                d
            } else {
                // fallback: pick first dir under /etc/letsencrypt/live
                let live_root = Path::new("/etc/letsencrypt/live");

                std::fs::read_dir(live_root)?
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no live certs found to copy"))?
            };
            let live_dir = Path::new("/etc/letsencrypt/live").join(&primary_domain);
            let fullchain = live_dir.join("fullchain.pem");
            let privkey = live_dir.join("privkey.pem");
            if !fullchain.exists() || !privkey.exists() {
                return Err(anyhow::anyhow!(format!(
                    "expected cert files not found in {}",
                    live_dir.display()
                )));
            }
            let out_cert = cfg
                .global
                .tls_cert
                .clone()
                .unwrap_or(format!("config/certs/{}.crt", primary_domain));
            let out_key = cfg
                .global
                .tls_key
                .clone()
                .unwrap_or(format!("config/certs/{}.key", primary_domain));
            if let Some(parent) = Path::new(&out_cert).parent() {
                fs::create_dir_all(parent)?;
            }
            if let Some(parent) = Path::new(&out_key).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&fullchain, &out_cert)?;
            fs::copy(&privkey, &out_key)?;
            println!(
                "Renewed cert for {} -> {} / {}",
                primary_domain, out_cert, out_key
            );
            reload_services(ServiceCommandOptions {
                units: vec![
                    "smtpd".to_string(),
                    "imapd".to_string(),
                    "web".to_string(),
                    "webmail".to_string(),
                ],
                dry_run: false,
            })?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{ServiceCommandOptions, normalize_unit_name, selected_units};

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
    fn stop_order_is_reversed() {
        let opts = ServiceCommandOptions {
            units: Vec::new(),
            dry_run: false,
        };
        let units = selected_units(&opts, true).unwrap();
        assert_eq!(units.first().copied(), Some("rmail_outbound.service"));
        assert_eq!(units.last().copied(), Some("rmail_smtpd.service"));
    }
}
