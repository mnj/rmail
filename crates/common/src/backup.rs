//! Backup and restore: the whole server's data, or one account, as a
//! zstd-compressed tar archive (`.tar.zst`).
//!
//! - A full backup holds the configuration file, the main database
//!   (mailboxes, settings, DKIM keys, ACME state), the TLS certificate and
//!   key files when they are configured, and the mail root: every
//!   account's mail and its own databases, and the outbound queue.
//! - SQLite databases are copied with `VACUUM INTO`, a consistent snapshot
//!   taken while the services keep running; their `-wal`/`-shm`/`-journal`
//!   side files are not needed and left out, as are maildir `tmp/`
//!   directories (messages still being written).
//! - A restore refuses to write over existing data unless forced, and then
//!   moves what is there aside (`<path>.before-restore-<time>`) instead of
//!   deleting it. Archive paths are checked, so an archive cannot write
//!   outside its targets.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MANIFEST: &str = "rmail-backup.json";
const FORMAT: u32 = 1;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// What a backup was made from, and what a restore writes to.
#[derive(Debug, Clone)]
pub struct Sources {
    /// The configuration file, when there is one.
    pub config: Option<PathBuf>,
    pub db: PathBuf,
    pub mail_root: PathBuf,
    /// TLS certificate and key files, by position (an empty path is a
    /// file not configured).
    pub tls: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format: u32,
    /// `full` or `account`.
    pub kind: String,
    /// Unix seconds.
    pub created: i64,
    /// The rMail version that made it.
    pub version: String,
    #[serde(default)]
    pub account: Option<String>,
    /// The configuration file's name, for a full backup that has one.
    #[serde(default)]
    pub config_name: Option<String>,
    /// Where the TLS files were, in the order stored (`tls/0`, `tls/1`...).
    #[serde(default)]
    pub tls: Vec<String>,
}

/// How much a backup or restore wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub files: usize,
    pub bytes: u64,
}

type Archive = tar::Builder<zstd::stream::write::Encoder<'static, File>>;
type Reader = Box<dyn Read>;

/// zstd level 3: about gzip's ratio or better, several times faster.
const ZSTD_LEVEL: i32 = 3;

/// Whether `path` is a SQLite database (by its header).
fn is_sqlite(path: &Path) -> bool {
    let mut magic = [0u8; 16];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && &magic == SQLITE_MAGIC
}

fn skipped_name(name: &str) -> bool {
    name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
}

/// A consistent copy of a SQLite database, in `scratch`.
fn snapshot(path: &Path, scratch: &Path) -> Result<PathBuf> {
    let copy = scratch.join(format!("{:016x}.sqlite", rand::random::<u64>()));
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    conn.execute(
        "VACUUM INTO ?1",
        [copy.to_str().context("scratch path is not UTF-8")?],
    )
    .with_context(|| format!("copying {}", path.display()))?;
    Ok(copy)
}

/// Add `path` (a file) under `name`, snapshotting databases.
fn add_file(
    archive: &mut Archive,
    path: &Path,
    name: &Path,
    scratch: &Path,
    summary: &mut Summary,
) -> Result<()> {
    let source = if is_sqlite(path) {
        snapshot(path, scratch)?
    } else {
        path.to_path_buf()
    };
    let mut file = File::open(&source).with_context(|| format!("reading {}", path.display()))?;
    let metadata = file.metadata()?;
    let mut header = tar::Header::new_gnu();
    header.set_metadata(&fs::metadata(path).unwrap_or(metadata.clone()));
    header.set_size(metadata.len());
    archive
        .append_data(&mut header, name, &mut file)
        .with_context(|| format!("archiving {}", path.display()))?;
    if source != path {
        let _ = fs::remove_file(&source);
    }
    summary.files += 1;
    summary.bytes += metadata.len();
    Ok(())
}

/// Add the tree under `dir` as `prefix/...`.
fn add_tree(
    archive: &mut Archive,
    dir: &Path,
    prefix: &Path,
    scratch: &Path,
    summary: &mut Summary,
) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        let kind = entry.file_type()?;
        // Messages still being written, and links (never followed).
        if kind.is_symlink() || (kind.is_dir() && text == "tmp") || skipped_name(text) {
            continue;
        }
        let path = entry.path();
        let target = prefix.join(text);
        if path == scratch {
            continue;
        }
        if kind.is_dir() {
            add_tree(archive, &path, &target, scratch, summary)?;
        } else if kind.is_file() {
            // A message moved or expunged while the backup ran is skipped.
            match add_file(archive, &path, &target, scratch, summary) {
                Ok(()) => {}
                Err(_) if !path.exists() => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn add_manifest(archive: &mut Archive, manifest: &Manifest) -> Result<()> {
    let data = serde_json::to_vec_pretty(manifest)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(manifest.created.max(0) as u64);
    archive.append_data(&mut header, MANIFEST, data.as_slice())?;
    Ok(())
}

/// Write an archive to `out` through a `.partial` file and a scratch
/// directory beside it, which are removed whatever happens.
fn write_archive(
    out: &Path,
    fill: impl FnOnce(&mut Archive, &Path) -> Result<Summary>,
) -> Result<Summary> {
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let partial = out.with_extension("partial");
    let scratch = parent.join(format!(".rmail-backup-{:016x}", rand::random::<u64>()));
    // Snapshots hold password hashes and keys: owner only, whatever the umask.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&scratch)?;
    let result = (|| {
        let file =
            File::create(&partial).with_context(|| format!("creating {}", partial.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&partial, fs::Permissions::from_mode(0o600))?;
        }
        let mut encoder = zstd::stream::write::Encoder::new(file, ZSTD_LEVEL)?;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
        encoder.multithread(threads as u32)?;
        let mut archive = tar::Builder::new(encoder);
        archive.follow_symlinks(false);
        let summary = fill(&mut archive, &scratch)?;
        archive.into_inner()?.finish()?.sync_all()?;
        fs::rename(&partial, out)?;
        Ok(summary)
    })();
    let _ = fs::remove_dir_all(&scratch);
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Back up the whole server to `out`.
pub fn create_full(sources: &Sources, out: &Path) -> Result<Summary> {
    let manifest = Manifest {
        format: FORMAT,
        kind: "full".into(),
        created: now(),
        version: env!("CARGO_PKG_VERSION").into(),
        account: None,
        config_name: sources
            .config
            .as_ref()
            .and_then(|c| c.file_name())
            .and_then(|n| n.to_str())
            .map(str::to_string),
        tls: sources
            .tls
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
    };
    write_archive(out, |archive, scratch| {
        let mut summary = Summary::default();
        add_manifest(archive, &manifest)?;
        if let (Some(config), Some(name)) = (&sources.config, &manifest.config_name) {
            add_file(
                archive,
                config,
                &Path::new("config").join(name),
                scratch,
                &mut summary,
            )?;
        }
        add_file(
            archive,
            &sources.db,
            Path::new("db/accounts.sqlite"),
            scratch,
            &mut summary,
        )?;
        // The index is the file's position in the configuration, so a
        // missing or unreadable file leaves a gap rather than shifting others.
        for (index, path) in sources.tls.iter().enumerate() {
            if path.is_file() && File::open(path).is_ok() {
                add_file(
                    archive,
                    path,
                    &Path::new("tls").join(index.to_string()),
                    scratch,
                    &mut summary,
                )?;
            }
        }
        add_tree(
            archive,
            &sources.mail_root,
            Path::new("mail"),
            scratch,
            &mut summary,
        )?;
        Ok(summary)
    })
}

fn account_dir(mail_root: &Path, address: &str) -> Result<PathBuf> {
    let address = crate::domain::canonicalize_mailbox_address(address)?.to_ascii_lowercase();
    let (local, domain) = address.split_once('@').context("invalid address")?;
    Ok(crate::maildir::account_maildir(mail_root, domain, local))
}

/// Back up one account's mail and data (its folders, calendars, contacts,
/// notes, settings) to `out`.
pub fn create_account(mail_root: &Path, address: &str, out: &Path) -> Result<Summary> {
    let dir = account_dir(mail_root, address)?;
    if !dir.is_dir() {
        bail!("{address} has no mail here");
    }
    let manifest = Manifest {
        format: FORMAT,
        kind: "account".into(),
        created: now(),
        version: env!("CARGO_PKG_VERSION").into(),
        account: Some(address.to_ascii_lowercase()),
        config_name: None,
        tls: Vec::new(),
    };
    write_archive(out, |archive, scratch| {
        let mut summary = Summary::default();
        add_manifest(archive, &manifest)?;
        add_tree(archive, &dir, Path::new("account"), scratch, &mut summary)?;
        Ok(summary)
    })
}

/// A backup for reading.
fn open_archive(path: &Path) -> Result<tar::Archive<Reader>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file).context("not an rMail backup")?;
    Ok(tar::Archive::new(Box::new(decoder) as Reader))
}

/// The manifest of a backup.
pub fn read_manifest(path: &Path) -> Result<Manifest> {
    let mut archive = open_archive(path)?;
    let mut entries = archive.entries()?;
    let mut first = entries.next().context("the archive is empty")??;
    if first.path()?.as_ref() != Path::new(MANIFEST) {
        bail!("not an rMail backup");
    }
    let mut data = Vec::new();
    first.read_to_end(&mut data)?;
    let manifest: Manifest = serde_json::from_slice(&data).context("unreadable manifest")?;
    if manifest.format > FORMAT {
        bail!(
            "this backup is from a newer rMail ({}); upgrade first",
            manifest.version
        );
    }
    Ok(manifest)
}

/// A relative archive path made only of normal components.
fn safe(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => bail!("unsafe path in the archive: {}", path.display()),
        }
    }
    if out.as_os_str().is_empty() {
        bail!("empty path in the archive");
    }
    Ok(out)
}

/// Move `path` aside when it exists and is not empty (or refuse without
/// `force`).
fn clear(path: &Path, force: bool, stamp: i64) -> Result<()> {
    let present = if path.is_dir() {
        fs::read_dir(path)?.next().is_some()
    } else {
        path.exists()
    };
    if !present {
        return Ok(());
    }
    if !force {
        bail!(
            "{} already has data; restore with --force to move it aside first",
            path.display()
        );
    }
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".before-restore-{stamp}"));
    fs::rename(path, &aside).with_context(|| format!("moving {} aside", path.display()))?;
    Ok(())
}

fn unpack(entry: &mut tar::Entry<'_, Reader>, target: &Path, summary: &mut Summary) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let kind = entry.header().entry_type();
    if kind.is_dir() {
        fs::create_dir_all(target)?;
        return Ok(());
    }
    if !kind.is_file() {
        // Links and devices are never restored.
        return Ok(());
    }
    let mut file = File::create(target).with_context(|| format!("writing {}", target.display()))?;
    let bytes = std::io::copy(entry, &mut file)?;
    file.flush()?;
    #[cfg(unix)]
    if let Ok(mode) = entry.header().mode() {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(mode & 0o700))?;
    }
    summary.files += 1;
    summary.bytes += bytes;
    Ok(())
}

/// Restore a full backup into `targets` (the services should be stopped).
/// Existing data is moved aside with `force`; without it, the restore
/// refuses to start. The configuration and TLS files are restored only
/// where none exist yet; an existing configuration gets the backup's
/// beside it as `<config>.from-backup`.
pub fn restore_full(archive_path: &Path, targets: &Sources, force: bool) -> Result<Summary> {
    let manifest = read_manifest(archive_path)?;
    if manifest.kind != "full" {
        bail!(
            "this is a backup of {}; restore it as an account",
            manifest.account.unwrap_or_default()
        );
    }
    let stamp = now();
    clear(&targets.db, force, stamp)?;
    // SQLite side files left by a crash would be replayed into the restored
    // database: they go aside too, with or without one.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut side = targets.db.as_os_str().to_owned();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.exists() {
            let mut aside = side.as_os_str().to_owned();
            aside.push(format!(".before-restore-{stamp}"));
            fs::rename(&side, &aside)
                .with_context(|| format!("moving {} aside", side.display()))?;
        }
    }
    clear(&targets.mail_root, force, stamp)?;
    fs::create_dir_all(&targets.mail_root)?;
    let mut summary = Summary::default();
    let mut archive = open_archive(archive_path)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = safe(&entry.path()?)?;
        let mut parts = path.components();
        let top = parts
            .next()
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or_default()
            .to_string();
        let rest = parts.as_path().to_path_buf();
        let target = match top.as_str() {
            MANIFEST => continue,
            "db" if rest == Path::new("accounts.sqlite") => targets.db.clone(),
            "mail" if !rest.as_os_str().is_empty() => targets.mail_root.join(&rest),
            // A configuration in place is never replaced: it names the
            // paths being restored to. The backup's goes beside it.
            "config" => match &targets.config {
                Some(config) if !config.exists() => config.clone(),
                Some(config) => {
                    let mut beside = config.as_os_str().to_owned();
                    beside.push(".from-backup");
                    PathBuf::from(beside)
                }
                None => continue,
            },
            "tls" => {
                let index: usize = rest
                    .to_str()
                    .and_then(|r| r.parse().ok())
                    .unwrap_or(usize::MAX);
                let Some(original) = targets
                    .tls
                    .get(index)
                    .filter(|p| !p.as_os_str().is_empty())
                    .cloned()
                    .or_else(|| {
                        manifest
                            .tls
                            .get(index)
                            .filter(|p| !p.is_empty())
                            .map(PathBuf::from)
                    })
                else {
                    continue;
                };
                // Certificates in place are kept.
                if original.exists() {
                    continue;
                }
                original
            }
            _ => continue,
        };
        unpack(&mut entry, &target, &mut summary)?;
    }
    Ok(summary)
}

/// Restore an account backup, as its own account or as `address`. The
/// account's current data is moved aside with `force`.
pub fn restore_account(
    archive_path: &Path,
    mail_root: &Path,
    address: Option<&str>,
    force: bool,
) -> Result<Summary> {
    let manifest = read_manifest(archive_path)?;
    if manifest.kind != "account" {
        bail!("this is a full backup; restore it with restore_full");
    }
    let address = address
        .map(str::to_string)
        .or(manifest.account.clone())
        .context("the backup names no account")?;
    let dir = account_dir(mail_root, &address)?;
    clear(&dir, force, now())?;
    fs::create_dir_all(&dir)?;
    let mut summary = Summary::default();
    let mut archive = open_archive(archive_path)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = safe(&entry.path()?)?;
        let Ok(rest) = path.strip_prefix("account") else {
            continue;
        };
        if rest.as_os_str().is_empty() {
            continue;
        }
        unpack(&mut entry, &dir.join(rest), &mut summary)?;
    }
    Ok(summary)
}

/// A dated full backup in `dir` (`rmail-YYYYMMDD-HHMMSS.tar.zst`), keeping
/// the newest `keep` of them.
pub fn create_in_dir(sources: &Sources, dir: &Path, keep: usize) -> Result<(PathBuf, Summary)> {
    fs::create_dir_all(dir)?;
    let name = format!(
        "rmail-{}.tar.zst",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    let out = dir.join(name);
    let summary = create_full(sources, &out)?;
    let mut existing: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("rmail-") && n.ends_with(".tar.zst"))
        })
        .collect();
    existing.sort();
    if keep > 0 && existing.len() > keep {
        for old in &existing[..existing.len() - keep] {
            let _ = fs::remove_file(old);
        }
    }
    Ok((out, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap_state;

    fn server(root: &Path) -> Sources {
        fs::create_dir_all(root).unwrap();
        let db = root.join("accounts.sqlite");
        crate::db::init_db(&db).unwrap();
        crate::db::add_mailbox(&db, "user@example.test", Some("plain:pw"), None, None).unwrap();
        let mail_root = root.join("mail");
        imap_state::init_account(&mail_root, "example.test", "user").unwrap();
        imap_state::deliver_message(
            &mail_root,
            "example.test",
            "user",
            b"Subject: kept\r\n\r\nbody",
        )
        .unwrap();
        // A message being written, which a backup leaves out.
        let tmp = crate::maildir::account_maildir(&mail_root, "example.test", "user").join("tmp");
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("partial"), b"half").unwrap();
        let config = root.join("rmail.toml");
        fs::write(&config, "[global]\n").unwrap();
        Sources {
            config: Some(config),
            db,
            mail_root,
            tls: Vec::new(),
        }
    }

    #[test]
    fn a_full_backup_restores_into_an_empty_server() {
        let td = tempfile::tempdir().unwrap();
        let sources = server(&td.path().join("live"));
        let out = td.path().join("backups/full.tar.zst");
        let summary = create_full(&sources, &out).unwrap();
        assert!(summary.files >= 3, "{summary:?}");
        assert_eq!(read_manifest(&out).unwrap().kind, "full");

        let target_root = td.path().join("new");
        let targets = Sources {
            config: Some(target_root.join("rmail.toml")),
            db: target_root.join("accounts.sqlite"),
            mail_root: target_root.join("mail"),
            tls: Vec::new(),
        };
        restore_full(&out, &targets, false).unwrap();
        assert!(crate::db::mailbox_exists(&targets.db, "user@example.test").unwrap());
        let (_, messages) =
            imap_state::load_folder(&targets.mail_root, "example.test", "user", "INBOX").unwrap();
        assert_eq!(messages.len(), 1);
        assert!(
            fs::read_to_string(targets.config.as_ref().unwrap())
                .unwrap()
                .contains("[global]")
        );
        fs::write(targets.config.as_ref().unwrap(), "# this server's own\n").unwrap();
        let account = crate::maildir::account_maildir(&targets.mail_root, "example.test", "user");
        assert!(
            !account.join("tmp/partial").exists(),
            "unfinished writes are left out"
        );

        // A crash's leftover WAL would be replayed into the restored database.
        let mut wal = targets.db.as_os_str().to_owned();
        wal.push("-wal");
        fs::write(&wal, b"stale").unwrap();
        // Over existing data: refused, unless forced, which moves it aside.
        assert!(restore_full(&out, &targets, false).is_err());
        restore_full(&out, &targets, true).unwrap();
        let aside = fs::read_dir(&target_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".before-restore-"))
            .count();
        assert_eq!(
            aside, 3,
            "the database, its stale WAL and the mail root, moved aside"
        );
        assert!(!PathBuf::from(&wal).exists());
        assert_eq!(
            fs::read_to_string(targets.config.as_ref().unwrap()).unwrap(),
            "# this server's own\n",
            "the configuration in place is kept"
        );
        assert!(target_root.join("rmail.toml.from-backup").exists());
    }

    #[test]
    fn an_account_backup_restores_one_mailbox_even_under_another_name() {
        let td = tempfile::tempdir().unwrap();
        let sources = server(&td.path().join("live"));
        let out = td.path().join("user.tar.zst");
        create_account(&sources.mail_root, "user@example.test", &out).unwrap();
        assert!(
            restore_full(&out, &sources, true).is_err(),
            "not a full backup"
        );
        restore_account(&out, &sources.mail_root, Some("copy@example.test"), false).unwrap();
        let (_, messages) =
            imap_state::load_folder(&sources.mail_root, "example.test", "copy", "INBOX").unwrap();
        assert_eq!(messages.len(), 1);
        assert!(
            restore_account(&out, &sources.mail_root, None, false).is_err(),
            "the original has data"
        );
    }

    #[test]
    fn archives_cannot_write_outside_their_targets() {
        assert!(safe(Path::new("mail/../../etc/passwd")).is_err());
        assert!(safe(Path::new("/etc/passwd")).is_err());
        assert_eq!(
            safe(Path::new("./mail/a")).unwrap(),
            PathBuf::from("mail/a")
        );
    }

    #[test]
    fn dated_backups_keep_the_newest() {
        let td = tempfile::tempdir().unwrap();
        let sources = server(&td.path().join("live"));
        let dir = td.path().join("nightly");
        fs::create_dir_all(&dir).unwrap();
        for name in [
            "rmail-20200101-000000.tar.zst",
            "rmail-20200102-000000.tar.zst",
            "notes.txt",
        ] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        let (made, _) = create_in_dir(&sources, &dir, 2).unwrap();
        assert!(made.exists());
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left.len(), 3, "{left:?}");
        assert!(
            left.contains(&"notes.txt".to_string())
                && left.contains(&"rmail-20200102-000000.tar.zst".to_string())
        );
    }
}
