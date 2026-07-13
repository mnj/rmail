use anyhow::{Context, Result};
use moka::sync::Cache;
use once_cell::sync::Lazy;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_DATABASE_POOLS: u64 = 1_024;
const MAX_CONNECTIONS_PER_DATABASE: u32 = 8;

type SqlitePool = Pool<SqliteConnectionManager>;
pub type SqliteConnection = PooledConnection<SqliteConnectionManager>;

static POOLS: Lazy<Cache<PathBuf, SqlitePool>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(MAX_DATABASE_POOLS)
        .time_to_idle(Duration::from_secs(15 * 60))
        .build()
});

/// Borrow a SQLite connection from the bounded pool associated with `path`.
///
/// Pools are evicted after inactivity and every connection gets consistent
/// contention, integrity, and durability settings when it is created.
pub fn connection(path: &Path) -> Result<SqliteConnection> {
    let started = Instant::now();
    let result = connection_inner(path);
    crate::metrics::observe_database_wait_duration(started.elapsed());
    result
}

fn connection_inner(path: &Path) -> Result<SqliteConnection> {
    let path = absolute_path(path)?;
    let pool = POOLS
        .try_get_with(path.clone(), || build_pool(&path))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    pool.get().context("waiting for a SQLite connection")
}

fn build_pool(path: &Path) -> Result<SqlitePool> {
    let manager = SqliteConnectionManager::file(path).with_init(|connection| {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(())
    });
    Pool::builder()
        .max_size(MAX_CONNECTIONS_PER_DATABASE)
        .min_idle(Some(0))
        .connection_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(5 * 60)))
        .max_lifetime(Some(Duration::from_secs(30 * 60)))
        .build(manager)
        .context("creating SQLite connection pool")
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolving current directory for SQLite path")?
        .join(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_a_pool_and_initializes_every_connection() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.sqlite");
        let first = connection(&path).unwrap();
        let foreign_keys: bool = first
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert!(foreign_keys);
        drop(first);

        let second = connection(&path).unwrap();
        second
            .execute_batch("CREATE TABLE reused(value INTEGER);")
            .unwrap();
        assert_eq!(POOLS.get(&path).unwrap().state().connections, 1);
    }

    #[test]
    fn rolled_back_transactions_do_not_leak_across_borrows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("transactions.sqlite");
        {
            let mut connection = connection(&path).unwrap();
            connection
                .execute_batch("CREATE TABLE values_(value INTEGER);")
                .unwrap();
            let transaction = connection.transaction().unwrap();
            transaction
                .execute("INSERT INTO values_ VALUES (1)", [])
                .unwrap();
        }
        let connection = connection(&path).unwrap();
        let count: u64 = connection
            .query_row("SELECT COUNT(*) FROM values_", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn concurrent_borrows_never_exceed_the_per_database_bound() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bounded.sqlite");
        let workers = (0..32)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let connection = connection(&path).unwrap();
                    std::thread::sleep(Duration::from_millis(10));
                    drop(connection);
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(POOLS.get(&path).unwrap().state().connections <= MAX_CONNECTIONS_PER_DATABASE);
    }
}
