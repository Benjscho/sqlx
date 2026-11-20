use sqlx::pool::{PoolConnectMetadata, PoolConnector};
use sqlx::sqlite::{Sqlite, SqliteConnectOptions, SqliteConnection, SqlitePoolOptions};
use sqlx::{ConnectOptions, Error};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

struct BorrowingConnector(Arc<AtomicUsize>);

impl PoolConnector<Sqlite> for BorrowingConnector {
    async fn connect(&self, meta: PoolConnectMetadata<Sqlite>) -> sqlx::Result<SqliteConnection> {
        let connection = meta.connect_options.connect().await?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(connection)
    }
}

#[sqlx_macros::test]
async fn borrowing_connector_observes_updated_options() -> anyhow::Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let options = SqliteConnectOptions::new().pragma("user_version", "1");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connector(BorrowingConnector(calls.clone()))
        .connect_with(options.clone())
        .await?;
    let version: i64 = sqlx::query_scalar("SELECT user_version FROM pragma_user_version")
        .fetch_one(&pool)
        .await?;
    assert_eq!(version, 1);
    pool.set_connect_options(options.pragma("user_version", "2"));
    pool.acquire().await?.close().await?;
    let version: i64 = sqlx::query_scalar("SELECT user_version FROM pragma_user_version")
        .fetch_one(&pool)
        .await?;
    assert_eq!(version, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    pool.close().await;
    Ok(())
}

#[sqlx_macros::test]
async fn closure_connector_preserves_retries_and_after_connect() -> anyhow::Result<()> {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let captured = attempts.clone();
    let initialized = Arc::new(AtomicUsize::new(0));
    let after_connect = initialized.clone();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connector(move |meta: PoolConnectMetadata<Sqlite>| {
            captured.lock().unwrap().push((
                meta.num_attempts,
                meta.start,
                meta.deadline,
                meta.pool_size,
            ));
            async move {
                if meta.num_attempts == 0 {
                    return Err(Error::Io(std::io::ErrorKind::ConnectionRefused.into()));
                }
                meta.connect_options.connect().await
            }
        })
        .after_connect(move |_, _| {
            after_connect.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .connect_with(SqliteConnectOptions::new())
        .await?;
    {
        let attempts = attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].0, 0);
        assert_eq!(attempts[1].0, 1);
        assert_eq!(attempts[0].1, attempts[1].1);
        assert_eq!(attempts[0].2, attempts[1].2);
        assert!(attempts[0].1 < attempts[0].2);
        assert_eq!(attempts[0].3, 1);
    }
    assert_eq!(initialized.load(Ordering::SeqCst), 1);
    pool.close().await;
    Ok(())
}

#[sqlx_macros::test]
async fn connector_is_subject_to_acquire_timeout() {
    let pool = SqlitePoolOptions::new()
        .acquire_timeout(Duration::from_millis(20))
        .connector(|_: PoolConnectMetadata<Sqlite>| std::future::pending())
        .connect_lazy_with(SqliteConnectOptions::new());
    assert!(matches!(pool.acquire().await, Err(Error::PoolTimedOut)));
    assert_eq!(pool.size(), 0);
    pool.close().await;
}
