use crate::connection::Connection;
use crate::database::Database;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

/// Creates connections for a pool, including connections over custom transports.
///
/// Implemented for closures taking [`PoolConnectMetadata`] and returning a
/// `Send` future. Custom implementations may return futures borrowing `self`.
/// The pool applies its usual connection timeout and retry policy, then calls
/// [`PoolOptions::after_connect`][super::PoolOptions::after_connect].
pub trait PoolConnector<DB: Database>: Send + Sync + 'static {
    /// Establish a connection using the options and metadata for this attempt.
    ///
    /// Use `meta.connect_options` for configuration that should follow
    /// [`Pool::set_connect_options`][super::Pool::set_connect_options].
    fn connect(
        &self,
        meta: PoolConnectMetadata<DB>,
    ) -> impl Future<Output = crate::Result<DB::Connection>> + Send + '_;
}

impl<DB, F, Fut> PoolConnector<DB> for F
where
    DB: Database,
    F: Fn(PoolConnectMetadata<DB>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = crate::Result<DB::Connection>> + Send + 'static,
{
    fn connect(
        &self,
        meta: PoolConnectMetadata<DB>,
    ) -> impl Future<Output = crate::Result<DB::Connection>> + Send + '_ {
        self(meta)
    }
}

/// Configuration and timing information for a pool connection attempt.
#[derive(Debug)]
#[non_exhaustive]
pub struct PoolConnectMetadata<DB: Database> {
    /// A snapshot of the pool's current options, refreshed on every attempt.
    pub connect_options: Arc<<DB::Connection as Connection>::Options>,
    /// When this sequence of connection attempts began.
    pub start: Instant,
    /// The deadline shared by all attempts in this sequence.
    pub deadline: Instant,
    /// The number of previous attempts in this sequence (zero on the first).
    pub num_attempts: u32,
    /// Total connections owned by the pool, including those being opened.
    pub pool_size: u32,
}
