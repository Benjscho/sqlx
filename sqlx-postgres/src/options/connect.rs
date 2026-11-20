use crate::connection::ConnectOptions;
use crate::error::Error;
use crate::{PgConnectOptions, PgConnection};
use log::LevelFilter;
use sqlx_core::Url;
use std::future::Future;
use std::time::Duration;

impl ConnectOptions for PgConnectOptions {
    type Connection = PgConnection;

    fn from_url(url: &Url) -> Result<Self, Error> {
        Self::parse_from_url(url)
    }

    fn to_url_lossy(&self) -> Url {
        self.build_url()
    }

    fn connect(&self) -> impl Future<Output = Result<Self::Connection, Error>> + Send + '_
    where
        Self::Connection: Sized,
    {
        PgConnection::establish(self)
    }

    fn log_statements(mut self, level: LevelFilter) -> Self {
        self.log_settings.log_statements(level);
        self
    }

    fn log_slow_statements(mut self, level: LevelFilter, duration: Duration) -> Self {
        self.log_settings.log_slow_statements(level, duration);
        self
    }
}

#[cfg(feature = "_rt-tokio")]
impl PgConnectOptions {
    /// Connect over a pre-connected tokio stream.
    ///
    /// Performs the database handshake and negotiates TLS using these options.
    /// The configured hostname is still used for TLS certificate verification.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sqlx::postgres::PgConnectOptions;
    ///
    /// # async fn example() -> Result<(), sqlx::Error> {
    /// let stream = tokio::net::TcpStream::connect("127.0.0.1:5432").await?;
    /// let conn = PgConnectOptions::new()
    ///     .connect_with_stream_tokio(stream)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_with_stream_tokio<S>(&self, stream: S) -> Result<PgConnection, Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        PgConnection::establish_with_socket(crate::net::TokioStream::new(stream), self).await
    }
}

#[cfg(feature = "_rt-async-io")]
impl PgConnectOptions {
    /// Connect over a pre-connected futures stream.
    ///
    /// Performs the database handshake and negotiates TLS using these options.
    /// The configured hostname is still used for TLS certificate verification.
    pub async fn connect_with_stream_futures<S>(&self, stream: S) -> Result<PgConnection, Error>
    where
        S: futures_io::AsyncRead + futures_io::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        PgConnection::establish_with_socket(crate::net::FuturesStream::new(stream), self).await
    }
}
