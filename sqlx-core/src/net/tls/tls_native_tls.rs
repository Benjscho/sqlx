use std::io::{self, Read, Write};

use crate::io::ReadBuf;
use crate::net::tls::util::{polling, StdSocket};
use crate::net::tls::TlsConfig;
use crate::net::Socket;
use crate::rt;
use crate::Error;

use native_tls::{HandshakeError, Identity};
use std::future::poll_fn;
use std::task::{ready, Context, Poll, Waker};

pub struct NativeTlsSocket<S: Socket> {
    stream: native_tls::TlsStream<TlsIo<S>>,
    shutdown_sent: bool,
}

// native_tls owns its synchronous stream. Own a Waker instead of a pointer to
// a borrowed Context so this bridge remains safe across handshake polls.
struct TlsIo<S> {
    socket: S,
    waker: Option<Waker>,
}

impl<S: Socket> TlsIo<S> {
    fn with_context<T>(&mut self, f: impl FnOnce(&mut StdSocket<'_, '_, '_, S>) -> T) -> T {
        let waker = self.waker.as_ref().expect("TLS I/O outside a poll");
        let mut cx = Context::from_waker(waker);
        f(&mut StdSocket::new(&mut self.socket, &mut cx))
    }
}

impl<S: Socket> Read for TlsIo<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.with_context(|socket| socket.read(buf))
    }
}

impl<S: Socket> Write for TlsIo<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.with_context(|socket| socket.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_context(|socket| socket.flush())
    }
}

impl<S: Socket> NativeTlsSocket<S> {
    fn poll_io<T>(
        &mut self,
        cx: &Context<'_>,
        f: impl FnOnce(&mut native_tls::TlsStream<TlsIo<S>>) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        self.stream.get_mut().waker = Some(cx.waker().clone());
        let result = f(&mut self.stream);
        self.stream.get_mut().waker = None;
        polling(result)
    }
}

impl<S: Socket> Socket for NativeTlsSocket<S> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        self.poll_io(cx, |stream| stream.read(buf.init_mut()))
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_io(cx, |stream| stream.write(buf))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(cx, |stream| stream.flush())
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            ready!(self.poll_io(cx, |stream| stream.shutdown()))?;
            self.shutdown_sent = true;
        }
        ready!(self.poll_flush(cx))?;
        // The database server may have already closed the connection.
        let _ = ready!(self.stream.get_mut().socket.poll_shutdown(cx));
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct NativeTlsConnector {
    connector: native_tls::TlsConnector,
}

pub async fn connector(config: TlsConfig<'_>) -> crate::Result<NativeTlsConnector> {
    let mut builder = native_tls::TlsConnector::builder();

    builder
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .danger_accept_invalid_hostnames(config.accept_invalid_hostnames);

    if let Some(root_cert_path) = config.root_cert_path {
        let data = root_cert_path.data().await?;
        builder.add_root_certificate(native_tls::Certificate::from_pem(&data).map_err(Error::tls)?);
    }

    // authentication using user's key-file and its associated certificate
    if let (Some(cert_path), Some(key_path)) = (config.client_cert_path, config.client_key_path) {
        let cert_path = cert_path.data().await?;
        let key_path = key_path.data().await?;
        let identity = Identity::from_pkcs8(&cert_path, &key_path).map_err(Error::tls)?;
        builder.identity(identity);
    }

    // The openssl TlsConnector synchronously loads certificates from files.
    // Loading these files can block for tens of milliseconds.
    let connector = rt::spawn_blocking(move || builder.build())
        .await
        .map_err(Error::tls)?;
    Ok(NativeTlsConnector { connector })
}

pub async fn handshake<S: Socket>(
    socket: S,
    hostname: &str,
    connector: &NativeTlsConnector,
) -> crate::Result<NativeTlsSocket<S>> {
    let mut initial = Some(TlsIo {
        socket,
        waker: None,
    });
    let mut pending: Option<native_tls::MidHandshakeTlsStream<TlsIo<S>>> = None;
    poll_fn(|cx| {
        let result = if let Some(mut socket) = initial.take() {
            socket.waker = Some(cx.waker().clone());
            connector.connector.connect(hostname, socket)
        } else {
            let mut handshake = pending.take().expect("handshake polled after completion");
            handshake.get_mut().waker = Some(cx.waker().clone());
            handshake.handshake()
        };
        match result {
            Ok(mut stream) => {
                stream.get_mut().waker = None;
                Poll::Ready(Ok(NativeTlsSocket {
                    stream,
                    shutdown_sent: false,
                }))
            }
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(Error::tls(e))),
            Err(HandshakeError::WouldBlock(mut handshake)) => {
                handshake.get_mut().waker = None;
                pending = Some(handshake);
                Poll::Pending
            }
        }
    })
    .await
}

#[cfg(all(test, feature = "_rt-tokio"))]
mod tests {
    use super::*;
    use crate::net::TokioStream;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::Wake;
    use tokio::io::AsyncWrite;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn synchronous_bridge_registers_the_current_task_without_buffering() {
        let (client, mut peer) = tokio::io::duplex(1);
        let first = Arc::new(WakeCount::default());
        let second = Arc::new(WakeCount::default());
        let mut socket = TlsIo {
            socket: TokioStream::new(client),
            waker: None,
        };
        let mut data = [0; 1];
        for task in [&first, &second] {
            socket.waker = Some(Waker::from(task.clone()));
            assert_eq!(
                socket.read(&mut data).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            socket.waker = None;
        }
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut peer).poll_write(&mut cx, b"x").is_ready());
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        socket.waker = Some(Waker::from(second));
        assert_eq!(socket.read(&mut data).unwrap(), 1);
        assert_eq!(&data, b"x");
        assert_eq!(socket.write(b"a").unwrap(), 1);
        assert_eq!(
            socket.write(b"b").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(peer);
        assert_eq!(socket.read(&mut data).unwrap(), 0);
    }
}
