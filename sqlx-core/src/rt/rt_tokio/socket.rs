use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::AsyncWrite;
use tokio::net::TcpStream;

use crate::io::ReadBuf;
use crate::net::Socket;

impl Socket for TcpStream {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        mut buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.try_read_buf(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!((*self).poll_read_ready(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(self).poll_write(cx, buf)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self).poll_shutdown(cx)
    }
}

#[cfg(unix)]
impl Socket for tokio::net::UnixStream {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        mut buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.try_read_buf(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!((*self).poll_read_ready(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(self).poll_write(cx, buf)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self).poll_shutdown(cx)
    }
}

/// Adapts a pre-connected Tokio stream without adding a data buffer.
pub struct TokioStream<S>(S);

impl<S> TokioStream<S> {
    pub fn new(stream: S) -> Self {
        Self(stream)
    }
}

impl<S> Socket for TokioStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        let mut buf = tokio::io::ReadBuf::new(buf.init_mut());
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::{Wake, Waker};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn backpressure_registers_wakers_without_empty_write_probes() {
        let (client, mut peer) = tokio::io::duplex(1);
        let mut socket = TokioStream::new(client);
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            socket.poll_write(&mut cx, b"a"),
            Poll::Ready(Ok(1))
        ));
        assert!(socket.poll_write(&mut cx, b"b").is_pending());
        let mut data = [0];
        let mut buf = tokio::io::ReadBuf::new(&mut data);
        assert!(Pin::new(&mut peer).poll_read(&mut cx, &mut buf).is_ready());
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            socket.poll_write(&mut cx, b"b"),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(data, *b"a");
    }

    #[test]
    fn reads_wake_and_buffered_writes_flush_before_shutdown() {
        crate::rt::test_block_on(async {
            let (client, mut peer) = tokio::io::duplex(64);
            let mut socket = TokioStream::new(tokio::io::BufStream::new(client));
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            let mut data = [0; 2];
            assert!(socket.poll_read(&mut cx, &mut &mut data[..]).is_pending());
            peer.write_all(b"hi").await.unwrap();
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            assert_eq!(socket.read(&mut &mut data[..]).await.unwrap(), 2);
            assert_eq!(&data, b"hi");
            socket.write(b"bye").await.unwrap();
            socket.flush().await.unwrap();
            let mut output = [0; 3];
            peer.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"bye");
            socket.shutdown().await.unwrap();
            assert_eq!(peer.read(&mut output).await.unwrap(), 0);
            peer.shutdown().await.unwrap();
            assert_eq!(socket.read(&mut &mut data[..]).await.unwrap(), 0);
        });
    }
}
