use crate::net::Socket;

use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_io::Async;

use crate::io::ReadBuf;

impl Socket for Async<TcpStream> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.get_ref().read(buf.init_mut()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_readable(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.get_ref().write(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_writable(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_ref().shutdown(Shutdown::Both))
    }
}

#[cfg(unix)]
impl Socket for Async<std::os::unix::net::UnixStream> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.get_ref().read(buf.init_mut()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_readable(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            match self.get_ref().write(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_writable(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_ref().shutdown(Shutdown::Both))
    }
}

/// Adapts a pre-connected futures I/O stream without adding a data buffer.
pub struct FuturesStream<S>(S);

impl<S> FuturesStream<S> {
    pub fn new(stream: S) -> Self {
        Self(stream)
    }
}

impl<S> Socket for FuturesStream<S>
where
    S: futures_io::AsyncRead + futures_io::AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf.init_mut())
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::Waker;

    struct BackpressuredStream {
        polls: usize,
    }

    impl futures_io::AsyncRead for BackpressuredStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    impl futures_io::AsyncWrite for BackpressuredStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls += 1;
            assert!(self.polls <= 4, "write spun without yielding");
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }

    #[test]
    fn backpressure_yields_without_empty_probes_and_forwards_flush_and_close() {
        let mut socket = FuturesStream::new(BackpressuredStream { polls: 0 });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(pin!(socket.write(b"data")).poll(&mut cx).is_pending());
        assert_eq!(socket.0.polls, 1);
        assert!(socket.poll_flush(&mut cx).is_pending());
        assert!(
            matches!(socket.poll_shutdown(&mut cx), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[cfg(unix)]
    #[test]
    fn pending_reads_resume_and_writes_reach_peer() {
        use std::os::unix::net::UnixStream;

        crate::rt::test_block_on(async {
            let (client, mut peer) = UnixStream::pair().unwrap();
            let mut socket = FuturesStream::new(Async::new(client).unwrap());
            let mut data = [0; 2];
            let mut cx = Context::from_waker(Waker::noop());
            assert!(socket.poll_read(&mut cx, &mut &mut data[..]).is_pending());
            peer.write_all(b"hi").unwrap();
            assert_eq!(socket.read(&mut &mut data[..]).await.unwrap(), 2);
            assert_eq!(&data, b"hi");
            socket.write(b"ok").await.unwrap();
            socket.flush().await.unwrap();
            peer.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"ok");
            socket.shutdown().await.unwrap();
            drop(socket);
            assert_eq!(peer.read(&mut data).unwrap(), 0);
        });
    }
}
