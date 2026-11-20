use crate::net::Socket;
use std::io::{self, Read, Write};
use std::task::{Context, Poll};

/// A synchronous view of a socket for a single TLS poll.
///
/// Pending I/O has already registered the task's waker before returning WouldBlock.
pub struct StdSocket<'s, 'c, 'w, S> {
    socket: &'s mut S,
    cx: &'c mut Context<'w>,
}

impl<'s, 'c, 'w, S: Socket> StdSocket<'s, 'c, 'w, S> {
    pub fn new(socket: &'s mut S, cx: &'c mut Context<'w>) -> Self {
        Self { socket, cx }
    }
}

impl<S: Socket> Read for StdSocket<'_, '_, '_, S> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        blocking(self.socket.poll_read(self.cx, &mut buf))
    }
}

impl<S: Socket> Write for StdSocket<'_, '_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        blocking(self.socket.poll_write(self.cx, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        blocking(self.socket.poll_flush(self.cx))
    }
}

pub fn blocking<T>(result: Poll<io::Result<T>>) -> io::Result<T> {
    match result {
        Poll::Ready(result) => result,
        Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
    }
}

pub fn polling<T>(result: io::Result<T>) -> Poll<io::Result<T>> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        result => Poll::Ready(result),
    }
}
