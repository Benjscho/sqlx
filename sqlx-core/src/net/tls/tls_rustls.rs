use std::future;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use rustls::{
    client::{
        danger::{ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{
        pem::{self, PemObject},
        CertificateDer, PrivateKeyDer, ServerName, UnixTime,
    },
    CertificateError, ClientConfig, ClientConnection, Error as TlsError, RootCertStore,
};

use crate::error::Error;
use crate::io::ReadBuf;
use crate::net::tls::util::{polling, StdSocket};
use crate::net::tls::TlsConfig;
use crate::net::Socket;

pub struct RustlsSocket<S: Socket> {
    inner: S,
    state: ClientConnection,
    close_notify_sent: bool,
}

impl<S: Socket> RustlsSocket<S> {
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        // Register both directions when writes are blocked. Incoming records
        // can still make progress while the peer is not accepting our writes.
        if let Poll::Ready(Err(error)) = self.poll_flush(cx) {
            return Poll::Ready(Err(error));
        }
        let read = ready!(polling(
            self.state
                .read_tls(&mut StdSocket::new(&mut self.inner, cx))
        ))?;
        if let Err(error) = self.state.process_new_packets() {
            // Best effort: send any queued alert without masking the TLS error.
            let _ = self.poll_flush(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        Poll::Ready(Ok(read))
    }
}

impl<S: Socket> Socket for RustlsSocket<S> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut dyn ReadBuf,
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.state.reader().read(buf.init_mut()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_receive(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match self.state.writer().write(buf) {
                // Rustls returns zero when its plaintext buffer is full.
                Ok(0) => {
                    ready!(self.poll_flush(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Only write out the pending TLS records: once nothing is left to write,
        // reading would wait for the peer to send something,
        // so a close (which flushes first) would hang if the peer has nothing more to say.
        while self.state.wants_write() {
            match ready!(polling(
                self.state
                    .write_tls(&mut StdSocket::new(&mut self.inner, cx))
            ))? {
                0 => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                _ => {}
            }
        }
        self.inner.poll_flush(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.close_notify_sent {
            self.state.send_close_notify();
            self.close_notify_sent = true;
        }

        ready!(self.poll_flush(cx))?;

        // Server can close socket as soon as it receives the connection shutdown request.
        // We shouldn't expect it to stick around for the TLS session to close cleanly.
        // https://security.stackexchange.com/a/82034
        let _ = ready!(self.inner.poll_shutdown(cx));

        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct RustlsConnector {
    config: Arc<ClientConfig>,
}

pub async fn connector(tls_config: TlsConfig<'_>) -> Result<RustlsConnector, Error> {
    #[cfg(all(
        any(
            feature = "_tls-rustls-aws-lc-rs",
            feature = "_tls-rustls-aws-lc-rs-native-roots"
        ),
        not(feature = "_tls-rustls-ring-webpki"),
        not(feature = "_tls-rustls-ring-native-roots")
    ))]
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(any(
        feature = "_tls-rustls-ring-webpki",
        feature = "_tls-rustls-ring-native-roots"
    ))]
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Unwrapping is safe here because we use a default provider.
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();

    // authentication using user's key and its associated certificate
    let user_auth = match (tls_config.client_cert_path, tls_config.client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_chain = certs_from_pem(cert_path.data().await?)?;
            let key_der = private_key_from_pem(key_path.data().await?)?;
            Some((cert_chain, key_der))
        }
        (None, None) => None,
        (_, _) => {
            return Err(Error::Configuration(
                "user auth key and certs must be given together".into(),
            ))
        }
    };

    let config = if tls_config.accept_invalid_certs {
        if let Some(user_auth) = user_auth {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier { provider }))
                .with_client_auth_cert(user_auth.0, user_auth.1)
                .map_err(Error::tls)?
        } else {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier { provider }))
                .with_no_client_auth()
        }
    } else {
        let mut cert_store = import_root_certs();

        if let Some(ca) = tls_config.root_cert_path {
            let data = ca.data().await?;

            for result in CertificateDer::pem_slice_iter(&data) {
                let Ok(cert) = result else {
                    return Err(Error::Tls(format!("Invalid certificate {ca}").into()));
                };

                cert_store.add(cert).map_err(|err| Error::Tls(err.into()))?;
            }
        }

        if tls_config.accept_invalid_hostnames {
            let verifier = WebPkiServerVerifier::builder(Arc::new(cert_store))
                .build()
                .map_err(|err| Error::Tls(err.into()))?;

            if let Some(user_auth) = user_auth {
                config
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoHostnameTlsVerifier { verifier }))
                    .with_client_auth_cert(user_auth.0, user_auth.1)
                    .map_err(Error::tls)?
            } else {
                config
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoHostnameTlsVerifier { verifier }))
                    .with_no_client_auth()
            }
        } else if let Some(user_auth) = user_auth {
            config
                .with_root_certificates(cert_store)
                .with_client_auth_cert(user_auth.0, user_auth.1)
                .map_err(Error::tls)?
        } else {
            config
                .with_root_certificates(cert_store)
                .with_no_client_auth()
        }
    };

    Ok(RustlsConnector {
        config: Arc::new(config),
    })
}

pub async fn handshake<S>(
    socket: S,
    hostname: &str,
    connector: &RustlsConnector,
) -> Result<RustlsSocket<S>, Error>
where
    S: Socket,
{
    let host = ServerName::try_from(hostname.to_owned()).map_err(Error::tls)?;

    let mut socket = RustlsSocket {
        inner: socket,
        state: ClientConnection::new(connector.config.clone(), host).map_err(Error::tls)?,
        close_notify_sent: false,
    };

    // Performs the TLS handshake or bails
    future::poll_fn(|cx| {
        while socket.state.is_handshaking() {
            if ready!(socket.poll_receive(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
        // A buffered transport can return Pending after accepting the final
        // handshake records. Retry its flush even once the handshake is done.
        socket.poll_flush(cx)
    })
    .await?;

    Ok(socket)
}

fn certs_from_pem(pem: Vec<u8>) -> Result<Vec<CertificateDer<'static>>, Error> {
    CertificateDer::pem_slice_iter(&pem)
        .map(|result| result.map_err(|err| Error::Tls(err.into())))
        .collect()
}

fn private_key_from_pem(pem: Vec<u8>) -> Result<PrivateKeyDer<'static>, Error> {
    match PrivateKeyDer::from_pem_slice(&pem) {
        Ok(key) => Ok(key),
        Err(pem::Error::NoItemsFound) => Err(Error::Configuration("no keys found pem file".into())),
        Err(e) => Err(Error::Configuration(e.to_string().into())),
    }
}

#[cfg(all(feature = "webpki-roots", not(feature = "rustls-native-certs")))]
fn import_root_certs() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

#[cfg(feature = "rustls-native-certs")]
fn import_root_certs() -> RootCertStore {
    let mut root_cert_store = RootCertStore::empty();

    let load_results = rustls_native_certs::load_native_certs();
    for e in load_results.errors {
        log::warn!("Error loading native certificates: {e:?}");
    }
    for cert in load_results.certs {
        if let Err(e) = root_cert_store.add(cert) {
            log::warn!("rustls failed to parse native certificate: {e:?}");
        }
    }

    root_cert_store
}

// Not currently used but allows for a "tls-rustls-no-roots" feature.
#[cfg(not(any(feature = "rustls-native-certs", feature = "webpki-roots")))]
fn import_root_certs() -> RootCertStore {
    RootCertStore::empty()
}

#[derive(Debug)]
struct DummyTlsVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct NoHostnameTlsVerifier {
    verifier: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            res => res,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::Waker;

    use rustls::{ConnectionCommon, ServerConfig, ServerConnection};

    use super::*;
    use crate::net::BufferedSocket;

    // A self-signed certificate and its key, for the test server only.
    const CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBIjCB1aADAgECAhQRcu62KABJbi99FYkUEAUGt9j9JDAFBgMrZXAwFDESMBAG
A1UEAwwJbG9jYWxob3N0MCAXDTI2MTAwODIyMzE0OVoYDzIxMjYwOTE0MjIzMTQ5
WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwKjAFBgMrZXADIQCIT8wE5M9/LF5HKWU7
hFe/SqknU66oA0FPmjfdziJ/IqM3MDUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MB0G
A1UdDgQWBBRarcSa6Ue2Ob0JlPlE/409LAm6STAFBgMrZXADQQBpNitWpyHm05qH
3Z4w/YG/Ufe05/aDwRAwOKM9snf+pqJ8eG+WnxupOK9oJY/GpmTpW2XSBpVHyGRJ
SmndpuEE
-----END CERTIFICATE-----";

    const KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID8jex+k7LAgC5JfhRHaleP+dhL1s4NemFDa1CMKvcuu
-----END PRIVATE KEY-----";

    /// A peer that takes every write and never sends anything.
    #[derive(Default)]
    struct SilentPeer {
        received: Vec<u8>,
    }

    impl Socket for SilentPeer {
        fn poll_read(
            &mut self,
            _cx: &mut Context<'_>,
            _buf: &mut dyn ReadBuf,
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_write(&mut self, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.received.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Has `to` read and process `records`.
    fn deliver<D>(mut records: &[u8], to: &mut ConnectionCommon<D>) {
        while !records.is_empty() {
            to.read_tls(&mut records).unwrap();
            to.process_new_packets().unwrap();
        }
    }

    /// Delivers the TLS records queued in `from` to `to`.
    fn transfer<A, B>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) {
        let mut records = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut records).unwrap();
        }
        deliver(&records, to);
    }

    #[track_caller]
    fn assert_ready_ok(poll: Poll<io::Result<()>>) {
        assert!(
            matches!(poll, Poll::Ready(Ok(()))),
            "expected `Ready(Ok(()))`, got {poll:?}"
        );
    }

    fn connections() -> (Arc<ClientConfig>, ServerConnection) {
        let mut cx = Context::from_waker(Waker::noop());
        // The client's config as `sslmode=require` builds it; loading no files, it's ready at once.
        let tls_config = TlsConfig {
            accept_invalid_certs: true,
            accept_invalid_hostnames: true,
            root_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        };
        let Poll::Ready(Ok(RustlsConnector { config })) = pin!(connector(tls_config)).poll(&mut cx)
        else {
            panic!("`connector()` should be ready at once");
        };

        let server_config = ServerConfig::builder_with_provider(config.crypto_provider().clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap(),
            )
            .unwrap();
        let server = ServerConnection::new(Arc::new(server_config)).unwrap();
        (config, server)
    }

    struct BufferedPeer {
        server: ServerConnection,
        outgoing: Vec<u8>,
        incoming: Vec<u8>,
        flush_pending: bool,
    }

    impl Socket for BufferedPeer {
        fn poll_read(
            &mut self,
            _cx: &mut Context<'_>,
            buf: &mut dyn ReadBuf,
        ) -> Poll<io::Result<usize>> {
            if !self.outgoing.is_empty() {
                return Poll::Pending;
            }
            if self.incoming.is_empty() {
                return Poll::Pending;
            }
            let buf = buf.init_mut();
            let len = buf.len().min(self.incoming.len()).min(17);
            buf[..len].copy_from_slice(&self.incoming[..len]);
            self.incoming.drain(..len);
            Poll::Ready(Ok(len))
        }

        fn poll_write(&mut self, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let len = buf.len().min(17);
            self.outgoing.extend_from_slice(&buf[..len]);
            Poll::Ready(Ok(len))
        }

        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !self.flush_pending {
                self.flush_pending = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.flush_pending = false;
            deliver(&std::mem::take(&mut self.outgoing), &mut self.server);
            while self.server.wants_write() {
                self.server.write_tls(&mut self.incoming)?;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn bounded_poll<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..10_000 {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                return result;
            }
        }
        panic!("TLS operation stalled");
    }

    #[test]
    fn handshake_and_shutdown_retry_pending_transport_flushes() {
        let (config, server) = connections();
        let peer = BufferedPeer {
            server,
            outgoing: Vec::new(),
            incoming: Vec::new(),
            flush_pending: false,
        };
        let connector = RustlsConnector { config };
        let mut socket = bounded_poll(handshake(peer, "localhost", &connector)).unwrap();
        let payload = vec![42; 20_000];
        bounded_poll(async {
            let mut remaining = &payload[..];
            while !remaining.is_empty() {
                let written = socket.write(remaining).await.unwrap();
                assert_ne!(written, 0);
                remaining = &remaining[written..];
            }
            socket.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        socket
            .inner
            .server
            .reader()
            .read_to_end(&mut received)
            .unwrap();
        assert_eq!(received, payload);
        assert!(socket
            .inner
            .server
            .process_new_packets()
            .unwrap()
            .peer_has_closed());
    }

    #[test]
    fn reads_progress_while_outgoing_records_are_backpressured() {
        struct BackpressuredPeer(io::Cursor<Vec<u8>>);

        impl Socket for BackpressuredPeer {
            fn poll_read(
                &mut self,
                _cx: &mut Context<'_>,
                buf: &mut dyn ReadBuf,
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(self.0.read(buf.init_mut()))
            }

            fn poll_write(
                &mut self,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }

            fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (config, mut server) = connections();
        let mut client =
            ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
        while client.is_handshaking() || server.is_handshaking() {
            transfer(&mut client, &mut server);
            transfer(&mut server, &mut client);
        }
        server.writer().write_all(b"response").unwrap();
        let mut incoming = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut incoming).unwrap();
        }
        client.writer().write_all(b"request").unwrap();
        let mut socket = RustlsSocket {
            inner: BackpressuredPeer(io::Cursor::new(incoming)),
            state: client,
            close_notify_sent: false,
        };
        let mut output = [0; 8];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            socket.poll_read(&mut cx, &mut &mut output[..]),
            Poll::Ready(Ok(8))
        ));
        assert_eq!(&output, b"response");
    }

    // A flush with nothing left to write used to read and wait for the peer to send something,
    // so a close, which flushes first, never ended if the peer had nothing more to say (#4449).
    #[test]
    fn flush_and_shutdown_do_not_wait_for_a_silent_peer() {
        let mut cx = Context::from_waker(Waker::noop());

        let (config, mut server) = connections();
        let mut client =
            ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();

        // Complete the handshake in memory.
        while client.is_handshaking() || server.is_handshaking() {
            transfer(&mut client, &mut server);
            transfer(&mut server, &mut client);
        }

        let mut socket = RustlsSocket {
            inner: SilentPeer::default(),
            state: client,
            close_notify_sent: false,
        };

        // A write is flushed out.
        assert_eq!(
            match socket.poll_write(&mut cx, b"ping") {
                Poll::Ready(Ok(n)) => n,
                other => panic!("{other:?}"),
            },
            4
        );
        assert_ready_ok(socket.poll_flush(&mut cx));

        // With nothing left to write, a flush must not wait for the peer.
        assert_ready_ok(socket.poll_flush(&mut cx));

        // `close_hard()` shuts down through `BufferedSocket::shutdown()`, which flushes first.
        let mut socket = BufferedSocket::new(socket);
        assert_ready_ok(pin!(socket.shutdown()).poll(&mut cx));

        // The peer got the write, then the close_notify.
        deliver(&socket.into_inner().inner.received, &mut server);
        let mut received = Vec::new();
        server.reader().read_to_end(&mut received).unwrap();
        assert_eq!(received, b"ping");
        assert!(server.process_new_packets().unwrap().peer_has_closed());
    }
}
