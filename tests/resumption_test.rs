//! End-to-end TLS 1.3 session resumption test.
//!
//! Uses an OpenSSL TLS 1.3 server (which issues a NewSessionTicket
//! post-handshake by default) to validate the full resumption path:
//!
//! 1. Connection 1: full TLS 1.3 handshake (Cert + CertVerify + Finished).
//!    Client reads server data, which delivers the NewSessionTicket as a
//!    handshake message after ApplicationData.
//! 2. Client calls `take_session_ticket()` to drain the cached
//!    `(ticket, psk, lifetime)` triple derived from the resumption_master_secret
//!    per RFC 8446 §7.1 / §4.6.1.
//! 3. Connection 2: client offers the cached PSK via
//!    `with_psk_resumption(psk, &[ticket])`. Server accepts the PSK,
//!    skips Cert/CertVerify, completes the abbreviated 1-RTT handshake.
//!
//! This catches regressions in:
//! * NewSessionTicket parse + per-ticket PSK derivation
//! * `take_session_ticket()` plumbing across the read loop
//! * The resumption-vs-external `binder_label` selection (RFC 8446 §4.2.11)
//!   — wrong label here makes the server's binder check fail.

#![macro_use]
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::*;
use openssl::ssl;
use rand::rngs::OsRng;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::Once;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

static INIT: Once = Once::new();

/// Spin up an OpenSSL TLS 1.3 server that handles two consecutive client
/// connections. The first sends "PING-1" and reads "PONG-1"; the second
/// sends "PING-2" and reads "PONG-2". Tickets are issued by default; the
/// session cache is internal so the second connection can resume.
fn setup() -> (SocketAddr, JoinHandle<()>) {
    INIT.call_once(|| {
        let _ = env_logger::try_init();
    });

    let mut builder =
        ssl::SslAcceptor::mozilla_intermediate_v5(ssl::SslMethod::tls_server()).unwrap();
    builder
        .set_private_key_file("tests/data/server-key.pem", ssl::SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("tests/data/server-cert.pem")
        .unwrap();
    builder
        .set_min_proto_version(Some(ssl::SslVersion::TLS1_3))
        .unwrap();
    builder
        .set_max_proto_version(Some(ssl::SslVersion::TLS1_3))
        .unwrap();
    // OpenSSL needs a session-id context to issue resumable tickets.
    builder.set_session_id_context(b"embedded-tls-resumption").unwrap();
    // Send exactly one NewSessionTicket per handshake (default is 2).
    builder.set_num_tickets(1).unwrap();
    let acceptor = builder.build();

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).expect("cannot listen on port");
    let addr = listener
        .local_addr()
        .expect("error retrieving socket address");

    let h = tokio::task::spawn_blocking(move || {
        for (greeting, expected_response) in
            [(b"PING-1" as &[u8], b"PONG-1" as &[u8]), (b"PING-2", b"PONG-2")]
        {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = acceptor
                .accept(stream)
                .expect("server-side TLS accept failed");
            // Send greeting; the NewSessionTicket rides along immediately
            // after the server Finished, so the client's first read after
            // open() will pick it up.
            conn.write_all(greeting).expect("server write failed");
            let mut buf = [0u8; 6];
            conn.read_exact(&mut buf).expect("server read failed");
            assert_eq!(&buf[..6], expected_response);
            // Graceful shutdown so the client's read loop returns Ok(0).
            let _ = conn.shutdown();
        }
    });
    (addr, h)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_session_resumption_round_trip() {
    let (addr, h) = setup();

    timeout(Duration::from_secs(120), async move {
        // ── Connection 1: full handshake, drain NST ─────────────────
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut read_buf = [0u8; 16384];
        let mut write_buf = [0u8; 16384];
        let config = TlsConfig::new().with_server_name("localhost");
        let mut tls = TlsConnection::new(FromTokio::new(stream), &mut read_buf, &mut write_buf);

        // NoVerify provider — we're testing resumption, not cert validation.
        tls.open(TlsContext::new(
            &config,
            UnsecureProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .await
        .expect("first handshake failed");

        // Read the server's PING-1; the NewSessionTicket lands during this
        // call (it's a handshake record interleaved with application data).
        let mut rx = [0u8; 6];
        let n = tls.read(&mut rx).await.expect("read after first handshake");
        assert_eq!(n, 6);
        assert_eq!(&rx[..6], b"PING-1");
        tls.write(b"PONG-1").await.expect("write PONG-1");
        tls.flush().await.expect("flush PONG-1");

        // Drain the captured ticket. Must be Some — OpenSSL is configured
        // to send exactly one NST.
        let ticket = tls
            .take_session_ticket()
            .expect("no session ticket captured after first handshake");
        assert!(!ticket.ticket.is_empty(), "captured ticket is empty");
        assert!(!ticket.psk.is_empty(), "captured psk is empty");
        assert_eq!(ticket.psk.len(), 32, "expected 32-byte PSK for SHA-256");

        // Close the first connection. take_session_ticket() consumed the slot.
        let _ = tls.close().await;

        // Hold ticket bytes in stable storage for the second handshake's
        // `with_psk_resumption` call.
        let ticket_bytes: Vec<u8> = ticket.ticket.iter().copied().collect();
        let psk_bytes: Vec<u8> = ticket.psk.iter().copied().collect();

        // ── Connection 2: abbreviated handshake via PSK_DHE_KE ─────
        let stream2 = TcpStream::connect(addr).await.unwrap();
        let mut read_buf2 = [0u8; 16384];
        let mut write_buf2 = [0u8; 16384];
        let identities: [&[u8]; 1] = [&ticket_bytes];
        let config2 = TlsConfig::new()
            .with_server_name("localhost")
            .with_psk_resumption(&psk_bytes, &identities);
        let mut tls2 =
            TlsConnection::new(FromTokio::new(stream2), &mut read_buf2, &mut write_buf2);

        tls2.open(TlsContext::new(
            &config2,
            UnsecureProvider::new::<Aes128GcmSha256>(OsRng),
        ))
        .await
        .expect("resumption handshake failed — likely binder mismatch");

        // The abbreviated handshake should be fully established and able to
        // round-trip data exactly like a fresh one.
        let mut rx2 = [0u8; 6];
        let n2 = tls2
            .read(&mut rx2)
            .await
            .expect("read after resumed handshake");
        assert_eq!(n2, 6);
        assert_eq!(&rx2[..6], b"PING-2");
        tls2.write(b"PONG-2").await.expect("write PONG-2");
        tls2.flush().await.expect("flush PONG-2");

        let _ = tls2.close().await;
        h.await.unwrap();
    })
    .await
    .expect("resumption round-trip timed out");
}
