//! TLS 1.3 session resumption material.
//!
//! `SessionTicket` carries the bytes the server expects back in a future
//! ClientHello (the opaque ticket identity) plus the per-ticket PSK derived
//! from the resumption_master_secret per RFC 8446 §4.6.1:
//!
//! ```text
//! psk = HKDF-Expand-Label(resumption_master_secret,
//!                         "resumption", ticket_nonce, Hash.length)
//! ```
//!
//! The application calls [`crate::TlsConnection::take_session_ticket`] to
//! drain the slot; the cached `(ticket, psk)` pair can then be fed back to
//! [`crate::TlsConfig::with_psk`] on the next connect to the same server,
//! turning a 1.5-RTT certificate-bearing handshake into a 1-RTT abbreviated
//! handshake.
//!
//! Maximum PSK length is sized for SHA-384 (48 bytes); SHA-256 cipher suites
//! populate the first 32 bytes only.

pub use crate::handshake::new_session_ticket::{MAX_TICKET_LEN, MAX_TICKET_NONCE_LEN};

/// Maximum PSK length in bytes — sized for SHA-384 (48 bytes).
pub const MAX_PSK_LEN: usize = 48;

#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// Opaque ticket identity from the server's NewSessionTicket. Echoed back
    /// in a future ClientHello PreSharedKey extension as one of the identities.
    pub ticket: heapless::Vec<u8, MAX_TICKET_LEN>,
    /// Per-ticket PSK derived via HKDF-Expand-Label(resumption_master_secret,
    /// "resumption", ticket_nonce, Hash.length). Length matches the cipher
    /// suite's hash output size (32 for SHA-256, 48 for SHA-384).
    pub psk: heapless::Vec<u8, MAX_PSK_LEN>,
    /// Ticket lifetime in seconds (RFC 8446 §4.6.1: ≤ 7 days = 604800).
    pub lifetime_secs: u32,
    /// Ticket age add (RFC 8446 §4.6.1) — relevant for 0-RTT, currently unused.
    pub age_add: u32,
}

#[cfg(feature = "defmt")]
impl defmt::Format for SessionTicket {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "SessionTicket {{ ticket_len: {}, psk_len: {}, lifetime: {} }}",
            self.ticket.len(),
            self.psk.len(),
            self.lifetime_secs,
        );
    }
}
