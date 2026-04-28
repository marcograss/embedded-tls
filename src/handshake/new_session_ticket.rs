use core::marker::PhantomData;

use crate::extensions::messages::NewSessionTicketExtension;
use crate::parse_buffer::ParseBuffer;
use crate::{TlsError, unused};

/// Maximum supported NewSessionTicket nonce length.
///
/// Per RFC 8446 §4.6.1 the on-wire field is a `u8` length, so up to 255 bytes
/// is legal. In practice servers (rustls, OpenSSL, BoringSSL) emit ≤32 bytes.
/// 64 leaves headroom for any well-behaved server.
///
/// Note: this Vec lives inside `ServerHandshake::NewSessionTicket(_)`, which
/// is `#[allow(clippy::large_enum_variant)]` and held across many awaits
/// inside `tls.open()`. Growing this constant directly bloats every TLS
/// future state machine — on resource-constrained embedded targets the cost
/// can push the stack over a tight bss/stack boundary. If you're picking a
/// new value, give the embedded consumer a chance to budget for it.
pub const MAX_TICKET_NONCE_LEN: usize = 64;

/// Maximum supported NewSessionTicket ticket length.
///
/// 384 bytes covers SimpleX / OpenSSL / rustls / BoringSSL ticket sizes in
/// practice (typical range 64-256 bytes). Same future-state caveat as
/// `MAX_TICKET_NONCE_LEN`.
pub const MAX_TICKET_LEN: usize = 384;

#[derive(Debug, Clone)]
pub struct NewSessionTicket<'a> {
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: heapless::Vec<u8, MAX_TICKET_NONCE_LEN>,
    pub ticket: heapless::Vec<u8, MAX_TICKET_LEN>,
    _marker: PhantomData<&'a ()>,
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for NewSessionTicket<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "NewSessionTicket {{ lifetime: {}, age_add: {:x}, nonce_len: {}, ticket_len: {} }}",
            self.lifetime,
            self.age_add,
            self.nonce.len(),
            self.ticket.len(),
        );
    }
}

impl<'a> NewSessionTicket<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<NewSessionTicket<'a>, TlsError> {
        let lifetime = buf.read_u32()?;
        let age_add = buf.read_u32()?;

        let nonce_length = buf.read_u8()? as usize;
        let nonce_slice = buf
            .slice(nonce_length)
            .map_err(|_| TlsError::InvalidNonceLength)?;

        let ticket_length = buf.read_u16()? as usize;
        let ticket_slice = buf
            .slice(ticket_length)
            .map_err(|_| TlsError::InvalidTicketLength)?;

        let extensions = NewSessionTicketExtension::parse_vector::<1>(buf)?;
        unused(extensions);

        // Copy out of the parse buffer (which is reused by the next record
        // read) into owned heapless::Vec storage so the ticket survives until
        // the application calls take_session_ticket(). If either length
        // exceeds the cap, return an *empty* ticket — the connection stays
        // healthy, the application's session_ticket_slot just won't be
        // populated. Failing the parse here would kill the post-handshake
        // read loop, which is far worse than missing one resumption
        // opportunity.
        let mut nonce = heapless::Vec::new();
        if nonce.extend_from_slice(nonce_slice.as_slice()).is_err() {
            return Ok(Self::empty());
        }

        let mut ticket = heapless::Vec::new();
        if ticket.extend_from_slice(ticket_slice.as_slice()).is_err() {
            return Ok(Self::empty());
        }

        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            _marker: PhantomData,
        })
    }

    fn empty() -> Self {
        Self {
            lifetime: 0,
            age_add: 0,
            nonce: heapless::Vec::new(),
            ticket: heapless::Vec::new(),
            _marker: PhantomData,
        }
    }
}
