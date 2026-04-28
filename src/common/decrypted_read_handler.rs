use core::ops::Range;

use crate::{
    TlsError,
    alert::AlertDescription,
    common::{decrypted_buffer_info::DecryptedBufferInfo, session_ticket::SessionTicket},
    config::TlsCipherSuite,
    handshake::ServerHandshake,
    key_schedule::ReadKeySchedule,
    record::ServerRecord,
};

pub struct DecryptedReadHandler<'a> {
    pub source_buffer: Range<*const u8>,
    pub buffer_info: &'a mut DecryptedBufferInfo,
    pub is_open: &'a mut bool,
    /// Slot for the most recent server-issued NewSessionTicket. `None` when the
    /// caller is uninterested in resumption material.
    pub session_ticket_slot: Option<&'a mut Option<SessionTicket>>,
}

impl DecryptedReadHandler<'_> {
    pub fn handle<CipherSuite: TlsCipherSuite>(
        &mut self,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
        record: ServerRecord<'_, CipherSuite>,
    ) -> Result<(), TlsError> {
        match record {
            ServerRecord::ApplicationData(data) => {
                let slice = data.data.as_slice();
                let slice_ptrs = slice.as_ptr_range();

                debug_assert!(
                    self.source_buffer.contains(&slice_ptrs.start)
                        && self.source_buffer.contains(&slice_ptrs.end)
                );

                let offset = unsafe {
                    // SAFETY: The assertion above ensures `slice` is a subslice of the read buffer.
                    // This, in turn, ensures we don't violate safety constraints of `offset_from`.

                    // TODO: We are only assuming here that the pointers are derived from the read
                    // buffer. While this is reasonable, and we don't do any pointer magic,
                    // it's not an invariant.
                    slice_ptrs.start.offset_from(self.source_buffer.start) as usize
                };

                self.buffer_info.offset = offset;
                self.buffer_info.len = slice.len();
                self.buffer_info.consumed = 0;
                Ok(())
            }
            ServerRecord::Alert(alert) => {
                if let AlertDescription::CloseNotify = alert.description {
                    *self.is_open = false;
                    Err(TlsError::ConnectionClosed)
                } else {
                    Err(TlsError::InternalError)
                }
            }
            ServerRecord::ChangeCipherSpec(_) => Err(TlsError::InternalError),
            ServerRecord::Handshake(ServerHandshake::NewSessionTicket(nst)) => {
                // Derive the per-ticket PSK and stash it in the slot the
                // caller (TlsConnection / TlsReader) reserved. Failures
                // (oversize ticket so parse returned empty, missing
                // resumption secret) are swallowed — the connection itself
                // stays healthy and resumption simply won't be available for
                // this ticket.
                if !nst.nonce.is_empty() && !nst.ticket.is_empty() {
                    if let Some(slot) = self.session_ticket_slot.as_deref_mut() {
                        if let Ok(psk_bytes) = key_schedule.derive_psk_for_ticket(&nst.nonce) {
                            let mut psk = heapless::Vec::new();
                            // SHA-384 is the largest cipher suite hash;
                            // psk_bytes always fits in MAX_PSK_LEN (48).
                            if psk
                                .extend_from_slice(psk_bytes.as_slice())
                                .is_ok()
                            {
                                *slot = Some(SessionTicket {
                                    ticket: nst.ticket,
                                    psk,
                                    lifetime_secs: nst.lifetime,
                                    age_add: nst.age_add,
                                });
                            }
                        }
                    }
                }
                Ok(())
            }
            ServerRecord::Handshake(_) => {
                unimplemented!()
            }
        }
    }
}
