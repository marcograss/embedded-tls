//! Key exchange abstraction supporting P-256 and X25519.

use crate::extensions::extension_data::supported_groups::NamedGroup;
use rand_core::CryptoRngCore;

/// Ephemeral key exchange secret supporting multiple groups.
pub(crate) enum EphemeralSecret {
    P256(p256::ecdh::EphemeralSecret),
    #[cfg(feature = "x25519")]
    X25519(x25519_dalek::EphemeralSecret),
}

impl EphemeralSecret {
    /// Generate a random ephemeral secret for the preferred named group.
    pub fn random(group: NamedGroup, rng: &mut impl CryptoRngCore) -> Self {
        match group {
            #[cfg(feature = "x25519")]
            NamedGroup::X25519 => Self::X25519(x25519_dalek::EphemeralSecret::random_from_rng(rng)),
            _ => Self::P256(p256::ecdh::EphemeralSecret::random(rng)),
        }
    }

    /// Get the named group for this secret.
    pub fn group(&self) -> NamedGroup {
        match self {
            Self::P256(_) => NamedGroup::Secp256r1,
            #[cfg(feature = "x25519")]
            Self::X25519(_) => NamedGroup::X25519,
        }
    }

    /// Encode the public key into the provided buffer. Returns the slice written.
    pub fn public_key_bytes<'a>(&self, buf: &'a mut [u8; 128]) -> &'a [u8] {
        match self {
            Self::P256(secret) => {
                let point = p256::EncodedPoint::from(&secret.public_key());
                let bytes = point.as_ref();
                buf[..bytes.len()].copy_from_slice(bytes);
                &buf[..bytes.len()]
            }
            #[cfg(feature = "x25519")]
            Self::X25519(secret) => {
                let public = x25519_dalek::PublicKey::from(secret);
                buf[..32].copy_from_slice(public.as_bytes());
                &buf[..32]
            }
        }
    }

    /// Compute the shared secret given the server's public key bytes.
    /// Returns the raw shared secret bytes (32 bytes for both P-256 and X25519).
    pub fn diffie_hellman(self, server_public_key: &[u8]) -> Option<SharedSecret> {
        match self {
            Self::P256(secret) => {
                let server_pk = p256::PublicKey::from_sec1_bytes(server_public_key).ok()?;
                let shared = secret.diffie_hellman(&server_pk);
                Some(SharedSecret::from_p256(shared))
            }
            #[cfg(feature = "x25519")]
            Self::X25519(secret) => {
                let server_pk_bytes: [u8; 32] = server_public_key.try_into().ok()?;
                let server_pk = x25519_dalek::PublicKey::from(server_pk_bytes);
                let shared = secret.diffie_hellman(&server_pk);
                Some(SharedSecret::from_x25519(shared))
            }
        }
    }
}

/// Wrapper for shared secret that provides uniform access to the raw bytes.
pub(crate) struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    fn from_p256(shared: p256::ecdh::SharedSecret) -> Self {
        let raw = shared.raw_secret_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw.as_slice());
        Self { bytes }
    }

    #[cfg(feature = "x25519")]
    fn from_x25519(shared: x25519_dalek::SharedSecret) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(shared.as_bytes());
        Self { bytes }
    }

    pub fn raw_secret_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
