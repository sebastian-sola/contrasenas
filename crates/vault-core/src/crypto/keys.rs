//! Material de claves con wipe best-effort.

use super::CryptoError;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

/// Clave de cifrado de datos (DEK).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey {
    bytes: [u8; KEY_LEN],
}

impl DataEncryptionKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataEncryptionKey([REDACTED])")
    }
}

/// Clave de envoltorio (KEK) derivada por KDF.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey {
    bytes: [u8; KEY_LEN],
}

impl KeyEncryptionKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyEncryptionKey([REDACTED])")
    }
}

/// Salt público por bóveda / por vía de recuperación.
pub type Salt = [u8; SALT_LEN];

pub fn generate_salt() -> Result<Salt, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RngFailed)?;
    Ok(salt)
}

pub fn generate_dek() -> Result<DataEncryptionKey, CryptoError> {
    let mut bytes = [0u8; KEY_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RngFailed)?;
    Ok(DataEncryptionKey::from_bytes(bytes))
}
