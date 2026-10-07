//! Envoltura AEAD de la DEK con una KEK.

use super::aead::{decrypt, encrypt, AeadBox};
use super::keys::{DataEncryptionKey, KeyEncryptionKey, KEY_LEN};
use super::CryptoError;
use serde::{Deserialize, Serialize};

/// Dominio AAD para evitar reutilizar envoltorios entre contextos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadKind {
    MasterDek,
    RecoveryDek,
}

impl AadKind {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::MasterDek => b"contrasenas/v1/wrap/master-dek",
            Self::RecoveryDek => b"contrasenas/v1/wrap/recovery-dek",
        }
    }
}

/// DEK envuelta: mismos bytes que `AeadBox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDek {
    pub bytes: Vec<u8>,
}

impl From<AeadBox> for WrappedDek {
    fn from(value: AeadBox) -> Self {
        Self { bytes: value.bytes }
    }
}

pub fn wrap_dek(
    kek: &KeyEncryptionKey,
    dek: &DataEncryptionKey,
    kind: AadKind,
) -> Result<WrappedDek, CryptoError> {
    // Reutilizamos AES-GCM tratando la KEK como clave AEAD de 32 B.
    let dek_as_key = DataEncryptionKey::from_bytes(*kek.expose());
    let boxed =
        encrypt(&dek_as_key, dek.expose(), kind.as_bytes()).map_err(|_| CryptoError::WrapFailed)?;
    Ok(boxed.into())
}

pub fn unwrap_dek(
    kek: &KeyEncryptionKey,
    wrapped: &WrappedDek,
    kind: AadKind,
) -> Result<DataEncryptionKey, CryptoError> {
    let dek_as_key = DataEncryptionKey::from_bytes(*kek.expose());
    let boxed = AeadBox {
        bytes: wrapped.bytes.clone(),
    };
    let plain = decrypt(&dek_as_key, &boxed, kind.as_bytes()).map_err(|e| match e {
        CryptoError::CorruptData => CryptoError::CorruptData,
        _ => CryptoError::UnwrapFailed,
    })?;
    if plain.len() != KEY_LEN {
        return Err(CryptoError::CorruptData);
    }
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(&plain);
    Ok(DataEncryptionKey::from_bytes(arr))
}
