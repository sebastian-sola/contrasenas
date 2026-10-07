//! AES-256-GCM para payloads (campos / blobs en memoria).

use super::keys::DataEncryptionKey;
use super::CryptoError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

const NONCE_LEN: usize = 12;

/// Caja AEAD: `nonce (12) || ciphertext+tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadBox {
    pub bytes: Vec<u8>,
}

pub fn encrypt(
    dek: &DataEncryptionKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AeadBox, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(dek.expose()).map_err(|_| CryptoError::EncryptFailed)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CryptoError::RngFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);
    Ok(AeadBox { bytes: out })
}

pub fn decrypt(
    dek: &DataEncryptionKey,
    boxed: &AeadBox,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if boxed.bytes.len() < NONCE_LEN + 16 {
        return Err(CryptoError::CorruptData);
    }
    let (nonce_bytes, ct) = boxed.bytes.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(dek.expose()).map_err(|_| CryptoError::DecryptFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| CryptoError::DecryptFailed)
}
