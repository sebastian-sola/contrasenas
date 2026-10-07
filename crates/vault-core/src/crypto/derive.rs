//! Derivación de subclaves a partir de la DEK (HKDF-SHA256).

use super::keys::{DataEncryptionKey, KEY_LEN};
use super::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

const INFO_SQLCIPHER: &[u8] = b"contrasenas/v1/sqlcipher-key";

/// Deriva la clave de 32 bytes para SQLCipher (u otro backend) desde la DEK.
pub fn derive_db_key(dek: &DataEncryptionKey) -> Result<[u8; KEY_LEN], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, dek.expose());
    let mut out = [0u8; KEY_LEN];
    hk.expand(INFO_SQLCIPHER, &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_dek;

    #[test]
    fn derive_is_deterministic() {
        let dek = generate_dek().unwrap();
        let a = derive_db_key(&dek).unwrap();
        let b = derive_db_key(&dek).unwrap();
        assert_eq!(a, b);
        assert_ne!(&a, dek.expose());
    }
}
