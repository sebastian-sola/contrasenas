//! Argon2id con parámetros versionados.

use super::keys::{KeyEncryptionKey, Salt, KEY_LEN};
use super::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

/// Parámetros KDF persistidos en la cabecera (públicos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Versión lógica de la política de parámetros (no la versión del algoritmo Argon2).
    pub version: u16,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Parámetros de producción v1 (~64 MiB, t=3, p=1).
    pub const fn v1() -> Self {
        Self {
            version: 1,
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Parámetros ligeros solo para tests unitarios (rápidos).
    pub const fn for_tests() -> Self {
        Self {
            version: 1,
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn to_argon2_params(self) -> Result<Params, CryptoError> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| CryptoError::UnsupportedKdfParams)
    }
}

/// Deriva una KEK de 32 bytes. No registra ni formatea la contraseña.
pub fn derive_kek(
    password: &[u8],
    salt: &Salt,
    params: &KdfParams,
) -> Result<KeyEncryptionKey, CryptoError> {
    if !(1..=65_536).contains(&params.m_cost_kib)
        || params.t_cost == 0
        || params.p_cost == 0
        || params.p_cost > 16
    {
        return Err(CryptoError::UnsupportedKdfParams);
    }

    let argon_params = params.to_argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(KeyEncryptionKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_salt;

    #[test]
    fn derive_is_deterministic() {
        let salt = generate_salt().unwrap();
        let p = KdfParams::for_tests();
        let a = derive_kek(b"same", &salt, &p).unwrap();
        let b = derive_kek(b"same", &salt, &p).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn different_password_different_kek() {
        let salt = generate_salt().unwrap();
        let p = KdfParams::for_tests();
        let a = derive_kek(b"a", &salt, &p).unwrap();
        let b = derive_kek(b"b", &salt, &p).unwrap();
        assert_ne!(a.expose(), b.expose());
    }
}
