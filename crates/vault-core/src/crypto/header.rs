//! Cabecera crypto versionada (campos públicos; sin secretos en claro).

use super::kdf::KdfParams;
use super::keys::{Salt, SALT_LEN};
use super::wrap::WrappedDek;
use super::CryptoError;
use serde::{Deserialize, Serialize};

pub const CRYPTO_FORMAT_VERSION: u16 = 1;
pub const KDF_ID_ARGON2ID: &str = "argon2id";
pub const AEAD_ID_AES256GCM: &str = "aes-256-gcm";

/// Cabecera serializable para el futuro archivo de bóveda (Fase 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoHeaderV1 {
    pub format_version: u16,
    pub kdf_id: String,
    pub kdf_version: u16,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Vec<u8>,
    pub aead_id: String,
    pub wrapped_dek: WrappedDek,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_salt: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_dek_recovery: Option<WrappedDek>,
}

impl CryptoHeaderV1 {
    pub fn new_master_wrap(params: KdfParams, salt: Salt, wrapped_dek: WrappedDek) -> Self {
        Self {
            format_version: CRYPTO_FORMAT_VERSION,
            kdf_id: KDF_ID_ARGON2ID.to_string(),
            kdf_version: params.version,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt: salt.to_vec(),
            aead_id: AEAD_ID_AES256GCM.to_string(),
            wrapped_dek,
            recovery_salt: None,
            wrapped_dek_recovery: None,
        }
    }

    pub fn set_recovery(&mut self, recovery_salt: Salt, wrapped: WrappedDek) {
        self.recovery_salt = Some(recovery_salt.to_vec());
        self.wrapped_dek_recovery = Some(wrapped);
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.format_version != CRYPTO_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedFormatVersion);
        }
        if self.kdf_id != KDF_ID_ARGON2ID {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        if self.aead_id != AEAD_ID_AES256GCM {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        if self.salt.len() != SALT_LEN {
            return Err(CryptoError::InvalidSaltLength);
        }
        if let Some(rs) = &self.recovery_salt {
            if rs.len() != SALT_LEN {
                return Err(CryptoError::InvalidSaltLength);
            }
        }
        if self.wrapped_dek.bytes.len() < 12 + 16 {
            return Err(CryptoError::CorruptData);
        }
        // Si hay uno de recovery, deben estar ambos.
        match (&self.recovery_salt, &self.wrapped_dek_recovery) {
            (None, None) => Ok(()),
            (Some(_), Some(w)) if w.bytes.len() >= 12 + 16 => Ok(()),
            _ => Err(CryptoError::InvalidHeader),
        }
    }

    pub fn kdf_params(&self) -> Result<KdfParams, CryptoError> {
        let params = KdfParams {
            version: self.kdf_version,
            m_cost_kib: self.m_cost_kib,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
        };
        // Solo aceptamos la política v1 conocida por ahora.
        if params.version != KdfParams::v1().version {
            return Err(CryptoError::UnsupportedKdfParams);
        }
        Ok(params)
    }

    pub fn salt_array(&self) -> Result<Salt, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        if self.salt.len() != SALT_LEN {
            return Err(CryptoError::InvalidSaltLength);
        }
        salt.copy_from_slice(&self.salt);
        Ok(salt)
    }

    pub fn recovery_salt_array(&self) -> Result<Option<Salt>, CryptoError> {
        match &self.recovery_salt {
            None => Ok(None),
            Some(rs) => {
                if rs.len() != SALT_LEN {
                    return Err(CryptoError::InvalidSaltLength);
                }
                let mut salt = [0u8; SALT_LEN];
                salt.copy_from_slice(rs);
                Ok(Some(salt))
            }
        }
    }
}
