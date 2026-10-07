//! Cabecera pública de bóveda en disco (`vault.header`).

use crate::backoff::BackoffState;
use crate::crypto::{CryptoError, CryptoHeaderV1};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;
use vault_storage::{
    ensure_data_dir, set_owner_only_file_permissions, StorageBackendKind, StorageError,
};

pub const VAULT_HEADER_MAGIC: &str = "CPVH1";
pub const VAULT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderError {
    #[error("cabecera no encontrada")]
    NotFound,
    #[error("cabecera inválida o corrupta")]
    Invalid,
    #[error("error de E/S")]
    Io,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFileHeader {
    pub magic: String,
    pub schema_version: u16,
    pub vault_id: String,
    pub backend: StorageBackendKind,
    pub crypto: CryptoHeaderV1,
    pub backoff: BackoffState,
    /// Segundos de auto-bloqueo (default 300 = 5 min).
    pub auto_lock_secs: u64,
}

impl VaultFileHeader {
    pub fn new(vault_id: String, backend: StorageBackendKind, crypto: CryptoHeaderV1) -> Self {
        Self {
            magic: VAULT_HEADER_MAGIC.to_string(),
            schema_version: VAULT_SCHEMA_VERSION,
            vault_id,
            backend,
            crypto,
            backoff: BackoffState::default(),
            auto_lock_secs: 300,
        }
    }

    pub fn validate(&self) -> Result<(), HeaderError> {
        if self.magic != VAULT_HEADER_MAGIC {
            return Err(HeaderError::Invalid);
        }
        if self.schema_version == 0 || self.schema_version > VAULT_SCHEMA_VERSION {
            return Err(HeaderError::Invalid);
        }
        self.crypto.validate()?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, HeaderError> {
        let bytes = fs::read(path).map_err(|_| HeaderError::NotFound)?;
        let header: Self = serde_json::from_slice(&bytes).map_err(|_| HeaderError::Invalid)?;
        header.validate()?;
        Ok(header)
    }

    pub fn save(&self, path: &Path) -> Result<(), HeaderError> {
        if let Some(parent) = path.parent() {
            ensure_data_dir(parent).map_err(|e| match e {
                StorageError::Io => HeaderError::Io,
                _ => HeaderError::Io,
            })?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| HeaderError::Invalid)?;
        fs::write(path, bytes).map_err(|_| HeaderError::Io)?;
        set_owner_only_file_permissions(path).map_err(|_| HeaderError::Io)?;
        Ok(())
    }
}
