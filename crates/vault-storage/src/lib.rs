//! Almacenamiento de bóveda — Fase 3.
//!
//! Backend preferido: **SQLCipher** (páginas cifradas). Las columnas secretas
//! futuras llevan AEAD adicional en la capa `vault-core` (D2).
//! Fallback: blob AEAD (`BlobVaultDb`) si se selecciona explícitamente.

#![forbid(unsafe_code)]

mod blob;
mod permissions;
mod sqlcipher;

pub use blob::BlobVaultDb;
pub use permissions::{ensure_data_dir, set_owner_only_file_permissions};
pub use sqlcipher::{SqlCipherVaultDb, SCHEMA_VERSION_V1};

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("bóveda no encontrada")]
    NotFound,
    #[error("bóveda ya existe")]
    AlreadyExists,
    #[error("bóveda corrupta o clave incorrecta")]
    CorruptOrWrongKey,
    #[error("error de E/S")]
    Io,
    #[error("error de base de datos")]
    Database,
    #[error("migración no soportada")]
    UnsupportedMigration,
    #[error("bóveda no abierta")]
    NotOpen,
    #[error("bóveda ya abierta")]
    AlreadyOpen,
}

/// Backend de almacenamiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackendKind {
    /// SQLCipher + AEAD de campos (preferido, D2).
    SqlCipherAead,
    /// Fallback: blob único AEAD.
    BlobAeadFallback,
}

impl StorageBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SqlCipherAead => "sqlcipher_aead",
            Self::BlobAeadFallback => "blob_aead_fallback",
        }
    }
}

/// Contrato de persistencia cifrada (clave de 32 bytes = material derivado de DEK).
pub trait VaultDb: Send {
    fn backend_kind(&self) -> StorageBackendKind;
    fn path(&self) -> &Path;
    fn exists_on_disk(&self) -> bool;
    fn create(&mut self, key: &[u8; 32]) -> Result<(), StorageError>;
    fn open(&mut self, key: &[u8; 32]) -> Result<(), StorageError>;
    fn close(&mut self);
    fn is_open(&self) -> bool;
    fn schema_version(&self) -> Result<u16, StorageError>;
    /// Asegura schema v1 (crea tablas o migra desde 0).
    fn ensure_schema_v1(&mut self) -> Result<(), StorageError>;
    /// Lee un ajuste no secreto (solo con DB abierta).
    fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError>;
    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), StorageError>;
}

/// Elige SQLCipher por defecto; el caller puede forzar blob.
pub fn default_backend() -> StorageBackendKind {
    StorageBackendKind::SqlCipherAead
}

pub fn open_db_handle(kind: StorageBackendKind, db_path: PathBuf) -> Box<dyn VaultDb> {
    match kind {
        StorageBackendKind::SqlCipherAead => Box::new(SqlCipherVaultDb::new(db_path)),
        StorageBackendKind::BlobAeadFallback => Box::new(BlobVaultDb::new(db_path)),
    }
}

/// Compat: trait antiguo usado por la UI Fase 1/2.
pub trait VaultStore: Send + Sync {
    fn backend_kind(&self) -> StorageBackendKind;
    fn exists(&self) -> Result<bool, StorageError>;
}

#[derive(Debug, Clone, Copy)]
pub struct StubVaultStore {
    pub preferred: StorageBackendKind,
}

impl Default for StubVaultStore {
    fn default() -> Self {
        Self::preferred_sqlcipher()
    }
}

impl StubVaultStore {
    pub fn preferred_sqlcipher() -> Self {
        Self {
            preferred: StorageBackendKind::SqlCipherAead,
        }
    }
}

impl VaultStore for StubVaultStore {
    fn backend_kind(&self) -> StorageBackendKind {
        self.preferred
    }

    fn exists(&self) -> Result<bool, StorageError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_sqlcipher() {
        assert_eq!(default_backend(), StorageBackendKind::SqlCipherAead);
    }
}
