//! Almacenamiento de bóveda — Fase 3–5.
//!
//! Backend preferido: **SQLCipher** + AEAD de campos en `vault-core`.

#![forbid(unsafe_code)]

mod blob;
mod permissions;
mod rows;
mod sqlcipher;

pub use blob::BlobVaultDb;
pub use permissions::{ensure_data_dir, set_owner_only_file_permissions};
pub use rows::{CredentialRow, HistoryRow, PolicyRow};
pub use sqlcipher::{SqlCipherVaultDb, SCHEMA_VERSION_V1, SCHEMA_VERSION_V2, SCHEMA_VERSION_V3};

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
    #[error("credencial no encontrada")]
    CredentialNotFound,
    #[error("política no encontrada")]
    PolicyNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackendKind {
    SqlCipherAead,
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

/// Contrato de persistencia cifrada.
pub trait VaultDb: Send {
    fn backend_kind(&self) -> StorageBackendKind;
    fn path(&self) -> &Path;
    fn exists_on_disk(&self) -> bool;
    fn create(&mut self, key: &[u8; 32]) -> Result<(), StorageError>;
    fn open(&mut self, key: &[u8; 32]) -> Result<(), StorageError>;
    fn close(&mut self);
    fn is_open(&self) -> bool;
    fn schema_version(&self) -> Result<u16, StorageError>;
    fn ensure_schema_v1(&mut self) -> Result<(), StorageError>;
    fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError>;
    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), StorageError>;

    // --- Credenciales (Fase 4) ---
    fn upsert_credential(&mut self, row: &CredentialRow) -> Result<(), StorageError>;
    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, StorageError>;
    fn list_credentials(&self, include_deleted: bool) -> Result<Vec<CredentialRow>, StorageError>;
    fn soft_delete_credential(&mut self, id: &str, deleted_at: &str) -> Result<(), StorageError>;
    fn restore_credential(&mut self, id: &str) -> Result<(), StorageError>;
    fn insert_history(&mut self, row: &HistoryRow) -> Result<(), StorageError>;
    fn list_history(&self, credential_id: &str) -> Result<Vec<HistoryRow>, StorageError>;
    fn count_password_fp(&self, fp: &str, exclude_id: Option<&str>) -> Result<u32, StorageError>;

    // --- Políticas (Fase 5) ---
    fn upsert_policy(&mut self, row: &PolicyRow) -> Result<(), StorageError>;
    fn get_policy(&self, id: &str) -> Result<Option<PolicyRow>, StorageError>;
    fn list_policies(&self) -> Result<Vec<PolicyRow>, StorageError>;
    fn delete_policy(&mut self, id: &str) -> Result<(), StorageError>;
    fn clear_credential_policy(&mut self, policy_id: &str) -> Result<(), StorageError>;
    fn insert_password_fp_history(
        &mut self,
        id: &str,
        credential_id: &str,
        password_fp: &str,
        created_at: &str,
    ) -> Result<(), StorageError>;
    fn list_password_fp_history(
        &self,
        credential_id: &str,
        limit: u32,
    ) -> Result<Vec<String>, StorageError>;
}

pub fn default_backend() -> StorageBackendKind {
    StorageBackendKind::SqlCipherAead
}

pub fn open_db_handle(kind: StorageBackendKind, db_path: PathBuf) -> Box<dyn VaultDb> {
    match kind {
        StorageBackendKind::SqlCipherAead => Box::new(SqlCipherVaultDb::new(db_path)),
        StorageBackendKind::BlobAeadFallback => Box::new(BlobVaultDb::new(db_path)),
    }
}

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
