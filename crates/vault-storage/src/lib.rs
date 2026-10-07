//! Almacenamiento de bóveda — stubs Fase 1.
//!
//! Decisión D2: SQLCipher + AEAD de campos, con fallback a blob AEAD.
//! Ninguna implementación de producción aquí.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("almacenamiento no implementado en Fase 1")]
    NotImplemented,
}

/// Backend de almacenamiento previsto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendKind {
    /// SQLCipher + AEAD de campos (preferido).
    SqlCipherAead,
    /// Fallback: blob único AEAD si el build SQLCipher bloquea un OS.
    BlobAeadFallback,
}

/// Contrato de almacén. Fase 1: no abre ni crea ficheros reales.
pub trait VaultStore: Send + Sync {
    fn backend_kind(&self) -> StorageBackendKind;
    fn exists(&self) -> Result<bool, StorageError>;
}

/// Stub que reporta “no existe bóveda” sin tocar disco.
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
        let store = StubVaultStore::preferred_sqlcipher();
        assert_eq!(store.backend_kind(), StorageBackendKind::SqlCipherAead);
        assert_eq!(store.exists(), Ok(false));
    }
}
