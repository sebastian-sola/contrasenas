//! Núcleo de la bóveda Contraseñas.
//!
//! Fase 4: criptografía + bóveda + CRUD de credenciales (AEAD de campos).

#![forbid(unsafe_code)]

pub mod audit;
pub mod backoff;
pub mod credentials;
pub mod crypto;
pub mod paths;
pub mod recovery;
pub mod session;
pub mod vault;
pub mod vault_header;

pub use audit::AuditSink;
pub use credentials::{expiry_color, Credential, CredentialInput, CredentialSummary, HistoryEntry};
pub use crypto::{
    bootstrap_key_material, bootstrap_key_material_with_params, decrypt, derive_db_key, encrypt,
    unlock_dek_with_master, CryptoEngine, CryptoError, CryptoHeaderV1, DataEncryptionKey,
    KdfParams, ProductionCryptoEngine, CRYPTO_FORMAT_VERSION,
};
pub use paths::AppPaths;
pub use recovery::{
    generate_recovery_code, unlock_dek_with_recovery, ProductionRecoveryKit, RecoveryError,
    RecoveryKit, StubRecoveryKit,
};
pub use session::{SessionError, SessionState, VaultSession};
pub use vault::{CreateVaultResult, Vault, VaultError};
pub use vault_header::{VaultFileHeader, VAULT_SCHEMA_VERSION};

/// Versión de esquema lógico de la bóveda en disco (v2 = credenciales completas).
pub const APP_SCHEMA_VERSION: u16 = 2;

/// Fase de desarrollo implementada en este crate.
pub const IMPLEMENTED_PHASE: u8 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_is_four() {
        assert_eq!(IMPLEMENTED_PHASE, 4);
    }

    #[test]
    fn session_starts_locked() {
        let session = VaultSession::new_locked();
        assert!(matches!(session.state(), SessionState::Locked));
    }
}
