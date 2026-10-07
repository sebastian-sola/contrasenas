//! Núcleo de la bóveda Contraseñas.
//!
//! Fase 2: criptografía de producción en memoria (Argon2id + AES-256-GCM).
//! **Sin** persistencia de bóveda ni CRUD (Fase 3).

#![forbid(unsafe_code)]

pub mod audit;
pub mod crypto;
pub mod paths;
pub mod recovery;
pub mod session;

pub use audit::AuditSink;
pub use crypto::{
    bootstrap_key_material, bootstrap_key_material_with_params, decrypt, encrypt,
    unlock_dek_with_master, CryptoEngine, CryptoError, CryptoHeaderV1, DataEncryptionKey,
    KdfParams, ProductionCryptoEngine, CRYPTO_FORMAT_VERSION,
};
pub use paths::AppPaths;
pub use recovery::{
    generate_recovery_code, unlock_dek_with_recovery, ProductionRecoveryKit, RecoveryError,
    RecoveryKit, StubRecoveryKit,
};
pub use session::{SessionError, SessionState, VaultSession};

/// Versión de esquema lógico de la app (independiente del formato en disco).
/// Fase 2 aún no persiste schema de DB → se mantiene 0 hasta Fase 3.
pub const APP_SCHEMA_VERSION: u16 = 0;

/// Fase de desarrollo implementada en este crate.
pub const IMPLEMENTED_PHASE: u8 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_is_two() {
        assert_eq!(IMPLEMENTED_PHASE, 2);
    }

    #[test]
    fn session_starts_locked() {
        let session = VaultSession::new_locked();
        assert!(matches!(session.state(), SessionState::Locked));
    }
}
