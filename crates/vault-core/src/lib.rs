//! Núcleo de la bóveda Contraseñas.
//!
//! Fase 10: hardening / revisión de seguridad.

#![forbid(unsafe_code)]

pub mod audit;
pub mod backup_ops;
pub mod backoff;
pub mod credentials;
pub mod crypto;
pub mod generator;
pub mod logging;
pub mod paths;
pub mod policy;
pub mod recovery;
pub mod session;
pub mod settings;
pub mod vault;
pub mod vault_header;

pub use audit::{
    AuditError, AuditEvent, AuditEventStub, AuditFilter, AuditSink, NullAuditSink, PendingAudit,
    CONTEXT_ALLOWLIST,
};
pub use backup_ops::BackupInfo;
pub use credentials::{expiry_color, Credential, CredentialInput, CredentialSummary, HistoryEntry};
pub use crypto::{
    bootstrap_key_material, bootstrap_key_material_with_params, decrypt, derive_db_key, encrypt,
    unlock_dek_with_master, CryptoEngine, CryptoError, CryptoHeaderV1, DataEncryptionKey,
    KdfParams, ProductionCryptoEngine, CRYPTO_FORMAT_VERSION,
};
pub use generator::{
    build_charset, estimate_strength, generate, generate_for_policy, options_from_policy,
    GeneratedPassword, GeneratorError, GeneratorOptions, GENERATOR_RNG_ID,
};
pub use logging::{contains_any_secret, redact_secrets};
pub use paths::AppPaths;
pub use policy::{
    apply_expiry_from_policy, validate_password, PasswordPolicy, PolicyInput, PolicyValidation,
};
pub use recovery::{
    generate_recovery_code, unlock_dek_with_recovery, ProductionRecoveryKit, RecoveryError,
    RecoveryKit, StubRecoveryKit,
};
pub use session::{SessionError, SessionState, VaultSession};
pub use settings::{normalize_clipboard_secs, AppSettings};
pub use vault::{CreateVaultResult, Vault, VaultError};
pub use vault_header::{VaultFileHeader, VAULT_SCHEMA_VERSION};

/// Versión de esquema lógico de la bóveda en disco (v4 = auditoría).
pub const APP_SCHEMA_VERSION: u16 = 4;

/// Fase de desarrollo implementada en este crate.
pub const IMPLEMENTED_PHASE: u8 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_is_ten() {
        assert_eq!(IMPLEMENTED_PHASE, 10);
    }

    /// Los crates de bóveda no deben arrastrar clientes HTTP obvios.
    #[test]
    fn vault_core_manifest_has_no_http_clients() {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        for forbidden in ["reqwest", "ureq", "hyper", "tokio-tungstenite"] {
            assert!(
                !manifest.contains(forbidden),
                "vault-core no debe depender de {forbidden}"
            );
        }
    }

    #[test]
    fn session_starts_locked() {
        let session = VaultSession::new_locked();
        assert!(matches!(session.state(), SessionState::Locked));
    }
}
