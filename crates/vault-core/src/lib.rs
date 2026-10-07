//! Núcleo de la bóveda Contraseñas.
//!
//! Fase 1: solo interfaces y stubs. **Sin crypto de producción ni persistencia real.**

#![forbid(unsafe_code)]

pub mod audit;
pub mod crypto;
pub mod paths;
pub mod recovery;
pub mod session;

pub use audit::AuditSink;
pub use crypto::CryptoEngine;
pub use paths::AppPaths;
pub use recovery::RecoveryKit;
pub use session::{SessionError, SessionState, VaultSession};

/// Versión de esquema lógico de la app (independiente del formato en disco).
pub const APP_SCHEMA_VERSION: u16 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_phase1_stub() {
        assert_eq!(APP_SCHEMA_VERSION, 0);
    }

    #[test]
    fn session_starts_locked() {
        let session = VaultSession::new_locked();
        assert!(matches!(session.state(), SessionState::Locked));
    }
}
