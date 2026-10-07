//! Sesión en memoria: derive → use → wipe (Fase 2).
//!
//! No abre archivos de bóveda (Fase 3). La DEK vive solo mientras `Unlocked`.

use crate::crypto::{unlock_dek_with_master, CryptoError, CryptoHeaderV1, DataEncryptionKey};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Locked,
    Unlocked,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("la sesión ya está desbloqueada")]
    AlreadyUnlocked,
    #[error("la sesión ya está bloqueada")]
    AlreadyLocked,
    #[error("desbloqueo fallido")]
    UnlockFailed,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Sesión de claves en memoria. Al hacer `lock` o `Drop`, la DEK se limpia (zeroize).
pub struct VaultSession {
    state: SessionState,
    dek: Option<DataEncryptionKey>,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self::new_locked()
    }
}

impl std::fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSession")
            .field("state", &self.state)
            .field("dek", &self.dek.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl VaultSession {
    pub fn new_locked() -> Self {
        Self {
            state: SessionState::Locked,
            dek: None,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Desbloquea en memoria desenvolviendo la DEK. No persiste nada.
    pub fn unlock_with_master(
        &mut self,
        master_password: &[u8],
        header: &CryptoHeaderV1,
    ) -> Result<(), SessionError> {
        if self.state == SessionState::Unlocked {
            return Err(SessionError::AlreadyUnlocked);
        }
        let dek = unlock_dek_with_master(master_password, header).map_err(|e| match e {
            CryptoError::UnwrapFailed | CryptoError::DecryptFailed | CryptoError::KdfFailed => {
                SessionError::UnlockFailed
            }
            other => SessionError::Crypto(other),
        })?;
        self.dek = Some(dek);
        self.state = SessionState::Unlocked;
        Ok(())
    }

    /// Acceso a la DEK solo con sesión desbloqueada.
    pub fn dek(&self) -> Option<&DataEncryptionKey> {
        self.dek.as_ref()
    }

    /// Bloquea y limpia la DEK (zeroize vía Drop del `DataEncryptionKey`).
    pub fn lock(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Locked {
            return Err(SessionError::AlreadyLocked);
        }
        self.dek = None;
        self.state = SessionState::Locked;
        Ok(())
    }

    /// Sin cabecera persistida no hay desbloqueo desde UI (Fase 3).
    pub fn try_unlock_stub(&mut self, _master_password: &str) -> Result<(), SessionError> {
        Err(SessionError::UnlockFailed)
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.dek = None;
        self.state = SessionState::Locked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{bootstrap_key_material_with_params, decrypt, encrypt, KdfParams};

    #[test]
    fn unlock_use_lock_wipes_dek_handle() {
        let params = KdfParams::for_tests();
        let boot = bootstrap_key_material_with_params(b"session-pass", &params, false).unwrap();
        let mut session = VaultSession::new_locked();
        session
            .unlock_with_master(b"session-pass", &boot.header)
            .unwrap();
        assert_eq!(session.state(), SessionState::Unlocked);
        let dek = session.dek().unwrap();
        let ct = encrypt(dek, b"payload", b"sess").unwrap();
        let pt = decrypt(dek, &ct, b"sess").unwrap();
        assert_eq!(pt, b"payload");
        session.lock().unwrap();
        assert_eq!(session.state(), SessionState::Locked);
        assert!(session.dek().is_none());
        assert_eq!(
            session.unlock_with_master(b"bad", &boot.header),
            Err(SessionError::UnlockFailed)
        );
    }

    #[test]
    fn stub_unlock_still_fails() {
        let mut s = VaultSession::new_locked();
        assert_eq!(s.try_unlock_stub("x"), Err(SessionError::UnlockFailed));
    }
}
