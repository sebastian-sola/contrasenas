//! Sesión de bóveda — stub Fase 1 (sin unlock real).

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Locked,
    /// Reservado; no alcanzable en Fase 1 sin crypto real.
    Unlocked,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("desbloqueo real no disponible en Fase 1")]
    UnlockNotImplemented,
    #[error("la sesión ya está bloqueada")]
    AlreadyLocked,
}

#[derive(Debug)]
pub struct VaultSession {
    state: SessionState,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self::new_locked()
    }
}

impl VaultSession {
    pub fn new_locked() -> Self {
        Self {
            state: SessionState::Locked,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Placeholder: rechaza cualquier intento de desbloqueo con material real.
    pub fn try_unlock_stub(&mut self, _master_password: &str) -> Result<(), SessionError> {
        Err(SessionError::UnlockNotImplemented)
    }

    pub fn lock(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Locked {
            return Err(SessionError::AlreadyLocked);
        }
        self.state = SessionState::Locked;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_stub_rejects() {
        let mut s = VaultSession::new_locked();
        assert_eq!(
            s.try_unlock_stub("no-es-una-password-real"),
            Err(SessionError::UnlockNotImplemented)
        );
        assert_eq!(s.state(), SessionState::Locked);
    }
}
