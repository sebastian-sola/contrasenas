//! Backups cifrados `.cpbak` — stubs Fase 1.
//! Ver `docs/BACKUP.md` para el formato con `backup_version`.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Versión de formato de backup prevista (aún no se escriben ficheros).
pub const BACKUP_FORMAT_VERSION: u16 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("backup no implementado en Fase 1")]
    NotImplemented,
}

/// Metadatos públicos previstos del header (sin secretos).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupHeaderStub {
    pub backup_version: u16,
}

impl Default for BackupHeaderStub {
    fn default() -> Self {
        Self {
            backup_version: BACKUP_FORMAT_VERSION,
        }
    }
}

pub trait BackupService: Send + Sync {
    fn format_version(&self) -> u16;
    fn create_stub(&self) -> Result<BackupHeaderStub, BackupError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StubBackupService;

impl BackupService for StubBackupService {
    fn format_version(&self) -> u16 {
        BACKUP_FORMAT_VERSION
    }

    fn create_stub(&self) -> Result<BackupHeaderStub, BackupError> {
        // No escribe a disco en Fase 1.
        Ok(BackupHeaderStub::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_version_is_defined() {
        let svc = StubBackupService;
        assert_eq!(svc.format_version(), 1);
        let header = svc.create_stub().expect("stub ok");
        assert_eq!(header.backup_version, BACKUP_FORMAT_VERSION);
    }
}
