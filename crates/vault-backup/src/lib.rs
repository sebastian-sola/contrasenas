//! Backups — Fase 3: hook de copia preventiva; formato `.cpbak` completo más adelante.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use thiserror::Error;

/// Versión de formato de backup prevista.
pub const BACKUP_FORMAT_VERSION: u16 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("backup no implementado completamente")]
    NotImplemented,
    #[error("error de E/S en backup")]
    Io,
    #[error("origen de backup no encontrado")]
    NotFound,
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
        Ok(BackupHeaderStub::default())
    }
}

/// Copia preventiva de un fichero (p. ej. antes de migrar schema).
/// No cifra adicionalmente: el origen ya debe estar cifrado (SQLCipher / header público).
pub fn preventive_copy(src: &Path, dst: &Path) -> Result<(), BackupError> {
    if !src.exists() {
        return Err(BackupError::NotFound);
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|_| BackupError::Io)?;
    }
    fs::copy(src, dst).map_err(|_| BackupError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn backup_version_is_defined() {
        let svc = StubBackupService;
        assert_eq!(svc.format_version(), 1);
        let header = svc.create_stub().expect("stub ok");
        assert_eq!(header.backup_version, BACKUP_FORMAT_VERSION);
    }

    #[test]
    fn preventive_copy_works() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.dat");
        let dst = dir.path().join("backups/a.dat");
        let mut f = fs::File::create(&src).unwrap();
        f.write_all(b"ciphered").unwrap();
        preventive_copy(&src, &dst).unwrap();
        assert_eq!(fs::read(dst).unwrap(), b"ciphered");
    }
}
