//! Permisos restrictivos del directorio de datos.

use super::StorageError;
use std::fs;
use std::path::Path;

/// Crea el data dir con permisos de propietario únicamente (Unix 0o700).
pub fn ensure_data_dir(dir: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(dir).map_err(|_| StorageError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms).map_err(|_| StorageError::Io)?;
    }
    Ok(())
}

/// Fichero solo lectura/escritura del propietario (Unix 0o600).
pub fn set_owner_only_file_permissions(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|_| StorageError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn data_dir_is_owner_only_700() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault-data");
        ensure_data_dir(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn file_is_owner_only_600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        fs::write(&path, b"x").unwrap();
        set_owner_only_file_permissions(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
