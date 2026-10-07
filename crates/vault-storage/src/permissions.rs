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
