//! Rutas de datos de la aplicación (Fase 3).
//!
//! Datos fuera del repo, en el data dir del SO. Nombres poco reveladores.

use std::path::PathBuf;

/// Nombres de fichero previstos (sin crearlos aún en Fase 1).
pub const VAULT_DB_FILE: &str = "vault.dat";
pub const VAULT_HEADER_FILE: &str = "vault.header";
pub const BACKUPS_DIR: &str = "backups";
pub const LOGS_DIR: &str = "logs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub data_dir: PathBuf,
}

impl AppPaths {
    /// Construye rutas lógicas bajo un data dir (p. ej. el que provea Tauri).
    pub fn from_data_dir(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub fn vault_db(&self) -> PathBuf {
        self.data_dir.join(VAULT_DB_FILE)
    }

    pub fn vault_header(&self) -> PathBuf {
        self.data_dir.join(VAULT_HEADER_FILE)
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.data_dir.join(BACKUPS_DIR)
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.data_dir.join(LOGS_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_paths_use_generic_names() {
        let paths = AppPaths::from_data_dir(PathBuf::from("/tmp/contrasenas-test"));
        assert!(paths.vault_db().ends_with("vault.dat"));
        assert!(!paths.vault_db().to_string_lossy().contains("password"));
    }
}
