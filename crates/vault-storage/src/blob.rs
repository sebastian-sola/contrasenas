//! Fallback blob AEAD: fichero JSON de metadatos internos cifrado por la capa superior.
//!
//! Este backend NO cifra por sí mismo: espera que `vault-core` escriba bytes ya AEAD
//! en `path` cuando está "cerrado", y aquí solo gestionamos un almacén temporal en
//! memoria + un sidecar `.meta.json` con schema/settings cuando está abierto.
//!
//! Para FASE 3 el backend activo por defecto es SQLCipher; este fallback permanece
//! disponible y se prueba de forma aislada.

use super::rows::{CredentialRow, HistoryRow};
use super::{StorageBackendKind, StorageError, VaultDb};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BlobState {
    schema_version: u16,
    settings: HashMap<String, String>,
}

/// Almacén blob: mientras está abierto mantiene estado en memoria;
/// `create`/`open` validan que exista un fichero opaco (cifrado por vault-core).
pub struct BlobVaultDb {
    path: PathBuf,
    open: bool,
    state: BlobState,
    /// Clave esperada solo para comprobar que create/open reciben material (no se guarda).
    opened_with_key_fingerprint: Option<[u8; 4]>,
}

impl BlobVaultDb {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            open: false,
            state: BlobState::default(),
            opened_with_key_fingerprint: None,
        }
    }

    fn meta_path(&self) -> PathBuf {
        let mut p = self.path.as_os_str().to_os_string();
        p.push(".openmeta");
        PathBuf::from(p)
    }

    fn fingerprint(key: &[u8; 32]) -> [u8; 4] {
        [key[0], key[1], key[2], key[3]]
    }
}

impl VaultDb for BlobVaultDb {
    fn backend_kind(&self) -> StorageBackendKind {
        StorageBackendKind::BlobAeadFallback
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn exists_on_disk(&self) -> bool {
        self.path.exists()
    }

    fn create(&mut self, key: &[u8; 32]) -> Result<(), StorageError> {
        if self.path.exists() {
            return Err(StorageError::AlreadyExists);
        }
        if let Some(parent) = self.path.parent() {
            super::permissions::ensure_data_dir(parent)?;
        }
        // Placeholder opaco; vault-core sobrescribe con AEAD real tras create.
        fs::write(&self.path, b"CPBLOB_PENDING").map_err(|_| StorageError::Io)?;
        super::permissions::set_owner_only_file_permissions(&self.path)?;
        self.state = BlobState {
            schema_version: 1,
            settings: HashMap::from([("auto_lock_secs".into(), "300".into())]),
        };
        self.open = true;
        self.opened_with_key_fingerprint = Some(Self::fingerprint(key));
        Ok(())
    }

    fn open(&mut self, key: &[u8; 32]) -> Result<(), StorageError> {
        if self.open {
            return Err(StorageError::AlreadyOpen);
        }
        if !self.path.exists() {
            return Err(StorageError::NotFound);
        }
        // El contenido real lo valida vault-core al descifrar; aquí solo abrimos sesión.
        if let Ok(bytes) = fs::read(self.meta_path()) {
            if let Ok(state) = serde_json::from_slice::<BlobState>(&bytes) {
                self.state = state;
            }
        }
        if self.state.schema_version == 0 {
            self.state.schema_version = 1;
        }
        self.open = true;
        self.opened_with_key_fingerprint = Some(Self::fingerprint(key));
        Ok(())
    }

    fn close(&mut self) {
        if self.open {
            let _ = fs::write(
                self.meta_path(),
                serde_json::to_vec(&self.state).unwrap_or_default(),
            );
        }
        self.open = false;
        self.opened_with_key_fingerprint = None;
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn schema_version(&self) -> Result<u16, StorageError> {
        if !self.open {
            return Err(StorageError::NotOpen);
        }
        Ok(self.state.schema_version)
    }

    fn ensure_schema_v1(&mut self) -> Result<(), StorageError> {
        if !self.open {
            return Err(StorageError::NotOpen);
        }
        if self.state.schema_version == 0 {
            self.state.schema_version = 1;
        } else if self.state.schema_version > 1 {
            return Err(StorageError::UnsupportedMigration);
        }
        Ok(())
    }

    fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        if !self.open {
            return Err(StorageError::NotOpen);
        }
        Ok(self.state.settings.get(key).cloned())
    }

    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), StorageError> {
        if !self.open {
            return Err(StorageError::NotOpen);
        }
        self.state
            .settings
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn upsert_credential(&mut self, _row: &CredentialRow) -> Result<(), StorageError> {
        Err(StorageError::Database)
    }
    fn get_credential(&self, _id: &str) -> Result<Option<CredentialRow>, StorageError> {
        Err(StorageError::Database)
    }
    fn list_credentials(&self, _include_deleted: bool) -> Result<Vec<CredentialRow>, StorageError> {
        Err(StorageError::Database)
    }
    fn soft_delete_credential(&mut self, _id: &str, _deleted_at: &str) -> Result<(), StorageError> {
        Err(StorageError::Database)
    }
    fn restore_credential(&mut self, _id: &str) -> Result<(), StorageError> {
        Err(StorageError::Database)
    }
    fn insert_history(&mut self, _row: &HistoryRow) -> Result<(), StorageError> {
        Err(StorageError::Database)
    }
    fn list_history(&self, _credential_id: &str) -> Result<Vec<HistoryRow>, StorageError> {
        Err(StorageError::Database)
    }
    fn count_password_fp(&self, _fp: &str, _exclude_id: Option<&str>) -> Result<u32, StorageError> {
        Err(StorageError::Database)
    }
}
