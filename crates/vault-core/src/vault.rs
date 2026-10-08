//! Bóveda en disco — Fase 3 (create / open / lock / unlock / close).

use crate::crypto::{
    bootstrap_key_material_with_params, derive_db_key, unlock_dek_with_master, CryptoError,
    DataEncryptionKey, KdfParams,
};
use crate::paths::AppPaths;
use crate::recovery::{unlock_dek_with_recovery, RecoveryError};
use crate::session::{SessionError, SessionState, VaultSession};
use crate::vault_header::{HeaderError, VaultFileHeader};
use rand::RngCore;
use std::fs;
use std::time::{Duration, Instant};
use thiserror::Error;
use vault_backup::preventive_copy;
use vault_storage::{ensure_data_dir, open_db_handle, StorageBackendKind, StorageError, VaultDb};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("la bóveda ya existe")]
    AlreadyExists,
    #[error("bóveda no encontrada")]
    NotFound,
    #[error("desbloqueo fallido")]
    UnlockFailed,
    #[error("demasiados intentos; espere {0} s")]
    BackoffActive(u64),
    #[error("la bóveda no está desbloqueada")]
    Locked,
    #[error("la bóveda ya está desbloqueada")]
    AlreadyUnlocked,
    #[error("cabecera inválida")]
    InvalidHeader,
    #[error("almacenamiento no disponible")]
    Storage,
    #[error("integridad de bóveda comprometida")]
    Integrity,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
}

impl From<StorageError> for VaultError {
    fn from(value: StorageError) -> Self {
        match value {
            StorageError::AlreadyExists => VaultError::AlreadyExists,
            StorageError::NotFound
            | StorageError::CredentialNotFound
            | StorageError::PolicyNotFound => VaultError::NotFound,
            StorageError::CorruptOrWrongKey => VaultError::Integrity,
            _ => VaultError::Storage,
        }
    }
}

/// Resultado de crear una bóveda (código de emergencia solo una vez).
pub struct CreateVaultResult {
    pub vault_id: String,
    pub recovery_code: Option<Zeroizing<String>>,
    pub backend: StorageBackendKind,
}

/// Manejador de bóveda en un data dir.
pub struct Vault {
    paths: AppPaths,
    header: Option<VaultFileHeader>,
    session: VaultSession,
    db: Option<Box<dyn VaultDb>>,
    last_activity: Option<Instant>,
    backend_preference: StorageBackendKind,
    /// Params KDF (tests usan `for_tests`).
    kdf_params: KdfParams,
    /// Eventos de auditoría pendientes mientras la DB está cerrada.
    pending_audit: Vec<crate::audit::PendingAudit>,
}

impl Vault {
    pub fn new(paths: AppPaths) -> Self {
        Self::with_backend(paths, StorageBackendKind::SqlCipherAead, KdfParams::v1())
    }

    pub fn with_backend(
        paths: AppPaths,
        backend: StorageBackendKind,
        kdf_params: KdfParams,
    ) -> Self {
        Self {
            paths,
            header: None,
            session: VaultSession::new_locked(),
            db: None,
            last_activity: None,
            backend_preference: backend,
            kdf_params,
            pending_audit: Vec::new(),
        }
    }

    pub(crate) fn db_is_open(&self) -> bool {
        self.db.as_ref().is_some_and(|d| d.is_open())
    }

    pub(crate) fn push_pending_audit(&mut self, event: crate::audit::PendingAudit) {
        if self.pending_audit.len() < 200 {
            self.pending_audit.push(event);
        }
    }

    pub(crate) fn take_pending_audit(&mut self) -> Vec<crate::audit::PendingAudit> {
        std::mem::take(&mut self.pending_audit)
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// Actualiza auto_lock en cabecera + settings DB (Fase 8).
    pub(crate) fn set_auto_lock_secs_persist(&mut self, secs: u64) -> Result<(), VaultError> {
        if let Some(h) = self.header.as_mut() {
            h.auto_lock_secs = secs;
            h.save(&self.paths.vault_header())?;
        }
        Ok(())
    }

    pub fn exists(&self) -> bool {
        self.paths.vault_header().exists() && self.paths.vault_db().exists()
    }

    pub fn state(&self) -> SessionState {
        self.session.state()
    }

    pub fn header(&self) -> Option<&VaultFileHeader> {
        self.header.as_ref()
    }

    pub fn backend(&self) -> Option<StorageBackendKind> {
        self.header.as_ref().map(|h| h.backend)
    }

    /// Crea bóveda nueva. Devuelve código de emergencia si `with_recovery`.
    pub fn create(
        &mut self,
        master_password: &[u8],
        with_recovery: bool,
    ) -> Result<CreateVaultResult, VaultError> {
        if self.exists() {
            return Err(VaultError::AlreadyExists);
        }
        ensure_data_dir(&self.paths.data_dir)?;
        let _ = fs::create_dir_all(self.paths.backups_dir());

        let boot =
            bootstrap_key_material_with_params(master_password, &self.kdf_params, with_recovery)?;
        let vault_id = random_vault_id();
        let mut header =
            VaultFileHeader::new(vault_id.clone(), self.backend_preference, boot.header);
        header.schema_version = crate::vault_header::VAULT_SCHEMA_VERSION;
        header.save(&self.paths.vault_header())?;

        let mut db_key = derive_db_key(&boot.dek)?;
        let mut db = open_db_handle(self.backend_preference, self.paths.vault_db());
        let create_result = db.create(&db_key);
        db_key.zeroize();
        create_result?;
        db.ensure_schema_v1()?;
        db.set_setting("auto_lock_secs", &header.auto_lock_secs.to_string())?;
        // Migración scaffolding: schema ya en v1; hook de backup preventivo listo.
        let _ = preventive_copy(
            &self.paths.vault_header(),
            &self.paths.backups_dir().join("pre-migrate-header.json"),
        );
        let _ = preventive_copy(
            &self.paths.vault_db(),
            &self.paths.backups_dir().join("pre-migrate-vault.dat"),
        );

        db.close();
        // No dejamos la sesión desbloqueada tras create: wipe DEK.
        drop(boot.dek);

        self.header = Some(header);
        self.db = Some(db);
        self.session = VaultSession::new_locked();
        self.last_activity = None;

        Ok(CreateVaultResult {
            vault_id,
            recovery_code: boot.recovery_code,
            backend: self.backend_preference,
        })
    }

    /// Carga cabecera (bóveda bloqueada).
    pub fn open_locked(&mut self) -> Result<(), VaultError> {
        if !self.paths.vault_header().exists() {
            return Err(VaultError::NotFound);
        }
        let header = VaultFileHeader::load(&self.paths.vault_header())?;
        let db = open_db_handle(header.backend, self.paths.vault_db());
        if !db.exists_on_disk() {
            return Err(VaultError::NotFound);
        }
        self.header = Some(header);
        self.db = Some(db);
        self.session = VaultSession::new_locked();
        self.last_activity = None;
        Ok(())
    }

    pub fn unlock_with_master(&mut self, master_password: &[u8]) -> Result<(), VaultError> {
        self.ensure_header_loaded()?;
        if self.session.state() == SessionState::Unlocked {
            return Err(VaultError::AlreadyUnlocked);
        }
        {
            let header = self.header.as_ref().unwrap();
            if let Err(secs) = header.backoff.check_allowed() {
                return Err(VaultError::BackoffActive(secs));
            }
        }

        let header_crypto = self.header.as_ref().unwrap().crypto.clone();
        let dek = match unlock_dek_with_master(master_password, &header_crypto) {
            Ok(d) => d,
            Err(_) => {
                self.register_unlock_failure()?;
                let mut ctx = serde_json::Map::new();
                ctx.insert("attempt".into(), serde_json::Value::String("master".into()));
                let _ = self.audit_record("unlock_failure", "failure", None, ctx);
                return Err(VaultError::UnlockFailed);
            }
        };

        if let Err(e) = self.open_db_with_dek(&dek) {
            // Clave crypto OK pero DB corrupta / wrong derived key → integridad
            drop(dek);
            self.register_unlock_failure()?;
            let mut ctx = serde_json::Map::new();
            ctx.insert("attempt".into(), serde_json::Value::String("master".into()));
            let _ = self.audit_record("unlock_failure", "failure", None, ctx);
            return Err(e);
        }

        // Éxito: reset backoff y sesión
        if let Some(h) = self.header.as_mut() {
            h.backoff.register_success();
            let _ = h.save(&self.paths.vault_header());
        }
        // Meter DEK en sesión
        self.session = VaultSession::new_locked();
        // unlock_with_master de session necesita header — ya tenemos dek
        // usamos API directa:
        self.install_unlocked_session(dek)?;
        self.touch_activity();
        let _ = self.flush_pending_audit();
        let mut ctx = serde_json::Map::new();
        ctx.insert("attempt".into(), serde_json::Value::String("master".into()));
        let _ = self.audit_record("unlock_success", "success", None, ctx);
        Ok(())
    }

    pub fn unlock_with_recovery(&mut self, recovery_code: &str) -> Result<(), VaultError> {
        self.ensure_header_loaded()?;
        if self.session.state() == SessionState::Unlocked {
            return Err(VaultError::AlreadyUnlocked);
        }
        {
            let header = self.header.as_ref().unwrap();
            if let Err(secs) = header.backoff.check_allowed() {
                return Err(VaultError::BackoffActive(secs));
            }
        }
        let crypto = self.header.as_ref().unwrap().crypto.clone();
        let dek = match unlock_dek_with_recovery(recovery_code, &crypto) {
            Ok(d) => d,
            Err(_) => {
                self.register_unlock_failure()?;
                return Err(VaultError::UnlockFailed);
            }
        };
        if let Err(e) = self.open_db_with_dek(&dek) {
            drop(dek);
            self.register_unlock_failure()?;
            return Err(e);
        }
        if let Some(h) = self.header.as_mut() {
            h.backoff.register_success();
            let _ = h.save(&self.paths.vault_header());
        }
        self.install_unlocked_session(dek)?;
        self.touch_activity();
        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), VaultError> {
        if self.session.state() == SessionState::Unlocked && self.db_is_open() {
            let _ = self.audit_record("session_lock", "success", None, serde_json::Map::new());
        }
        if let Some(db) = self.db.as_mut() {
            db.close();
        }
        if self.session.state() == SessionState::Unlocked {
            let _ = self.session.lock();
        } else {
            self.session = VaultSession::new_locked();
        }
        self.last_activity = None;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), VaultError> {
        self.lock()?;
        self.db = None;
        self.header = None;
        Ok(())
    }

    /// Comprueba idle auto-lock (default 5 min). Devuelve true si se bloqueó.
    pub fn tick_auto_lock(&mut self) -> Result<bool, VaultError> {
        if self.session.state() != SessionState::Unlocked {
            return Ok(false);
        }
        let limit = self
            .header
            .as_ref()
            .map(|h| h.auto_lock_secs)
            .unwrap_or(300);
        if limit == 0 {
            return Ok(false); // "nunca"
        }
        let Some(last) = self.last_activity else {
            return Ok(false);
        };
        if last.elapsed() >= Duration::from_secs(limit) {
            let _ = self.audit_record("auto_lock", "success", None, serde_json::Map::new());
            self.lock()?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn touch_activity(&mut self) {
        if self.session.state() == SessionState::Unlocked {
            self.last_activity = Some(Instant::now());
        }
    }

    pub fn dek(&self) -> Option<&DataEncryptionKey> {
        self.session.dek()
    }

    pub(crate) fn db_mut(&mut self) -> Result<&mut (dyn VaultDb + '_), VaultError> {
        match self.db.as_mut() {
            Some(d) => Ok(d.as_mut()),
            None => Err(VaultError::Storage),
        }
    }

    fn ensure_header_loaded(&mut self) -> Result<(), VaultError> {
        if self.header.is_none() {
            self.open_locked()?;
        }
        Ok(())
    }

    fn register_unlock_failure(&mut self) -> Result<(), VaultError> {
        if let Some(h) = self.header.as_mut() {
            h.backoff.register_failure();
            h.save(&self.paths.vault_header())?;
        }
        Ok(())
    }

    fn open_db_with_dek(&mut self, dek: &DataEncryptionKey) -> Result<(), VaultError> {
        let mut db_key = derive_db_key(dek)?;
        if self.db.is_none() {
            let backend = self
                .header
                .as_ref()
                .map(|h| h.backend)
                .unwrap_or(self.backend_preference);
            self.db = Some(open_db_handle(backend, self.paths.vault_db()));
        }
        let db = self.db.as_mut().unwrap();
        if db.is_open() {
            db.close();
        }
        let result = db.open(&db_key);
        db_key.zeroize();
        result?;
        db.ensure_schema_v1()?;
        Ok(())
    }

    fn install_unlocked_session(&mut self, dek: DataEncryptionKey) -> Result<(), VaultError> {
        // Reconstruir sesión desbloqueada sin re-derivar.
        self.session = VaultSession::from_unlocked_dek(dek);
        Ok(())
    }
}

fn random_vault_id() -> String {
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn test_vault(dir: &std::path::Path) -> Vault {
        Vault::with_backend(
            AppPaths::from_data_dir(dir.to_path_buf()),
            StorageBackendKind::SqlCipherAead,
            KdfParams::for_tests(),
        )
    }

    #[test]
    fn create_open_unlock_lock_roundtrip() {
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        let created = v.create(b"master-secret-ok", true).unwrap();
        assert!(created.recovery_code.is_some());
        assert_eq!(v.state(), SessionState::Locked);
        assert!(v.exists());

        let mut v2 = test_vault(dir.path());
        v2.open_locked().unwrap();
        assert_eq!(
            v2.unlock_with_master(b"wrong"),
            Err(VaultError::UnlockFailed)
        );
        v2.unlock_with_master(b"master-secret-ok").unwrap();
        assert_eq!(v2.state(), SessionState::Unlocked);
        assert!(v2.dek().is_some());
        v2.lock().unwrap();
        assert_eq!(v2.state(), SessionState::Locked);
        assert!(v2.dek().is_none());
    }

    #[test]
    fn master_password_not_on_disk_plaintext() {
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        let password = b"unique-master-XYZ-not-on-disk-7942";
        v.create(password, false).unwrap();
        let header_bytes = fs::read(v.paths.vault_header()).unwrap();
        let db_bytes = fs::read(v.paths.vault_db()).unwrap();
        assert!(
            !header_bytes.windows(password.len()).any(|w| w == password),
            "header must not contain master password"
        );
        assert!(
            !db_bytes.windows(password.len()).any(|w| w == password),
            "db must not contain master password"
        );
        // Tampoco como UTF-8 string en header JSON fields obvios
        let header_txt = String::from_utf8_lossy(&header_bytes);
        assert!(!header_txt.contains("unique-master-XYZ-not-on-disk-7942"));
    }

    #[cfg(unix)]
    #[test]
    fn vault_files_have_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        v.create(b"perm-master-ok", false).unwrap();
        let dir_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        let header_mode =
            fs::metadata(v.paths.vault_header()).unwrap().permissions().mode() & 0o777;
        let db_mode = fs::metadata(v.paths.vault_db()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(header_mode, 0o600);
        assert_eq!(db_mode, 0o600);
    }

    #[test]
    fn recovery_unlock_works() {
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        let created = v.create(b"master-a", true).unwrap();
        let code = created.recovery_code.unwrap();
        v.close().unwrap();

        let mut v2 = test_vault(dir.path());
        v2.open_locked().unwrap();
        v2.unlock_with_recovery(&code).unwrap();
        assert_eq!(v2.state(), SessionState::Unlocked);
    }

    #[test]
    fn tampered_header_rejected() {
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        v.create(b"master-b", false).unwrap();
        let path = v.paths.vault_header();
        let mut f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all(br#"{"magic":"BAD"}"#).unwrap();
        let mut v2 = test_vault(dir.path());
        assert!(matches!(
            v2.open_locked(),
            Err(VaultError::Header(_)) | Err(VaultError::InvalidHeader)
        ));
    }

    #[test]
    fn backoff_engages_after_failures() {
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        v.create(b"master-c", false).unwrap();
        let mut v2 = test_vault(dir.path());
        v2.open_locked().unwrap();
        for _ in 0..3 {
            let _ = v2.unlock_with_master(b"nope");
        }
        // Tras 3 fallos, delay 2s — el 4º intento inmediato puede estar en backoff
        // Forzamos failures a 3+ y next_attempt en futuro
        if let Some(h) = v2.header.as_mut() {
            h.backoff.consecutive_failures = 3;
            h.backoff.next_attempt_after_unix_ms =
                Some(crate::backoff::BackoffState::now_unix_ms() + 5_000);
            h.save(&v2.paths.vault_header()).unwrap();
        }
        // Reload
        let mut v3 = test_vault(dir.path());
        v3.open_locked().unwrap();
        assert!(matches!(
            v3.unlock_with_master(b"master-c"),
            Err(VaultError::BackoffActive(_))
        ));
    }

    #[test]
    fn auto_lock_timer() {
        let dir = tempdir().unwrap();
        let mut v = test_vault(dir.path());
        v.create(b"master-d", false).unwrap();
        let mut v2 = test_vault(dir.path());
        v2.open_locked().unwrap();
        if let Some(h) = v2.header.as_mut() {
            h.auto_lock_secs = 1;
            h.save(&v2.paths.vault_header()).unwrap();
        }
        v2.unlock_with_master(b"master-d").unwrap();
        v2.last_activity = Some(Instant::now() - Duration::from_secs(2));
        assert_eq!(v2.tick_auto_lock().unwrap(), true);
        assert_eq!(v2.state(), SessionState::Locked);
    }
}
