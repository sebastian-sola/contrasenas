//! Orquestación de backup/restore/export (Fase 8).

use crate::vault::VaultError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use vault_backup::{
    create_cpbak, delete_backup_file, export_plaintext_blocked, import_external_stub,
    read_cpbak_header, restore_cpbak, verify_cpbak, BackupError, BackupFileHeader,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub path: String,
    pub backup_version: u16,
    pub vault_id: String,
    pub created_at: String,
    pub schema_version: u16,
    pub content_hash: String,
}

impl From<BackupError> for VaultError {
    fn from(_: BackupError) -> Self {
        VaultError::Storage
    }
}

fn map_header(path: &Path, h: BackupFileHeader) -> BackupInfo {
    BackupInfo {
        path: path.display().to_string(),
        backup_version: h.backup_version,
        vault_id: h.vault_id,
        created_at: h.created_at,
        schema_version: h.schema_version,
        content_hash: h.content_hash,
    }
}

impl crate::vault::Vault {
    /// Crea `.cpbak` en `dest` (requiere master; no deja secretos en logs).
    pub fn create_backup(
        &mut self,
        dest: &Path,
        master_password: &[u8],
    ) -> Result<BackupInfo, VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(VaultError::Locked);
        }
        self.touch_activity();
        let header_path = self.paths().vault_header();
        let dat_path = self.paths().vault_db();
        let header_json = fs::read_to_string(&header_path).map_err(|_| VaultError::Storage)?;
        let vault_dat = fs::read(&dat_path).map_err(|_| VaultError::Storage)?;
        let vault_id = self
            .header()
            .map(|h| h.vault_id.clone())
            .unwrap_or_else(|| "unknown".into());
        let schema = crate::APP_SCHEMA_VERSION;
        let test_fast = cfg!(test);
        let meta = create_cpbak(
            dest,
            &vault_id,
            schema,
            &header_json,
            &vault_dat,
            master_password,
            test_fast,
        )
        .map_err(|_| VaultError::Storage)?;
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "action".into(),
            serde_json::Value::String("backup_create".into()),
        );
        let _ = self.audit_record("backup_create", "success", None, ctx);
        Ok(map_header(dest, meta))
    }

    pub fn verify_backup(
        &mut self,
        path: &Path,
        master_password: &[u8],
    ) -> Result<BackupInfo, VaultError> {
        let meta = verify_cpbak(path, master_password).map_err(|e| match e {
            BackupError::Integrity | BackupError::Corrupt => VaultError::Integrity,
            _ => VaultError::Storage,
        })?;
        Ok(map_header(path, meta))
    }

    pub fn restore_backup(
        &mut self,
        path: &Path,
        master_password: &[u8],
        confirm_overwrite: bool,
    ) -> Result<BackupInfo, VaultError> {
        // Lock first so files are not open
        let _ = self.lock();
        let dest_h = self.paths().vault_header();
        let dest_d = self.paths().vault_db();
        let prev = self.paths().backups_dir();
        let meta = restore_cpbak(
            path,
            master_password,
            &dest_h,
            &dest_d,
            &prev,
            confirm_overwrite,
        )
        .map_err(|e| match e {
            BackupError::DestinationExists => VaultError::AlreadyExists,
            BackupError::Integrity | BackupError::Corrupt => VaultError::Integrity,
            _ => VaultError::Storage,
        })?;
        // Re-open locked
        let _ = self.open_locked();
        // Pending audit until unlock
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "action".into(),
            serde_json::Value::String("backup_restore".into()),
        );
        let _ = self.audit_record("backup_restore", "success", None, ctx);
        Ok(map_header(path, meta))
    }

    pub fn list_local_backups(&self) -> Result<Vec<BackupInfo>, VaultError> {
        let dir = self.paths().backups_dir();
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        let entries = fs::read_dir(&dir).map_err(|_| VaultError::Storage)?;
        for ent in entries.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) == Some("cpbak") {
                if let Ok(h) = read_cpbak_header(&p) {
                    out.push(map_header(&p, h));
                }
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn delete_local_backup(&mut self, path: &Path, confirmed: bool) -> Result<(), VaultError> {
        delete_backup_file(path, confirmed).map_err(|_| VaultError::Storage)?;
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "action".into(),
            serde_json::Value::String("backup_delete".into()),
        );
        let _ = self.audit_record("backup_delete", "success", None, ctx);
        Ok(())
    }

    pub fn default_backup_path(&self) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.paths()
            .backups_dir()
            .join(format!("manual-{stamp}.cpbak"))
    }

    pub fn export_plaintext(&self) -> Result<(), VaultError> {
        export_plaintext_blocked().map_err(|_| VaultError::Storage)
    }

    pub fn import_external(&mut self, confirmed: bool) -> Result<(), VaultError> {
        import_external_stub(confirmed).map_err(|e| match e {
            BackupError::ImportNeedsConfirmation => VaultError::Storage,
            BackupError::ImportNotAvailable => VaultError::Storage,
            _ => VaultError::Storage,
        })?;
        Ok(())
    }

    pub fn record_clipboard_copy(&mut self, field: &str) -> Result<(), VaultError> {
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "field".into(),
            serde_json::Value::String(field.to_string()),
        );
        self.audit_record("clipboard_copy", "success", None, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{contains_any_secret, redact_secrets};
    use crate::paths::AppPaths;
    use crate::vault::Vault;
    use tempfile::tempdir;

    #[test]
    fn backup_roundtrip_via_vault() {
        let dir = tempdir().unwrap();
        let mut v = Vault::new(AppPaths::from_data_dir(dir.path().to_path_buf()));
        let master = b"Fase8-Backup-Master!!";
        v.create(master, false).unwrap();
        v.unlock_with_master(master).unwrap();

        let bak = v.default_backup_path();
        let info = v.create_backup(&bak, master).unwrap();
        assert_eq!(info.backup_version, 1);
        assert!(!contains_any_secret(
            &format!("{info:?}"),
            &[std::str::from_utf8(master).unwrap()]
        ));

        let verified = v.verify_backup(&bak, master).unwrap();
        assert_eq!(verified.content_hash, info.content_hash);

        // Restore into fresh dir
        let dir2 = tempdir().unwrap();
        let mut v2 = Vault::new(AppPaths::from_data_dir(dir2.path().to_path_buf()));
        // copy bak path still valid
        v2.restore_backup(&bak, master, false).unwrap();
        v2.unlock_with_master(master).unwrap();
        assert!(v2.exists());
    }

    #[test]
    fn plaintext_export_blocked() {
        let dir = tempdir().unwrap();
        let v = Vault::new(AppPaths::from_data_dir(dir.path().to_path_buf()));
        assert!(v.export_plaintext().is_err());
    }

    #[test]
    fn secrets_not_in_log_helpers() {
        let s = "ClipboardPasswordValueXYZ";
        let line = format!("copied {s}");
        assert!(contains_any_secret(&line, &[s]));
        assert!(!contains_any_secret(&redact_secrets(&line, &[s]), &[s]));
    }
}
