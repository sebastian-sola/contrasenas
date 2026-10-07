//! Shell Tauri — Fase 3: bóveda en disco (create/unlock/lock); sin CRUD.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use vault_backup::{BackupService, StubBackupService};
use vault_core::recovery::{ProductionRecoveryKit, RecoveryKit};
use vault_core::session::SessionState;
use vault_core::{AppPaths, Vault, APP_SCHEMA_VERSION, IMPLEMENTED_PHASE};
use vault_storage::StorageBackendKind;

struct AppState {
    vault: Option<Vault>,
    data_dir: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhaseInfo {
    phase: u8,
    schema_version: u16,
    session_state: &'static str,
    storage_backend: &'static str,
    recovery_summary: String,
    backup_format_version: u16,
    data_dir_hint: String,
    production_crypto: bool,
    vault_exists: bool,
}

fn session_label(state: SessionState) -> &'static str {
    match state {
        SessionState::Locked => "locked",
        SessionState::Unlocked => "unlocked",
    }
}

fn backend_label(kind: StorageBackendKind) -> &'static str {
    match kind {
        StorageBackendKind::SqlCipherAead => "sqlcipher_aead",
        StorageBackendKind::BlobAeadFallback => "blob_aead_fallback",
    }
}

fn default_data_dir() -> PathBuf {
    // En desktop real usaremos path de Tauri; aquí: subcarpeta local de desarrollo.
    std::env::temp_dir().join("contrasenas-dev-data")
}

#[tauri::command]
fn get_phase_info(state: tauri::State<'_, Mutex<AppState>>) -> Result<PhaseInfo, String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    let recovery = ProductionRecoveryKit;
    let backup = StubBackupService;

    if guard.vault.is_none() {
        let paths = AppPaths::from_data_dir(guard.data_dir.clone());
        let mut v = Vault::new(paths);
        if v.exists() {
            let _ = v.open_locked();
        }
        guard.vault = Some(v);
    }

    let vault = guard.vault.as_ref().unwrap();
    let backend = vault.backend().unwrap_or(StorageBackendKind::SqlCipherAead);

    Ok(PhaseInfo {
        phase: IMPLEMENTED_PHASE,
        schema_version: APP_SCHEMA_VERSION,
        session_state: session_label(vault.state()),
        storage_backend: backend_label(backend),
        recovery_summary: recovery.design_summary().to_string(),
        backup_format_version: backup.format_version(),
        data_dir_hint: guard.data_dir.display().to_string(),
        production_crypto: true,
        vault_exists: vault.exists(),
    })
}

#[tauri::command]
fn vault_create(
    state: tauri::State<'_, Mutex<AppState>>,
    master_password: String,
) -> Result<String, String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    if guard.vault.is_none() {
        guard.vault = Some(Vault::new(AppPaths::from_data_dir(guard.data_dir.clone())));
    }
    let vault = guard.vault.as_mut().unwrap();
    let result = vault
        .create(master_password.as_bytes(), true)
        .map_err(|e| e.to_string())?;
    drop(master_password);
    let code = result
        .recovery_code
        .map(|c| c.to_string())
        .unwrap_or_default();
    Ok(code)
}

#[tauri::command]
fn try_unlock(
    state: tauri::State<'_, Mutex<AppState>>,
    master_password: String,
) -> Result<(), String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    if guard.vault.is_none() {
        let mut v = Vault::new(AppPaths::from_data_dir(guard.data_dir.clone()));
        v.open_locked().map_err(|e| e.to_string())?;
        guard.vault = Some(v);
    }
    let vault = guard.vault.as_mut().unwrap();
    if !vault.exists() && vault.header().is_none() {
        vault.open_locked().map_err(|e| e.to_string())?;
    }
    let result = vault.unlock_with_master(master_password.as_bytes());
    drop(master_password);
    result.map_err(|e| e.to_string())
}

#[tauri::command]
fn lock_session(state: tauri::State<'_, Mutex<AppState>>) -> Result<(), String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    if let Some(vault) = guard.vault.as_mut() {
        vault.lock().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Mutex::new(AppState {
            vault: None,
            data_dir: default_data_dir(),
        }))
        .invoke_handler(tauri::generate_handler![
            get_phase_info,
            vault_create,
            try_unlock,
            lock_session
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar Contraseñas");
}
