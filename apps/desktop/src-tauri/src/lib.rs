//! Shell Tauri — Fase 2: crypto en crates; sin persistencia de bóveda.

use serde::Serialize;
use vault_backup::{BackupService, StubBackupService};
use vault_core::recovery::{ProductionRecoveryKit, RecoveryKit};
use vault_core::session::{SessionState, VaultSession};
use vault_core::{AppPaths, APP_SCHEMA_VERSION, IMPLEMENTED_PHASE};
use vault_storage::{StorageBackendKind, StubVaultStore, VaultStore};

use std::sync::Mutex;

struct AppState {
    session: VaultSession,
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

#[tauri::command]
fn get_phase_info(state: tauri::State<'_, Mutex<AppState>>) -> Result<PhaseInfo, String> {
    let guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    let store = StubVaultStore::preferred_sqlcipher();
    let recovery = ProductionRecoveryKit;
    let backup = StubBackupService;
    let paths = AppPaths::from_data_dir(std::path::PathBuf::from("(data-dir-del-SO)"));

    Ok(PhaseInfo {
        phase: IMPLEMENTED_PHASE,
        schema_version: APP_SCHEMA_VERSION,
        session_state: session_label(guard.session.state()),
        storage_backend: backend_label(store.backend_kind()),
        recovery_summary: recovery.design_summary().to_string(),
        backup_format_version: backup.format_version(),
        data_dir_hint: paths.data_dir.display().to_string(),
        production_crypto: true,
    })
}

/// Sin cabecera persistida (Fase 3): el desbloqueo de UI sigue siendo stub.
#[tauri::command]
fn try_unlock(
    state: tauri::State<'_, Mutex<AppState>>,
    master_password: String,
) -> Result<(), String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    let result = guard.session.try_unlock_stub(&master_password);
    drop(master_password);
    result.map_err(|e| e.to_string())
}

#[tauri::command]
fn lock_session(state: tauri::State<'_, Mutex<AppState>>) -> Result<(), String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    match guard.session.lock() {
        Ok(()) | Err(vault_core::session::SessionError::AlreadyLocked) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Mutex::new(AppState {
            session: VaultSession::new_locked(),
        }))
        .invoke_handler(tauri::generate_handler![
            get_phase_info,
            try_unlock,
            lock_session
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar Contraseñas");
}
