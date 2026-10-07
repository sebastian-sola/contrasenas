//! Shell Tauri — Fase 5: bóveda + credenciales + políticas.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use vault_backup::{BackupService, StubBackupService};
use vault_core::credentials::{Credential, CredentialInput, CredentialSummary, HistoryEntry};
use vault_core::policy::{PasswordPolicy, PolicyInput, PolicyValidation};
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
    std::env::temp_dir().join("contrasenas-dev-data")
}

fn with_vault_mut<T>(
    state: &Mutex<AppState>,
    f: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state
        .lock()
        .map_err(|_| "estado interno bloqueado".to_string())?;
    if guard.vault.is_none() {
        let mut v = Vault::new(AppPaths::from_data_dir(guard.data_dir.clone()));
        if v.exists() {
            let _ = v.open_locked();
        }
        guard.vault = Some(v);
    }
    f(guard.vault.as_mut().unwrap())
}

#[tauri::command]
fn get_phase_info(state: tauri::State<'_, Mutex<AppState>>) -> Result<PhaseInfo, String> {
    let recovery = ProductionRecoveryKit;
    let backup = StubBackupService;
    with_vault_mut(&state, |vault| {
        let backend = vault.backend().unwrap_or(StorageBackendKind::SqlCipherAead);
        Ok(PhaseInfo {
            phase: IMPLEMENTED_PHASE,
            schema_version: APP_SCHEMA_VERSION,
            session_state: session_label(vault.state()),
            storage_backend: backend_label(backend),
            recovery_summary: recovery.design_summary().to_string(),
            backup_format_version: backup.format_version(),
            data_dir_hint: "(data-dir)".into(),
            production_crypto: true,
            vault_exists: vault.exists(),
        })
    })
}

#[tauri::command]
fn vault_create(
    state: tauri::State<'_, Mutex<AppState>>,
    master_password: String,
) -> Result<String, String> {
    let result = with_vault_mut(&state, |vault| {
        vault
            .create(master_password.as_bytes(), true)
            .map_err(|e| e.to_string())
    });
    drop(master_password);
    let created = result?;
    Ok(created
        .recovery_code
        .map(|c| c.to_string())
        .unwrap_or_default())
}

#[tauri::command]
fn try_unlock(
    state: tauri::State<'_, Mutex<AppState>>,
    master_password: String,
) -> Result<(), String> {
    let result = with_vault_mut(&state, |vault| {
        if vault.header().is_none() {
            vault.open_locked().map_err(|e| e.to_string())?;
        }
        vault
            .unlock_with_master(master_password.as_bytes())
            .map_err(|e| e.to_string())
    });
    drop(master_password);
    result
}

#[tauri::command]
fn lock_session(state: tauri::State<'_, Mutex<AppState>>) -> Result<(), String> {
    with_vault_mut(&state, |vault| vault.lock().map_err(|e| e.to_string()))
}

#[tauri::command]
fn credentials_list(
    state: tauri::State<'_, Mutex<AppState>>,
    query: Option<String>,
) -> Result<Vec<CredentialSummary>, String> {
    with_vault_mut(&state, |vault| {
        vault
            .list_credentials(query.as_deref())
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn credentials_get(
    state: tauri::State<'_, Mutex<AppState>>,
    id: String,
) -> Result<Credential, String> {
    with_vault_mut(&state, |vault| {
        vault.get_credential(&id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn credentials_create(
    state: tauri::State<'_, Mutex<AppState>>,
    input: CredentialInput,
) -> Result<Credential, String> {
    with_vault_mut(&state, |vault| {
        vault.create_credential(input).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn credentials_update(
    state: tauri::State<'_, Mutex<AppState>>,
    id: String,
    input: CredentialInput,
) -> Result<Credential, String> {
    with_vault_mut(&state, |vault| {
        vault
            .update_credential(&id, input)
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn credentials_delete(state: tauri::State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    with_vault_mut(&state, |vault| {
        vault.delete_credential(&id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn credentials_restore(
    state: tauri::State<'_, Mutex<AppState>>,
    id: String,
) -> Result<Credential, String> {
    with_vault_mut(&state, |vault| {
        vault.restore_credential(&id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn credentials_history(
    state: tauri::State<'_, Mutex<AppState>>,
    id: String,
) -> Result<Vec<HistoryEntry>, String> {
    with_vault_mut(&state, |vault| {
        vault
            .list_credential_history(&id)
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn policies_list(state: tauri::State<'_, Mutex<AppState>>) -> Result<Vec<PasswordPolicy>, String> {
    with_vault_mut(&state, |vault| {
        vault.list_policies().map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn policies_get(
    state: tauri::State<'_, Mutex<AppState>>,
    id: String,
) -> Result<PasswordPolicy, String> {
    with_vault_mut(&state, |vault| {
        vault.get_policy(&id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn policies_create(
    state: tauri::State<'_, Mutex<AppState>>,
    input: PolicyInput,
) -> Result<PasswordPolicy, String> {
    with_vault_mut(&state, |vault| {
        vault.create_policy(input).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn policies_update(
    state: tauri::State<'_, Mutex<AppState>>,
    id: String,
    input: PolicyInput,
) -> Result<PasswordPolicy, String> {
    with_vault_mut(&state, |vault| {
        vault.update_policy(&id, input).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn policies_delete(state: tauri::State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    with_vault_mut(&state, |vault| {
        vault.delete_policy(&id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn policies_validate(
    state: tauri::State<'_, Mutex<AppState>>,
    policy_id: String,
    password: String,
    credential_id: Option<String>,
) -> Result<PolicyValidation, String> {
    let result = with_vault_mut(&state, |vault| {
        vault
            .validate_against_policy(&policy_id, &password, credential_id.as_deref())
            .map_err(|e| e.to_string())
    });
    drop(password);
    result
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
            lock_session,
            credentials_list,
            credentials_get,
            credentials_create,
            credentials_update,
            credentials_delete,
            credentials_restore,
            credentials_history,
            policies_list,
            policies_get,
            policies_create,
            policies_update,
            policies_delete,
            policies_validate
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar Contraseñas");
}
