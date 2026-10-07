//! CRUD de credenciales (Fase 4) — secretos con AEAD; historial solo metadatos.

use crate::crypto::{decrypt, encrypt, AeadBox, CryptoError, DataEncryptionKey};
use crate::vault::VaultError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use vault_storage::{CredentialRow, HistoryRow, StorageError};

const AAD_PASSWORD: &[u8] = b"contrasenas/v1/field/password";
const AAD_NOTES: &[u8] = b"contrasenas/v1/field/notes";

/// Entrada de credencial en claro (solo con bóveda desbloqueada).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub id: String,
    pub service_name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub system_app: Option<String>,
    pub environment: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub auth_type: Option<String>,
    pub domain: Option<String>,
    pub email: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub password_changed_at: Option<String>,
    pub next_renewal_at: Option<String>,
    pub expiry_policy: Option<String>,
    pub status: String,
    pub strength_score: Option<i32>,
    pub policy_compliant: Option<bool>,
    pub policy_id: Option<String>,
    pub deleted: bool,
    /// Cuántos servicios usan la misma contraseña (sin listar cuáles).
    pub reuse_count: u32,
    /// Color de caducidad: green | yellow | orange | red | none
    pub expiry_color: String,
}

/// Resumen para lista (sin contraseña ni notas).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSummary {
    pub id: String,
    pub service_name: String,
    pub username: Option<String>,
    pub category: Option<String>,
    pub environment: Option<String>,
    pub status: String,
    pub expiry_color: String,
    pub next_renewal_at: Option<String>,
    pub reuse_count: u32,
    pub policy_id: Option<String>,
    pub policy_compliant: Option<bool>,
}

/// Datos de creación/edición desde la UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInput {
    pub service_name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub system_app: Option<String>,
    pub environment: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub auth_type: Option<String>,
    pub domain: Option<String>,
    pub email: Option<String>,
    pub notes: Option<String>,
    pub next_renewal_at: Option<String>,
    pub expiry_policy: Option<String>,
    pub policy_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: String,
    pub credential_id: String,
    pub timestamp: String,
    pub actor: Option<String>,
    pub action: String,
    pub fields_changed: Vec<String>,
    pub reason: Option<String>,
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Timestamp ISO-ish simple (suficiente para ordenación local).
    format!("{secs}")
}

fn new_id() -> String {
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn password_fingerprint(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Caducidad visual §12: Verde >30d; Amarillo ≤30; Naranja ≤7; Rojo caducada.
pub fn expiry_color(next_renewal_at: Option<&str>, now_secs: u64) -> String {
    let Some(raw) = next_renewal_at else {
        return "none".into();
    };
    let Ok(due) = raw.parse::<u64>() else {
        return "none".into();
    };
    if due < now_secs {
        return "red".into();
    }
    let days = (due - now_secs) / 86_400;
    if days <= 7 {
        "orange".into()
    } else if days <= 30 {
        "yellow".into()
    } else {
        "green".into()
    }
}

fn compute_status(next_renewal_at: Option<&str>, deleted: bool) -> String {
    if deleted {
        return "Archivada".into();
    }
    match expiry_color(next_renewal_at, now_unix()).as_str() {
        "red" => "Caducada".into(),
        "orange" | "yellow" => "Próxima a caducar".into(),
        _ => "Activa".into(),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn encrypt_field(
    dek: &DataEncryptionKey,
    plaintext: &str,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Ok(encrypt(dek, plaintext.as_bytes(), aad)?.bytes)
}

fn decrypt_field(dek: &DataEncryptionKey, bytes: &[u8], aad: &[u8]) -> Result<String, CryptoError> {
    let plain = decrypt(
        dek,
        &AeadBox {
            bytes: bytes.to_vec(),
        },
        aad,
    )?;
    String::from_utf8(plain).map_err(|_| CryptoError::CorruptData)
}

impl crate::vault::Vault {
    fn ensure_unlocked(&mut self) -> Result<DataEncryptionKey, VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(VaultError::Locked);
        }
        self.touch_activity();
        self.dek().cloned().ok_or(VaultError::Locked)
    }

    pub fn list_credentials(
        &mut self,
        query: Option<&str>,
    ) -> Result<Vec<CredentialSummary>, VaultError> {
        let _dek = self.ensure_unlocked()?;
        let db = self.db_mut()?;
        let rows = db.list_credentials(false)?;
        let q = query.map(|s| s.to_lowercase()).unwrap_or_default();
        let mut out = Vec::new();
        for row in rows {
            if !q.is_empty() {
                let hay = format!(
                    "{} {} {} {} {}",
                    row.service_name,
                    row.username.clone().unwrap_or_default(),
                    row.category.clone().unwrap_or_default(),
                    row.url.clone().unwrap_or_default(),
                    row.environment.clone().unwrap_or_default()
                )
                .to_lowercase();
                if !hay.contains(&q) {
                    continue;
                }
            }
            let reuse = match &row.password_fp {
                Some(fp) => db.count_password_fp(fp, None)?,
                None => 1,
            };
            let color = expiry_color(row.next_renewal_at.as_deref(), now_unix());
            let status = row
                .status
                .clone()
                .unwrap_or_else(|| compute_status(row.next_renewal_at.as_deref(), false));
            out.push(CredentialSummary {
                id: row.id,
                service_name: row.service_name,
                username: row.username,
                category: row.category,
                environment: row.environment,
                status,
                expiry_color: color,
                next_renewal_at: row.next_renewal_at,
                reuse_count: if reuse > 1 { reuse } else { 0 },
                policy_id: row.policy_id,
                policy_compliant: row.policy_compliant.map(|v| v != 0),
            });
        }
        Ok(out)
    }

    pub fn get_credential(&mut self, id: &str) -> Result<Credential, VaultError> {
        let dek = self.ensure_unlocked()?;
        let row = {
            let db = self.db_mut()?;
            db.get_credential(id)?
                .ok_or(VaultError::from(StorageError::CredentialNotFound))?
        };
        let password = decrypt_field(&dek, &row.password_ciphertext, AAD_PASSWORD)?;
        let notes = match &row.notes_ciphertext {
            Some(b) if !b.is_empty() => Some(decrypt_field(&dek, b, AAD_NOTES)?),
            _ => None,
        };
        let reuse = {
            let db = self.db_mut()?;
            match &row.password_fp {
                Some(fp) => db.count_password_fp(fp, None)?,
                None => 1,
            }
        };
        Ok(row_to_credential(row, password, notes, reuse))
    }

    pub fn create_credential(&mut self, input: CredentialInput) -> Result<Credential, VaultError> {
        if input.service_name.trim().is_empty() {
            return Err(VaultError::Storage);
        }
        let id = new_id();
        let now = now_rfc3339();
        let dek = self.ensure_unlocked()?;
        let pw_ct = encrypt_field(&dek, &input.password, AAD_PASSWORD)?;
        let notes_ct = match &input.notes {
            Some(n) if !n.is_empty() => Some(encrypt_field(&dek, n, AAD_NOTES)?),
            _ => None,
        };
        let fp = password_fingerprint(&input.password);
        let (compliant, next_renewal) = self.eval_policy_for_save(
            input.policy_id.as_deref(),
            &input.password,
            None,
            input.next_renewal_at.clone(),
        )?;
        let status = compute_status(next_renewal.as_deref(), false);
        let row = CredentialRow {
            id: id.clone(),
            service_name: input.service_name.clone(),
            category: input.category.clone(),
            description: input.description.clone(),
            url: input.url.clone(),
            system_app: input.system_app.clone(),
            environment: input.environment.clone(),
            username: input.username.clone(),
            password_ciphertext: pw_ct,
            auth_type: input.auth_type.clone(),
            domain: input.domain.clone(),
            email: input.email.clone(),
            notes_ciphertext: notes_ct,
            created_at: now.clone(),
            updated_at: now.clone(),
            password_changed_at: Some(now.clone()),
            next_renewal_at: next_renewal,
            expiry_policy: input.expiry_policy.clone(),
            status: Some(status),
            strength_score: None,
            policy_compliant: compliant.map(i32::from),
            password_fp: Some(fp),
            deleted_at: None,
            policy_id: input.policy_id.clone(),
        };
        {
            let db = self.db_mut()?;
            db.upsert_credential(&row)?;
            db.insert_history(&HistoryRow {
                id: new_id(),
                credential_id: id.clone(),
                timestamp: now,
                actor: Some("local".into()),
                action: "create".into(),
                fields_changed: Some(r#"["service_name","password"]"#.into()),
                reason: input.reason.clone(),
            })?;
        }
        self.get_credential(&id)
    }

    pub fn update_credential(
        &mut self,
        id: &str,
        input: CredentialInput,
    ) -> Result<Credential, VaultError> {
        let dek = self.ensure_unlocked()?;
        let existing = {
            let db = self.db_mut()?;
            db.get_credential(id)?
                .ok_or(VaultError::from(StorageError::CredentialNotFound))?
        };
        if existing.deleted_at.is_some() {
            return Err(VaultError::from(StorageError::CredentialNotFound));
        }
        let now = now_rfc3339();
        let old_pw = decrypt_field(&dek, &existing.password_ciphertext, AAD_PASSWORD)?;
        let pw_changed = old_pw != input.password;
        let pw_ct = encrypt_field(&dek, &input.password, AAD_PASSWORD)?;
        let notes_ct = match &input.notes {
            Some(n) if !n.is_empty() => Some(encrypt_field(&dek, n, AAD_NOTES)?),
            _ => None,
        };
        let fp = password_fingerprint(&input.password);
        if pw_changed {
            if let Some(old_fp) = &existing.password_fp {
                let db = self.db_mut()?;
                db.insert_password_fp_history(&new_id(), id, old_fp, &now)?;
            }
        }
        let (compliant, next_renewal) = self.eval_policy_for_save(
            input.policy_id.as_deref(),
            &input.password,
            Some(id),
            input.next_renewal_at.clone(),
        )?;
        let status = compute_status(next_renewal.as_deref(), false);
        let mut fields: Vec<String> = vec!["service_name".into()];
        if pw_changed {
            fields.push("password".into());
        }
        let row = CredentialRow {
            id: id.to_string(),
            service_name: input.service_name,
            category: input.category,
            description: input.description,
            url: input.url,
            system_app: input.system_app,
            environment: input.environment,
            username: input.username,
            password_ciphertext: pw_ct,
            auth_type: input.auth_type,
            domain: input.domain,
            email: input.email,
            notes_ciphertext: notes_ct,
            created_at: existing.created_at,
            updated_at: now.clone(),
            password_changed_at: if pw_changed {
                Some(now.clone())
            } else {
                existing.password_changed_at
            },
            next_renewal_at: next_renewal,
            expiry_policy: input.expiry_policy,
            status: Some(status),
            strength_score: existing.strength_score,
            policy_compliant: compliant.map(i32::from),
            password_fp: Some(fp),
            deleted_at: None,
            policy_id: input.policy_id,
        };
        {
            let db = self.db_mut()?;
            db.upsert_credential(&row)?;
            db.insert_history(&HistoryRow {
                id: new_id(),
                credential_id: id.to_string(),
                timestamp: now,
                actor: Some("local".into()),
                action: "update".into(),
                fields_changed: Some(
                    serde_json::to_string(&fields).unwrap_or_else(|_| "[]".into()),
                ),
                reason: input.reason,
            })?;
        }
        drop(old_pw);
        self.get_credential(id)
    }

    fn eval_policy_for_save(
        &mut self,
        policy_id: Option<&str>,
        password: &str,
        credential_id: Option<&str>,
        next_renewal_at: Option<String>,
    ) -> Result<(Option<bool>, Option<String>), VaultError> {
        let Some(pid) = policy_id else {
            return Ok((None, next_renewal_at));
        };
        let validation = self.validate_against_policy(pid, password, credential_id)?;
        let policy = self.get_policy(pid)?;
        let renewal = crate::policy::apply_expiry_from_policy(next_renewal_at, policy.expiry_days);
        Ok((Some(validation.compliant), renewal))
    }

    pub fn delete_credential(&mut self, id: &str) -> Result<(), VaultError> {
        let now = now_rfc3339();
        let _dek = self.ensure_unlocked()?;
        let db = self.db_mut()?;
        db.soft_delete_credential(id, &now)?;
        db.insert_history(&HistoryRow {
            id: new_id(),
            credential_id: id.to_string(),
            timestamp: now,
            actor: Some("local".into()),
            action: "delete".into(),
            fields_changed: None,
            reason: None,
        })?;
        Ok(())
    }

    pub fn restore_credential(&mut self, id: &str) -> Result<Credential, VaultError> {
        let _dek = self.ensure_unlocked()?;
        {
            let db = self.db_mut()?;
            db.restore_credential(id)?;
            let now = now_rfc3339();
            db.insert_history(&HistoryRow {
                id: new_id(),
                credential_id: id.to_string(),
                timestamp: now,
                actor: Some("local".into()),
                action: "restore".into(),
                fields_changed: None,
                reason: None,
            })?;
        }
        self.get_credential(id)
    }

    pub fn list_credential_history(&mut self, id: &str) -> Result<Vec<HistoryEntry>, VaultError> {
        let _dek = self.ensure_unlocked()?;
        let db = self.db_mut()?;
        let rows = db.list_history(id)?;
        Ok(rows
            .into_iter()
            .map(|r| HistoryEntry {
                id: r.id,
                credential_id: r.credential_id,
                timestamp: r.timestamp,
                actor: r.actor,
                action: r.action,
                fields_changed: r
                    .fields_changed
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                    .unwrap_or_default(),
                reason: r.reason,
            })
            .collect())
    }
}

fn row_to_credential(
    row: CredentialRow,
    password: String,
    notes: Option<String>,
    reuse_total: u32,
) -> Credential {
    let deleted = row.deleted_at.is_some();
    let color = expiry_color(row.next_renewal_at.as_deref(), now_unix());
    let status = row
        .status
        .unwrap_or_else(|| compute_status(row.next_renewal_at.as_deref(), deleted));
    Credential {
        id: row.id,
        service_name: row.service_name,
        category: row.category,
        description: row.description,
        url: row.url,
        system_app: row.system_app,
        environment: row.environment,
        username: row.username,
        password,
        auth_type: row.auth_type,
        domain: row.domain,
        email: row.email,
        notes,
        created_at: row.created_at,
        updated_at: row.updated_at,
        password_changed_at: row.password_changed_at,
        next_renewal_at: row.next_renewal_at,
        expiry_policy: row.expiry_policy,
        status,
        strength_score: row.strength_score,
        policy_compliant: row.policy_compliant.map(|v| v != 0),
        policy_id: row.policy_id,
        deleted,
        reuse_count: if reuse_total > 1 { reuse_total } else { 0 },
        expiry_color: color,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::vault::Vault;
    use crate::KdfParams;
    use std::fs;
    use tempfile::tempdir;
    use vault_storage::StorageBackendKind;

    fn unlocked_vault(dir: &std::path::Path) -> Vault {
        let mut v = Vault::with_backend(
            AppPaths::from_data_dir(dir.to_path_buf()),
            StorageBackendKind::SqlCipherAead,
            KdfParams::for_tests(),
        );
        v.create(b"cred-master", false).unwrap();
        let mut v2 = Vault::with_backend(
            AppPaths::from_data_dir(dir.to_path_buf()),
            StorageBackendKind::SqlCipherAead,
            KdfParams::for_tests(),
        );
        v2.open_locked().unwrap();
        v2.unlock_with_master(b"cred-master").unwrap();
        v2
    }

    #[test]
    fn crud_reuse_and_no_plaintext_on_disk() {
        let dir = tempdir().unwrap();
        let mut v = unlocked_vault(dir.path());
        let secret = "SuperSecret-SitePass-998877";
        let c1 = v
            .create_credential(CredentialInput {
                service_name: "Banco Demo".into(),
                category: Some("finanzas".into()),
                description: None,
                url: Some("https://banco.example".into()),
                system_app: None,
                environment: Some("Producción".into()),
                username: Some("seb".into()),
                password: secret.into(),
                auth_type: Some("password".into()),
                domain: None,
                email: None,
                notes: Some("nota privada".into()),
                next_renewal_at: Some((now_unix() + 40 * 86400).to_string()),
                expiry_policy: Some("90d".into()),
                policy_id: None,
                reason: Some("alta inicial".into()),
            })
            .unwrap();
        assert_eq!(c1.expiry_color, "green");
        assert_eq!(c1.reuse_count, 0);

        let c2 = v
            .create_credential(CredentialInput {
                service_name: "Correo Demo".into(),
                category: None,
                description: None,
                url: None,
                system_app: None,
                environment: Some("Producción".into()),
                username: Some("seb".into()),
                password: secret.into(),
                auth_type: None,
                domain: None,
                email: None,
                notes: None,
                next_renewal_at: Some((now_unix() + 5 * 86400).to_string()),
                expiry_policy: None,
                policy_id: None,
                reason: None,
            })
            .unwrap();
        assert_eq!(c2.expiry_color, "orange");
        assert!(c2.reuse_count >= 2);

        let list = v.list_credentials(Some("banco")).unwrap();
        assert_eq!(list.len(), 1);
        assert!(!format!("{:?}", list[0]).contains(secret));

        let got = v.get_credential(&c1.id).unwrap();
        assert_eq!(got.password, secret);
        assert!(got.reuse_count >= 2);

        v.update_credential(
            &c1.id,
            CredentialInput {
                service_name: "Banco Demo".into(),
                category: Some("finanzas".into()),
                description: None,
                url: None,
                system_app: None,
                environment: Some("Producción".into()),
                username: Some("seb".into()),
                password: "OtraClaveDistinta-112233".into(),
                auth_type: None,
                domain: None,
                email: None,
                notes: None,
                next_renewal_at: None,
                expiry_policy: None,
                policy_id: None,
                reason: Some("rotación".into()),
            },
        )
        .unwrap();
        let hist = v.list_credential_history(&c1.id).unwrap();
        assert!(hist.iter().any(|h| h.action == "update"));
        assert!(!format!("{hist:?}").contains(secret));

        v.delete_credential(&c2.id).unwrap();
        assert_eq!(v.list_credentials(None).unwrap().len(), 1);
        v.restore_credential(&c2.id).unwrap();
        assert_eq!(v.list_credentials(None).unwrap().len(), 2);

        v.lock().unwrap();
        let db_bytes = fs::read(dir.path().join("vault.dat")).unwrap();
        assert!(!db_bytes
            .windows(secret.len())
            .any(|w| w == secret.as_bytes()));
    }

    #[test]
    fn expiry_thresholds() {
        let now = 1_700_000_000u64;
        assert_eq!(expiry_color(None, now), "none");
        assert_eq!(expiry_color(Some(&(now - 10).to_string()), now), "red");
        assert_eq!(
            expiry_color(Some(&(now + 3 * 86400).to_string()), now),
            "orange"
        );
        assert_eq!(
            expiry_color(Some(&(now + 20 * 86400).to_string()), now),
            "yellow"
        );
        assert_eq!(
            expiry_color(Some(&(now + 60 * 86400).to_string()), now),
            "green"
        );
    }
}
