//! Motor de políticas de contraseñas (Fase 5) — requisito §8.

use crate::vault::VaultError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use vault_storage::{PolicyRow, StorageError};

/// Política configurable por servicio.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicy {
    pub id: String,
    pub name: String,
    pub min_length: u32,
    pub max_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    pub allow_spaces: bool,
    /// Caracteres prohibidos (cada char del string).
    pub forbidden_chars: String,
    /// Patrones prohibidos (subcadenas, case-sensitive).
    pub forbidden_patterns: Vec<String>,
    /// Cuántas contraseñas anteriores no se pueden reutilizar (huellas, sin plaintext).
    pub previous_password_count: u32,
    /// Periodo de caducidad en días (None = sin forzar).
    pub expiry_days: Option<u32>,
    /// Reglas extensibles (JSON libre); hoy: `{"min_unique_chars": N}` opcional.
    pub extra_rules_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Entrada de creación/edición.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyInput {
    pub name: String,
    pub min_length: u32,
    pub max_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    pub allow_spaces: bool,
    pub forbidden_chars: String,
    pub forbidden_patterns: Vec<String>,
    pub previous_password_count: u32,
    pub expiry_days: Option<u32>,
    pub extra_rules_json: Option<String>,
}

/// Resultado de validar una contraseña (sin incluir la contraseña).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyValidation {
    pub compliant: bool,
    /// Códigos estables para tests/UI (p. ej. `min_length`, `require_digit`).
    pub violations: Vec<String>,
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

fn is_symbol(c: char) -> bool {
    !c.is_ascii_alphanumeric() && !c.is_whitespace()
}

/// Valida `password` contra `policy`. `previous_fps` = huellas históricas (más reciente primero).
/// Nunca registra ni devuelve el plaintext.
pub fn validate_password(
    password: &str,
    policy: &PasswordPolicy,
    previous_fps: &[String],
) -> PolicyValidation {
    let mut violations = Vec::new();
    let chars: Vec<char> = password.chars().collect();
    let len = chars.len() as u32;

    if len < policy.min_length {
        violations.push("min_length".into());
    }
    if len > policy.max_length {
        violations.push("max_length".into());
    }
    if policy.require_uppercase && !chars.iter().any(|c| c.is_ascii_uppercase()) {
        violations.push("require_uppercase".into());
    }
    if policy.require_lowercase && !chars.iter().any(|c| c.is_ascii_lowercase()) {
        violations.push("require_lowercase".into());
    }
    if policy.require_digit && !chars.iter().any(|c| c.is_ascii_digit()) {
        violations.push("require_digit".into());
    }
    if policy.require_symbol && !chars.iter().any(|c| is_symbol(*c)) {
        violations.push("require_symbol".into());
    }
    if !policy.allow_spaces && chars.iter().any(|c| c.is_whitespace()) {
        violations.push("spaces_not_allowed".into());
    }
    if !policy.forbidden_chars.is_empty() {
        for fc in policy.forbidden_chars.chars() {
            if chars.contains(&fc) {
                violations.push("forbidden_chars".into());
                break;
            }
        }
    }
    for pat in &policy.forbidden_patterns {
        if !pat.is_empty() && password.contains(pat.as_str()) {
            violations.push("forbidden_patterns".into());
            break;
        }
    }
    if policy.previous_password_count > 0 {
        let fp = password_fingerprint(password);
        let limit = policy.previous_password_count as usize;
        if previous_fps.iter().take(limit).any(|h| h == &fp) {
            violations.push("previous_password_reuse".into());
        }
    }
    if let Some(raw) = &policy.extra_rules_json {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(n) = v.get("min_unique_chars").and_then(|x| x.as_u64()) {
                let mut uniq = chars.clone();
                uniq.sort_unstable();
                uniq.dedup();
                if (uniq.len() as u64) < n {
                    violations.push("min_unique_chars".into());
                }
            }
        }
    }

    PolicyValidation {
        compliant: violations.is_empty(),
        violations,
    }
}

fn row_to_policy(row: PolicyRow) -> PasswordPolicy {
    let patterns: Vec<String> = row
        .forbidden_patterns_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    PasswordPolicy {
        id: row.id,
        name: row.name,
        min_length: row.min_length as u32,
        max_length: row.max_length as u32,
        require_uppercase: row.require_uppercase != 0,
        require_lowercase: row.require_lowercase != 0,
        require_digit: row.require_digit != 0,
        require_symbol: row.require_symbol != 0,
        allow_spaces: row.allow_spaces != 0,
        forbidden_chars: row.forbidden_chars.unwrap_or_default(),
        forbidden_patterns: patterns,
        previous_password_count: row.previous_password_count as u32,
        expiry_days: row.expiry_days.map(|d| d as u32),
        extra_rules_json: row.extra_rules_json,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn policy_to_row(p: &PasswordPolicy) -> PolicyRow {
    PolicyRow {
        id: p.id.clone(),
        name: p.name.clone(),
        min_length: p.min_length as i32,
        max_length: p.max_length as i32,
        require_uppercase: i32::from(p.require_uppercase),
        require_lowercase: i32::from(p.require_lowercase),
        require_digit: i32::from(p.require_digit),
        require_symbol: i32::from(p.require_symbol),
        allow_spaces: i32::from(p.allow_spaces),
        forbidden_chars: if p.forbidden_chars.is_empty() {
            None
        } else {
            Some(p.forbidden_chars.clone())
        },
        forbidden_patterns_json: Some(
            serde_json::to_string(&p.forbidden_patterns).unwrap_or_else(|_| "[]".into()),
        ),
        previous_password_count: p.previous_password_count as i32,
        expiry_days: p.expiry_days.map(|d| d as i32),
        extra_rules_json: p.extra_rules_json.clone(),
        created_at: p.created_at.clone(),
        updated_at: p.updated_at.clone(),
    }
}

impl crate::vault::Vault {
    pub fn list_policies(&mut self) -> Result<Vec<PasswordPolicy>, VaultError> {
        self.ensure_unlocked_for_policy()?;
        let db = self.db_mut()?;
        let rows = db.list_policies()?;
        Ok(rows.into_iter().map(row_to_policy).collect())
    }

    pub fn get_policy(&mut self, id: &str) -> Result<PasswordPolicy, VaultError> {
        self.ensure_unlocked_for_policy()?;
        let db = self.db_mut()?;
        let row = db
            .get_policy(id)?
            .ok_or(VaultError::from(StorageError::PolicyNotFound))?;
        Ok(row_to_policy(row))
    }

    pub fn create_policy(&mut self, input: PolicyInput) -> Result<PasswordPolicy, VaultError> {
        self.ensure_unlocked_for_policy()?;
        if input.name.trim().is_empty() {
            return Err(VaultError::Storage);
        }
        if input.min_length == 0 || input.min_length > input.max_length {
            return Err(VaultError::Storage);
        }
        let now = now_rfc3339();
        let policy = PasswordPolicy {
            id: new_id(),
            name: input.name.trim().to_string(),
            min_length: input.min_length,
            max_length: input.max_length,
            require_uppercase: input.require_uppercase,
            require_lowercase: input.require_lowercase,
            require_digit: input.require_digit,
            require_symbol: input.require_symbol,
            allow_spaces: input.allow_spaces,
            forbidden_chars: input.forbidden_chars,
            forbidden_patterns: input.forbidden_patterns,
            previous_password_count: input.previous_password_count,
            expiry_days: input.expiry_days,
            extra_rules_json: input.extra_rules_json,
            created_at: now.clone(),
            updated_at: now,
        };
        {
            let db = self.db_mut()?;
            db.upsert_policy(&policy_to_row(&policy))?;
        }
        Ok(policy)
    }

    pub fn update_policy(
        &mut self,
        id: &str,
        input: PolicyInput,
    ) -> Result<PasswordPolicy, VaultError> {
        self.ensure_unlocked_for_policy()?;
        if input.name.trim().is_empty()
            || input.min_length == 0
            || input.min_length > input.max_length
        {
            return Err(VaultError::Storage);
        }
        let existing = {
            let db = self.db_mut()?;
            db.get_policy(id)?
                .ok_or(VaultError::from(StorageError::PolicyNotFound))?
        };
        let policy = PasswordPolicy {
            id: id.to_string(),
            name: input.name.trim().to_string(),
            min_length: input.min_length,
            max_length: input.max_length,
            require_uppercase: input.require_uppercase,
            require_lowercase: input.require_lowercase,
            require_digit: input.require_digit,
            require_symbol: input.require_symbol,
            allow_spaces: input.allow_spaces,
            forbidden_chars: input.forbidden_chars,
            forbidden_patterns: input.forbidden_patterns,
            previous_password_count: input.previous_password_count,
            expiry_days: input.expiry_days,
            extra_rules_json: input.extra_rules_json,
            created_at: existing.created_at,
            updated_at: now_rfc3339(),
        };
        {
            let db = self.db_mut()?;
            db.upsert_policy(&policy_to_row(&policy))?;
        }
        Ok(policy)
    }

    pub fn delete_policy(&mut self, id: &str) -> Result<(), VaultError> {
        self.ensure_unlocked_for_policy()?;
        let db = self.db_mut()?;
        db.clear_credential_policy(id)?;
        db.delete_policy(id)?;
        Ok(())
    }

    /// Valida una contraseña contra una política (por id). No registra el secreto.
    pub fn validate_against_policy(
        &mut self,
        policy_id: &str,
        password: &str,
        credential_id: Option<&str>,
    ) -> Result<PolicyValidation, VaultError> {
        self.ensure_unlocked_for_policy()?;
        let policy = self.get_policy(policy_id)?;
        let previous = if policy.previous_password_count > 0 {
            if let Some(cid) = credential_id {
                let db = self.db_mut()?;
                db.list_password_fp_history(cid, policy.previous_password_count)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let result = validate_password(password, &policy, &previous);
        // Asegurar que no dejamos el password en logs (no hay logging aquí).
        let _ = password.len();
        Ok(result)
    }

    fn ensure_unlocked_for_policy(&mut self) -> Result<(), VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(VaultError::Locked);
        }
        self.touch_activity();
        Ok(())
    }
}

/// Aplica caducidad de política si hay `expiry_days` y no hay fecha manual.
pub fn apply_expiry_from_policy(
    next_renewal_at: Option<String>,
    expiry_days: Option<u32>,
) -> Option<String> {
    if next_renewal_at.is_some() {
        return next_renewal_at;
    }
    let days = expiry_days?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some((now + u64::from(days) * 86_400).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::vault::Vault;
    use tempfile::tempdir;

    fn base_policy() -> PasswordPolicy {
        PasswordPolicy {
            id: "p1".into(),
            name: "Estricta".into(),
            min_length: 10,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_symbol: true,
            allow_spaces: false,
            forbidden_chars: "!".into(),
            forbidden_patterns: vec!["password".into()],
            previous_password_count: 2,
            expiry_days: Some(90),
            extra_rules_json: Some(r#"{"min_unique_chars":5}"#.into()),
            created_at: "1".into(),
            updated_at: "1".into(),
        }
    }

    #[test]
    fn all_major_rules_fire() {
        let p = base_policy();
        let short = validate_password("Aa1!", &p, &[]);
        assert!(!short.compliant);
        assert!(short.violations.contains(&"min_length".into()));

        let no_upper = validate_password("abcdefgh1!", &p, &[]);
        assert!(no_upper.violations.contains(&"require_uppercase".into()));

        let no_lower = validate_password("ABCDEFGH1!", &p, &[]);
        assert!(no_lower.violations.contains(&"require_lowercase".into()));

        let mut p2 = p.clone();
        p2.forbidden_chars.clear();
        let no_digit = validate_password("Abcdefgh!!", &p2, &[]);
        assert!(no_digit.violations.contains(&"require_digit".into()));

        let no_sym = validate_password("Abcdefgh12", &p2, &[]);
        assert!(no_sym.violations.contains(&"require_symbol".into()));

        let spaces = validate_password("Abcdefg 1!", &p2, &[]);
        assert!(spaces.violations.contains(&"spaces_not_allowed".into()));

        let forbid_c = validate_password("Abcdefgh1!", &p, &[]);
        assert!(forbid_c.violations.contains(&"forbidden_chars".into()));

        let mut p3 = p2.clone();
        p3.forbidden_patterns = vec!["pass".into()];
        let pat = validate_password("Abpass12#$", &p3, &[]);
        assert!(pat.violations.contains(&"forbidden_patterns".into()));

        let good = "Abcd1234#$";
        let fp = password_fingerprint(good);
        let reuse = validate_password(good, &p3, &[fp.clone(), "other".into()]);
        assert!(reuse.violations.contains(&"previous_password_reuse".into()));

        let uniq = validate_password("Aa1!Aa1!Aa", &p3, &[]);
        assert!(
            uniq.violations.contains(&"min_unique_chars".into()),
            "{:?}",
            uniq.violations
        );

        let ok = validate_password("Xy9#mK2$qp", &p3, &[]);
        assert!(ok.compliant, "{:?}", ok.violations);
    }

    #[test]
    fn validation_result_has_no_password_leak() {
        let p = base_policy();
        let secret = "SuperSecret99!!";
        let v = validate_password(secret, &p, &[]);
        let dump = format!("{v:?}");
        assert!(!dump.contains(secret));
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains(secret));
    }

    #[test]
    fn policy_crud_and_attach_compliance() {
        let dir = tempdir().unwrap();
        let mut v = Vault::new(AppPaths::from_data_dir(dir.path().to_path_buf()));
        v.create(b"master-policy-test-99", false).unwrap();
        // create deja la sesión lista; forzar unlock explícito por si el estado varía
        if v.state() != crate::session::SessionState::Unlocked {
            v.unlock_with_master(b"master-policy-test-99").unwrap();
        }

        let pol = v
            .create_policy(PolicyInput {
                name: "Corp".into(),
                min_length: 8,
                max_length: 32,
                require_uppercase: true,
                require_lowercase: true,
                require_digit: true,
                require_symbol: false,
                allow_spaces: false,
                forbidden_chars: String::new(),
                forbidden_patterns: vec![],
                previous_password_count: 3,
                expiry_days: Some(30),
                extra_rules_json: None,
            })
            .unwrap();

        let bad = v.validate_against_policy(&pol.id, "short", None).unwrap();
        assert!(!bad.compliant);

        let good_pw = "Abcdefg1";
        let ok = v.validate_against_policy(&pol.id, good_pw, None).unwrap();
        assert!(ok.compliant, "{:?}", ok.violations);

        let cred = v
            .create_credential(crate::credentials::CredentialInput {
                service_name: "Mail".into(),
                category: None,
                description: None,
                url: None,
                system_app: None,
                environment: None,
                username: Some("u".into()),
                password: good_pw.into(),
                auth_type: None,
                domain: None,
                email: None,
                notes: None,
                next_renewal_at: None,
                expiry_policy: None,
                policy_id: Some(pol.id.clone()),
                reason: None,
            })
            .unwrap();
        assert_eq!(cred.policy_compliant, Some(true));
        assert!(cred.policy_id.as_deref() == Some(pol.id.as_str()));

        // Reutilizar la misma contraseña viola previous_password_count tras cambio
        let again = v
            .update_credential(
                &cred.id,
                crate::credentials::CredentialInput {
                    service_name: "Mail".into(),
                    category: None,
                    description: None,
                    url: None,
                    system_app: None,
                    environment: None,
                    username: Some("u".into()),
                    password: good_pw.into(),
                    auth_type: None,
                    domain: None,
                    email: None,
                    notes: None,
                    next_renewal_at: None,
                    expiry_policy: None,
                    policy_id: Some(pol.id.clone()),
                    reason: Some("same".into()),
                },
            )
            .unwrap();
        // Same password: previous history gets old fp on change; if password unchanged,
        // we still may mark compliant. Force a change cycle:
        let mid = v
            .update_credential(
                &cred.id,
                crate::credentials::CredentialInput {
                    service_name: "Mail".into(),
                    category: None,
                    description: None,
                    url: None,
                    system_app: None,
                    environment: None,
                    username: Some("u".into()),
                    password: "OtherPw9".into(),
                    auth_type: None,
                    domain: None,
                    email: None,
                    notes: None,
                    next_renewal_at: None,
                    expiry_policy: None,
                    policy_id: Some(pol.id.clone()),
                    reason: None,
                },
            )
            .unwrap();
        assert_eq!(mid.policy_compliant, Some(true));

        let reused = v
            .update_credential(
                &cred.id,
                crate::credentials::CredentialInput {
                    service_name: "Mail".into(),
                    category: None,
                    description: None,
                    url: None,
                    system_app: None,
                    environment: None,
                    username: Some("u".into()),
                    password: good_pw.into(),
                    auth_type: None,
                    domain: None,
                    email: None,
                    notes: None,
                    next_renewal_at: None,
                    expiry_policy: None,
                    policy_id: Some(pol.id.clone()),
                    reason: None,
                },
            )
            .unwrap();
        assert_eq!(reused.policy_compliant, Some(false));
        let _ = again;

        v.delete_policy(&pol.id).unwrap();
        assert!(v.get_policy(&pol.id).is_err());
    }
}
