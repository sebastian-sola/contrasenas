//! Auditoría independiente cifrada (Fase 7) — §7 / AUDIT.md MVP opción A.

use crate::vault::VaultError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vault_storage::AuditRow;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("contexto de auditoría contiene claves no permitidas")]
    ForbiddenContextKey,
    #[error("auditoría no disponible")]
    Unavailable,
}

/// Claves permitidas en `context` (nunca secretos).
pub const CONTEXT_ALLOWLIST: &[&str] = &[
    "fields_changed",
    "reason_present",
    "field",
    "policy_id",
    "attempt",
    "source",
    "action",
    "schema_version",
    "backend",
    "length",
    "strength_label",
    "rng",
];

/// Evento de auditoría (sin secretos).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub sequence: i64,
    pub timestamp: String,
    pub event_type: String,
    pub local_user_id: String,
    pub object_id: Option<String>,
    pub result: String,
    pub context: Map<String, Value>,
    pub prev_hash: Option<String>,
}

/// Filtros de consulta UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilter {
    pub event_type: Option<String>,
    pub object_id: Option<String>,
    pub local_user_id: Option<String>,
    pub result: Option<String>,
    pub since_ts: Option<String>,
    pub until_ts: Option<String>,
    pub limit: Option<u32>,
}

/// Borrador encolado mientras la bóveda está bloqueada (p. ej. unlock_failure).
#[derive(Debug, Clone)]
pub struct PendingAudit {
    pub event_type: String,
    pub result: String,
    pub object_id: Option<String>,
    pub context: Map<String, Value>,
}

fn now_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

fn new_id() -> String {
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// Valida allowlist; rechaza claves desconocidas.
pub fn sanitize_context(raw: Map<String, Value>) -> Result<Map<String, Value>, AuditError> {
    let mut out = Map::new();
    for (k, v) in raw {
        if !CONTEXT_ALLOWLIST.contains(&k.as_str()) {
            return Err(AuditError::ForbiddenContextKey);
        }
        // Nunca permitir strings enormes que podrían ser secrets pegados
        if let Value::String(s) = &v {
            if s.len() > 200 {
                return Err(AuditError::ForbiddenContextKey);
            }
        }
        out.insert(k, v);
    }
    Ok(out)
}

fn ctx_json(ctx: &Map<String, Value>) -> Option<String> {
    if ctx.is_empty() {
        None
    } else {
        Some(serde_json::to_string(ctx).unwrap_or_else(|_| "{}".into()))
    }
}

fn row_to_event(row: AuditRow) -> AuditEvent {
    let context = row
        .context_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<Map<String, Value>>(s).ok())
        .unwrap_or_default();
    AuditEvent {
        id: row.id,
        sequence: row.sequence,
        timestamp: row.timestamp,
        event_type: row.event_type,
        local_user_id: row.local_user_id,
        object_id: row.object_id,
        result: row.result,
        context,
        prev_hash: row.prev_hash,
    }
}

/// Hash de evento para schema opción B (MVP no verifica cadena).
fn event_content_hash(
    sequence: i64,
    timestamp: &str,
    event_type: &str,
    result: &str,
    object_id: Option<&str>,
    context_json: Option<&str>,
    prev_hash: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sequence.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.as_bytes());
    hasher.update(b"|");
    hasher.update(event_type.as_bytes());
    hasher.update(b"|");
    hasher.update(result.as_bytes());
    hasher.update(b"|");
    hasher.update(object_id.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(context_json.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(prev_hash.unwrap_or("").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Stub legacy (compat tests Fase 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventStub {
    pub kind: &'static str,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEventStub) -> Result<(), AuditError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _event: AuditEventStub) -> Result<(), AuditError> {
        Ok(())
    }
}

impl crate::vault::Vault {
    /// Encola evento si está bloqueada; escribe si está abierta.
    pub fn audit_record(
        &mut self,
        event_type: &str,
        result: &str,
        object_id: Option<&str>,
        context: Map<String, Value>,
    ) -> Result<(), VaultError> {
        let context = sanitize_context(context).map_err(|_| VaultError::Storage)?;
        if self.state() != crate::session::SessionState::Unlocked || !self.db_is_open() {
            self.push_pending_audit(PendingAudit {
                event_type: event_type.into(),
                result: result.into(),
                object_id: object_id.map(|s| s.to_string()),
                context,
            });
            return Ok(());
        }
        self.write_audit_now(event_type, result, object_id, context)
    }

    fn write_audit_now(
        &mut self,
        event_type: &str,
        result: &str,
        object_id: Option<&str>,
        context: Map<String, Value>,
    ) -> Result<(), VaultError> {
        let db = self.db_mut()?;
        let sequence = db.next_audit_sequence()?;
        // prev_hash: schema listo; MVP deja NULL (opción A). Columna existe para D6-B.
        let prev_hash: Option<String> = None;
        let id = new_id();
        let timestamp = now_ts();
        let context_json = ctx_json(&context);
        // Calculamos hash de contenido por si se activa cadena más adelante (no se guarda aún como prev).
        let _ready_hash = event_content_hash(
            sequence,
            &timestamp,
            event_type,
            result,
            object_id,
            context_json.as_deref(),
            prev_hash.as_deref(),
        );
        db.insert_audit(&AuditRow {
            id,
            sequence,
            timestamp,
            event_type: event_type.into(),
            local_user_id: "local".into(),
            object_id: object_id.map(|s| s.to_string()),
            result: result.into(),
            context_json,
            prev_hash,
        })?;
        Ok(())
    }

    pub fn flush_pending_audit(&mut self) -> Result<(), VaultError> {
        let pending = self.take_pending_audit();
        for p in pending {
            self.write_audit_now(&p.event_type, &p.result, p.object_id.as_deref(), p.context)?;
        }
        Ok(())
    }

    pub fn list_audit(&mut self, filter: AuditFilter) -> Result<Vec<AuditEvent>, VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(VaultError::Locked);
        }
        self.touch_activity();
        let limit = filter.limit.unwrap_or(200).min(1000);
        let db = self.db_mut()?;
        let rows = db.list_audit(
            filter.event_type.as_deref(),
            filter.object_id.as_deref(),
            filter.result.as_deref(),
            filter.since_ts.as_deref(),
            filter.until_ts.as_deref(),
            limit,
        )?;
        let mut events: Vec<_> = rows.into_iter().map(row_to_event).collect();
        if let Some(uid) = filter.local_user_id {
            events.retain(|e| e.local_user_id == uid);
        }
        Ok(events)
    }

    pub fn record_password_view(&mut self, credential_id: &str) -> Result<(), VaultError> {
        let mut ctx = Map::new();
        ctx.insert("field".into(), Value::String("password".into()));
        self.audit_record("password_view", "success", Some(credential_id), ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialInput;
    use crate::paths::AppPaths;
    use crate::vault::Vault;
    use tempfile::tempdir;

    #[test]
    fn null_sink_accepts_events() {
        let sink = NullAuditSink;
        assert!(sink.record(AuditEventStub { kind: "app_start" }).is_ok());
    }

    #[test]
    fn sanitize_rejects_unknown_keys() {
        let mut m = Map::new();
        m.insert("password".into(), Value::String("secret".into()));
        assert_eq!(sanitize_context(m), Err(AuditError::ForbiddenContextKey));
    }

    #[test]
    fn operations_emit_events_without_secrets() {
        let dir = tempdir().unwrap();
        let mut v = Vault::new(AppPaths::from_data_dir(dir.path().to_path_buf()));
        let master = b"AuditMaster-Secret-7799!!";
        v.create(master, false).unwrap();

        // Fallo de unlock → pendiente (sin material)
        assert!(v.unlock_with_master(b"wrong-password").is_err());
        assert!(v.unlock_with_master(master).is_ok());

        let secret = "PlaintextShouldNeverAppearInAuditZZ";
        let c = v
            .create_credential(CredentialInput {
                service_name: "AuditSvc".into(),
                category: None,
                description: None,
                url: None,
                system_app: None,
                environment: None,
                username: Some("u".into()),
                password: secret.into(),
                auth_type: None,
                domain: None,
                email: None,
                notes: Some("nota privada secreta".into()),
                next_renewal_at: None,
                expiry_policy: None,
                policy_id: None,
                reason: Some("alta".into()),
            })
            .unwrap();

        v.record_password_view(&c.id).unwrap();
        v.update_credential(
            &c.id,
            CredentialInput {
                service_name: "AuditSvc".into(),
                category: None,
                description: None,
                url: None,
                system_app: None,
                environment: None,
                username: Some("u".into()),
                password: "OtherSecretNeverInAuditAA".into(),
                auth_type: None,
                domain: None,
                email: None,
                notes: None,
                next_renewal_at: None,
                expiry_policy: None,
                policy_id: None,
                reason: Some("cambio".into()),
            },
        )
        .unwrap();

        let all = v.list_audit(AuditFilter::default()).unwrap();
        assert!(all.iter().any(|e| e.event_type == "unlock_failure"));
        assert!(all.iter().any(|e| e.event_type == "unlock_success"));
        assert!(all.iter().any(|e| e.event_type == "credential_create"));
        assert!(all.iter().any(|e| e.event_type == "password_view"));
        assert!(all
            .iter()
            .any(|e| e.event_type == "password_change" || e.event_type == "credential_update"));

        let dump = format!("{all:?}");
        assert!(!dump.contains(secret));
        assert!(!dump.contains("OtherSecretNeverInAuditAA"));
        assert!(!dump.contains("AuditMaster-Secret-7799!!"));
        assert!(!dump.contains("nota privada secreta"));
        assert!(!dump.contains("wrong-password"));

        let hist = v.list_credential_history(&c.id).unwrap();
        let hist_dump = format!("{hist:?}");
        assert!(!hist_dump.contains(secret));
        assert!(!hist_dump.contains("OtherSecretNeverInAuditAA"));

        let filtered = v
            .list_audit(AuditFilter {
                event_type: Some("password_view".into()),
                object_id: Some(c.id.clone()),
                ..AuditFilter::default()
            })
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].result, "success");
    }
}
