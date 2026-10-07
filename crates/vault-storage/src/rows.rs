//! Filas de almacenamiento (secretos ya como ciphertext).

/// Fila de credencial en SQLCipher (campos sensibles = BLOB AEAD).
#[derive(Debug, Clone)]
pub struct CredentialRow {
    pub id: String,
    pub service_name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub system_app: Option<String>,
    pub environment: Option<String>,
    pub username: Option<String>,
    pub password_ciphertext: Vec<u8>,
    pub auth_type: Option<String>,
    pub domain: Option<String>,
    pub email: Option<String>,
    pub notes_ciphertext: Option<Vec<u8>>,
    pub created_at: String,
    pub updated_at: String,
    pub password_changed_at: Option<String>,
    pub next_renewal_at: Option<String>,
    pub expiry_policy: Option<String>,
    pub status: Option<String>,
    pub strength_score: Option<i32>,
    pub policy_compliant: Option<i32>,
    /// Huella opaca (hex) para reutilización; no es la contraseña.
    pub password_fp: Option<String>,
    pub deleted_at: Option<String>,
}

/// Entrada de historial (solo metadatos; sin contraseñas).
#[derive(Debug, Clone)]
pub struct HistoryRow {
    pub id: String,
    pub credential_id: String,
    pub timestamp: String,
    pub actor: Option<String>,
    pub action: String,
    pub fields_changed: Option<String>,
    pub reason: Option<String>,
}
