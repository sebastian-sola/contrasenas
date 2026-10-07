//! Backend SQLCipher (D2 preferido) — schema v2 con credenciales.

use super::permissions::set_owner_only_file_permissions;
use super::rows::{CredentialRow, HistoryRow};
use super::{StorageBackendKind, StorageError, VaultDb};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION_V1: u16 = 1;
pub const SCHEMA_VERSION_V2: u16 = 2;

pub struct SqlCipherVaultDb {
    path: PathBuf,
    conn: Option<Connection>,
}

impl SqlCipherVaultDb {
    pub fn new(path: PathBuf) -> Self {
        Self { path, conn: None }
    }

    fn apply_key(conn: &Connection, key: &[u8; 32]) -> Result<(), StorageError> {
        let hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let pragma = format!("PRAGMA key = \"x'{hex}'\";");
        conn.execute_batch(&pragma)
            .map_err(|_| StorageError::CorruptOrWrongKey)?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| StorageError::CorruptOrWrongKey)?;
        Ok(())
    }

    fn conn(&self) -> Result<&Connection, StorageError> {
        self.conn.as_ref().ok_or(StorageError::NotOpen)
    }

    fn set_schema_version(&self, ver: u16) -> Result<(), StorageError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('schema_version', ?1)",
            [ver.to_string()],
        )
        .map_err(|_| StorageError::Database)?;
        Ok(())
    }

    fn migrate_to_v2(&self) -> Result<(), StorageError> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS history_entries (
                id TEXT PRIMARY KEY NOT NULL,
                credential_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                fields_changed TEXT,
                reason TEXT
            );
            "#,
        )
        .map_err(|_| StorageError::Database)?;

        let has_fp = conn
            .prepare("SELECT password_fp FROM credentials LIMIT 1")
            .is_ok();
        if !has_fp {
            // Sustituir tabla v1 (o inexistente) por schema v2 completo.
            conn.execute_batch(
                r#"
                CREATE TABLE credentials_new (
                    id TEXT PRIMARY KEY NOT NULL,
                    service_name TEXT NOT NULL,
                    category TEXT,
                    description TEXT,
                    url TEXT,
                    system_app TEXT,
                    environment TEXT,
                    username TEXT,
                    password_ciphertext BLOB NOT NULL,
                    auth_type TEXT,
                    domain TEXT,
                    email TEXT,
                    notes_ciphertext BLOB,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    password_changed_at TEXT,
                    next_renewal_at TEXT,
                    expiry_policy TEXT,
                    status TEXT,
                    strength_score INTEGER,
                    policy_compliant INTEGER,
                    password_fp TEXT,
                    deleted_at TEXT
                );
                "#,
            )
            .map_err(|_| StorageError::Database)?;

            let has_old = conn.prepare("SELECT id FROM credentials LIMIT 1").is_ok();
            if has_old {
                let _ = conn.execute_batch(
                    r#"
                    INSERT OR IGNORE INTO credentials_new (
                        id, service_name, username, password_ciphertext, notes_ciphertext,
                        created_at, updated_at
                    )
                    SELECT
                        id,
                        COALESCE(service_name, 'sin-nombre'),
                        username,
                        COALESCE(password_ciphertext, X''),
                        notes_ciphertext,
                        COALESCE(created_at, datetime('now')),
                        COALESCE(updated_at, datetime('now'))
                    FROM credentials;
                    "#,
                );
            }
            conn.execute_batch(
                r#"
                DROP TABLE IF EXISTS credentials;
                ALTER TABLE credentials_new RENAME TO credentials;
                "#,
            )
            .map_err(|_| StorageError::Database)?;
        }

        self.set_schema_version(SCHEMA_VERSION_V2)?;
        Ok(())
    }

    fn map_credential_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialRow> {
        Ok(CredentialRow {
            id: r.get(0)?,
            service_name: r.get(1)?,
            category: r.get(2)?,
            description: r.get(3)?,
            url: r.get(4)?,
            system_app: r.get(5)?,
            environment: r.get(6)?,
            username: r.get(7)?,
            password_ciphertext: r.get(8)?,
            auth_type: r.get(9)?,
            domain: r.get(10)?,
            email: r.get(11)?,
            notes_ciphertext: r.get(12)?,
            created_at: r.get(13)?,
            updated_at: r.get(14)?,
            password_changed_at: r.get(15)?,
            next_renewal_at: r.get(16)?,
            expiry_policy: r.get(17)?,
            status: r.get(18)?,
            strength_score: r.get(19)?,
            policy_compliant: r.get(20)?,
            password_fp: r.get(21)?,
            deleted_at: r.get(22)?,
        })
    }
}

impl VaultDb for SqlCipherVaultDb {
    fn backend_kind(&self) -> StorageBackendKind {
        StorageBackendKind::SqlCipherAead
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
        let conn = Connection::open(&self.path).map_err(|_| StorageError::Database)?;
        set_owner_only_file_permissions(&self.path)?;
        Self::apply_key(&conn, key)?;
        self.conn = Some(conn);
        self.ensure_schema_v1()?;
        self.set_setting("auto_lock_secs", "300")?;
        Ok(())
    }

    fn open(&mut self, key: &[u8; 32]) -> Result<(), StorageError> {
        if self.conn.is_some() {
            return Err(StorageError::AlreadyOpen);
        }
        if !self.path.exists() {
            return Err(StorageError::NotFound);
        }
        let conn = Connection::open(&self.path).map_err(|_| StorageError::Database)?;
        Self::apply_key(&conn, key)?;
        self.conn = Some(conn);
        Ok(())
    }

    fn close(&mut self) {
        self.conn = None;
    }

    fn is_open(&self) -> bool {
        self.conn.is_some()
    }

    fn schema_version(&self) -> Result<u16, StorageError> {
        let conn = self.conn()?;
        let ver: Option<String> = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| StorageError::Database)?;
        match ver {
            Some(v) => v.parse().map_err(|_| StorageError::CorruptOrWrongKey),
            None => Ok(0),
        }
    }

    fn ensure_schema_v1(&mut self) -> Result<(), StorageError> {
        let conn = self.conn.as_ref().ok_or(StorageError::NotOpen)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_settings (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            "#,
        )
        .map_err(|_| StorageError::Database)?;

        let current = self.schema_version().unwrap_or(0);
        if current > SCHEMA_VERSION_V2 {
            return Err(StorageError::UnsupportedMigration);
        }
        if current < SCHEMA_VERSION_V2 {
            self.migrate_to_v2()?;
        }
        Ok(())
    }

    fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT value FROM vault_settings WHERE key = ?1",
            [key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| StorageError::Database)
    }

    fn set_setting(&mut self, key: &str, value: &str) -> Result<(), StorageError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO vault_settings(key, value) VALUES (?1, ?2)",
            [key, value],
        )
        .map_err(|_| StorageError::Database)?;
        Ok(())
    }

    fn upsert_credential(&mut self, row: &CredentialRow) -> Result<(), StorageError> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO credentials (
                id, service_name, category, description, url, system_app, environment,
                username, password_ciphertext, auth_type, domain, email, notes_ciphertext,
                created_at, updated_at, password_changed_at, next_renewal_at, expiry_policy,
                status, strength_score, policy_compliant, password_fp, deleted_at
            ) VALUES (
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23
            )
            ON CONFLICT(id) DO UPDATE SET
                service_name=excluded.service_name,
                category=excluded.category,
                description=excluded.description,
                url=excluded.url,
                system_app=excluded.system_app,
                environment=excluded.environment,
                username=excluded.username,
                password_ciphertext=excluded.password_ciphertext,
                auth_type=excluded.auth_type,
                domain=excluded.domain,
                email=excluded.email,
                notes_ciphertext=excluded.notes_ciphertext,
                updated_at=excluded.updated_at,
                password_changed_at=excluded.password_changed_at,
                next_renewal_at=excluded.next_renewal_at,
                expiry_policy=excluded.expiry_policy,
                status=excluded.status,
                strength_score=excluded.strength_score,
                policy_compliant=excluded.policy_compliant,
                password_fp=excluded.password_fp,
                deleted_at=excluded.deleted_at
            "#,
            params![
                row.id,
                row.service_name,
                row.category,
                row.description,
                row.url,
                row.system_app,
                row.environment,
                row.username,
                row.password_ciphertext,
                row.auth_type,
                row.domain,
                row.email,
                row.notes_ciphertext,
                row.created_at,
                row.updated_at,
                row.password_changed_at,
                row.next_renewal_at,
                row.expiry_policy,
                row.status,
                row.strength_score,
                row.policy_compliant,
                row.password_fp,
                row.deleted_at,
            ],
        )
        .map_err(|_| StorageError::Database)?;
        Ok(())
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialRow>, StorageError> {
        let conn = self.conn()?;
        conn.query_row(
            r#"
            SELECT id, service_name, category, description, url, system_app, environment,
                   username, password_ciphertext, auth_type, domain, email, notes_ciphertext,
                   created_at, updated_at, password_changed_at, next_renewal_at, expiry_policy,
                   status, strength_score, policy_compliant, password_fp, deleted_at
            FROM credentials WHERE id = ?1
            "#,
            [id],
            Self::map_credential_row,
        )
        .optional()
        .map_err(|_| StorageError::Database)
    }

    fn list_credentials(&self, include_deleted: bool) -> Result<Vec<CredentialRow>, StorageError> {
        let conn = self.conn()?;
        let sql = if include_deleted {
            r#"
            SELECT id, service_name, category, description, url, system_app, environment,
                   username, password_ciphertext, auth_type, domain, email, notes_ciphertext,
                   created_at, updated_at, password_changed_at, next_renewal_at, expiry_policy,
                   status, strength_score, policy_compliant, password_fp, deleted_at
            FROM credentials ORDER BY service_name COLLATE NOCASE
            "#
        } else {
            r#"
            SELECT id, service_name, category, description, url, system_app, environment,
                   username, password_ciphertext, auth_type, domain, email, notes_ciphertext,
                   created_at, updated_at, password_changed_at, next_renewal_at, expiry_policy,
                   status, strength_score, policy_compliant, password_fp, deleted_at
            FROM credentials WHERE deleted_at IS NULL ORDER BY service_name COLLATE NOCASE
            "#
        };
        let mut stmt = conn.prepare(sql).map_err(|_| StorageError::Database)?;
        let rows = stmt
            .query_map([], Self::map_credential_row)
            .map_err(|_| StorageError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| StorageError::Database)?);
        }
        Ok(out)
    }

    fn soft_delete_credential(&mut self, id: &str, deleted_at: &str) -> Result<(), StorageError> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "UPDATE credentials SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2",
                params![deleted_at, id],
            )
            .map_err(|_| StorageError::Database)?;
        if n == 0 {
            return Err(StorageError::CredentialNotFound);
        }
        Ok(())
    }

    fn restore_credential(&mut self, id: &str) -> Result<(), StorageError> {
        let conn = self.conn()?;
        let n = conn
            .execute(
                "UPDATE credentials SET deleted_at = NULL, updated_at = datetime('now') WHERE id = ?1",
                [id],
            )
            .map_err(|_| StorageError::Database)?;
        if n == 0 {
            return Err(StorageError::CredentialNotFound);
        }
        Ok(())
    }

    fn insert_history(&mut self, row: &HistoryRow) -> Result<(), StorageError> {
        let conn = self.conn()?;
        conn.execute(
            r#"
            INSERT INTO history_entries (id, credential_id, timestamp, actor, action, fields_changed, reason)
            VALUES (?1,?2,?3,?4,?5,?6,?7)
            "#,
            params![
                row.id,
                row.credential_id,
                row.timestamp,
                row.actor,
                row.action,
                row.fields_changed,
                row.reason,
            ],
        )
        .map_err(|_| StorageError::Database)?;
        Ok(())
    }

    fn list_history(&self, credential_id: &str) -> Result<Vec<HistoryRow>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT id, credential_id, timestamp, actor, action, fields_changed, reason
                FROM history_entries WHERE credential_id = ?1 ORDER BY timestamp DESC
                "#,
            )
            .map_err(|_| StorageError::Database)?;
        let rows = stmt
            .query_map([credential_id], |r| {
                Ok(HistoryRow {
                    id: r.get(0)?,
                    credential_id: r.get(1)?,
                    timestamp: r.get(2)?,
                    actor: r.get(3)?,
                    action: r.get(4)?,
                    fields_changed: r.get(5)?,
                    reason: r.get(6)?,
                })
            })
            .map_err(|_| StorageError::Database)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| StorageError::Database)?);
        }
        Ok(out)
    }

    fn count_password_fp(&self, fp: &str, exclude_id: Option<&str>) -> Result<u32, StorageError> {
        let conn = self.conn()?;
        let count: i64 = match exclude_id {
            Some(id) => conn
                .query_row(
                    "SELECT COUNT(*) FROM credentials WHERE password_fp = ?1 AND deleted_at IS NULL AND id != ?2",
                    params![fp, id],
                    |r| r.get(0),
                )
                .map_err(|_| StorageError::Database)?,
            None => conn
                .query_row(
                    "SELECT COUNT(*) FROM credentials WHERE password_fp = ?1 AND deleted_at IS NULL",
                    [fp],
                    |r| r.get(0),
                )
                .map_err(|_| StorageError::Database)?,
        };
        Ok(count as u32)
    }
}

impl Drop for SqlCipherVaultDb {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_open_wrong_key_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let key = [7u8; 32];
        let mut db = SqlCipherVaultDb::new(path.clone());
        db.create(&key).unwrap();
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION_V2);
        db.close();

        let mut db2 = SqlCipherVaultDb::new(path.clone());
        let bad = [8u8; 32];
        assert_eq!(db2.open(&bad), Err(StorageError::CorruptOrWrongKey));

        let mut db3 = SqlCipherVaultDb::new(path);
        db3.open(&key).unwrap();
        assert!(db3.is_open());
    }
}
