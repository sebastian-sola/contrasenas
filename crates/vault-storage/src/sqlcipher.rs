//! Backend SQLCipher (D2 preferido).

use super::permissions::set_owner_only_file_permissions;
use super::{StorageBackendKind, StorageError, VaultDb};
use rusqlite::{Connection, OptionalExtension};
use std::path::{Path, PathBuf};
pub const SCHEMA_VERSION_V1: u16 = 1;

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
        // Verificación temprana: una query simple falla si la clave es incorrecta.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|_| StorageError::CorruptOrWrongKey)?;
        Ok(())
    }

    fn conn(&self) -> Result<&Connection, StorageError> {
        self.conn.as_ref().ok_or(StorageError::NotOpen)
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
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY NOT NULL,
                service_name TEXT,
                username TEXT,
                password_ciphertext BLOB,
                notes_ciphertext BLOB,
                created_at TEXT,
                updated_at TEXT
            );
            "#,
        )
        .map_err(|_| StorageError::Database)?;

        let current = self.schema_version().unwrap_or(0);
        if current == 0 {
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('schema_version', ?1)",
                [SCHEMA_VERSION_V1.to_string()],
            )
            .map_err(|_| StorageError::Database)?;
        } else if current > SCHEMA_VERSION_V1 {
            return Err(StorageError::UnsupportedMigration);
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
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION_V1);
        db.close();

        let mut db2 = SqlCipherVaultDb::new(path.clone());
        let bad = [8u8; 32];
        assert_eq!(db2.open(&bad), Err(StorageError::CorruptOrWrongKey));

        let mut db3 = SqlCipherVaultDb::new(path);
        db3.open(&key).unwrap();
        assert!(db3.is_open());
        assert_eq!(
            db3.get_setting("auto_lock_secs").unwrap().as_deref(),
            Some("300")
        );
    }
}
