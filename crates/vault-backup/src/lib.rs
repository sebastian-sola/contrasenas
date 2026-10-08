//! Backups cifrados `.cpbak` — Fase 8 (requisitos §15 / BACKUP.md).

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Versión de formato de backup (campo obligatorio `backup_version`).
pub const BACKUP_FORMAT_VERSION: u16 = 1;
pub const MAGIC: &[u8; 4] = b"CPBK";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const AAD: &[u8] = b"contrasenas/v1/backup/payload";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("backup no implementado completamente")]
    NotImplemented,
    #[error("error de E/S en backup")]
    Io,
    #[error("origen de backup no encontrado")]
    NotFound,
    #[error("formato de backup inválido o corrupto")]
    Corrupt,
    #[error("versión de backup no soportada")]
    UnsupportedVersion,
    #[error("integridad del backup fallida")]
    Integrity,
    #[error("destino ya existe; se requiere confirmación y backup preventivo")]
    DestinationExists,
    #[error("exportación en texto plano bloqueada")]
    PlaintextExportForbidden,
    #[error("importación requiere confirmación explícita")]
    ImportNeedsConfirmation,
    #[error("importación de gestores externos aún no disponible")]
    ImportNotAvailable,
    #[error("derivación KDF fallida")]
    KdfFailed,
    #[error("cifrado/descifrado fallido")]
    CryptoFailed,
}

/// Cabecera pública del `.cpbak` (sin secretos).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFileHeader {
    pub backup_version: u16,
    pub vault_id: String,
    pub created_at: String,
    pub app_version: String,
    pub schema_version: u16,
    pub kdf_id: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_hex: String,
    pub aead_id: String,
    pub content_hash: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupPayload {
    vault_header: String,
    vault_dat_b64: String,
}

pub trait BackupService: Send + Sync {
    fn format_version(&self) -> u16;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StubBackupService;

impl BackupService for StubBackupService {
    fn format_version(&self) -> u16 {
        BACKUP_FORMAT_VERSION
    }
}

/// Copia preventiva de un fichero (origen ya cifrado).
pub fn preventive_copy(src: &Path, dst: &Path) -> Result<(), BackupError> {
    if !src.exists() {
        return Err(BackupError::NotFound);
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|_| BackupError::Io)?;
    }
    fs::copy(src, dst).map_err(|_| BackupError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, BackupError> {
    if !s.len().is_multiple_of(2) {
        return Err(BackupError::Corrupt);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| BackupError::Corrupt))
        .collect()
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, BackupError> {
    let params =
        Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_LEN)).map_err(|_| BackupError::KdfFailed)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut *out)
        .map_err(|_| BackupError::KdfFailed)?;
    Ok(out)
}

fn aead_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, BackupError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BackupError::CryptoFailed)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|_| BackupError::CryptoFailed)?;
    let mut ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| BackupError::CryptoFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.append(&mut ct);
    Ok(out)
}

fn aead_decrypt(key: &[u8; KEY_LEN], boxed: &[u8]) -> Result<Vec<u8>, BackupError> {
    if boxed.len() < NONCE_LEN + 16 {
        return Err(BackupError::Corrupt);
    }
    let (nonce, ct) = boxed.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BackupError::CryptoFailed)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: AAD,
            },
        )
        .map_err(|_| BackupError::Integrity)
}

fn content_hash(ciphertext: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(ciphertext);
    hex_encode(&h.finalize())
}

/// Crea un `.cpbak` cifrado con la contraseña maestra (passphrase = master en MVP).
pub fn create_cpbak(
    dest: &Path,
    vault_id: &str,
    schema_version: u16,
    vault_header_json: &str,
    vault_dat: &[u8],
    master_password: &[u8],
    test_fast_kdf: bool,
) -> Result<BackupFileHeader, BackupError> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|_| BackupError::Io)?;
    }

    let (m, t, p) = if test_fast_kdf {
        (8u32, 1u32, 1u32)
    } else {
        (64 * 1024, 3, 1)
    };
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .map_err(|_| BackupError::CryptoFailed)?;

    let payload = BackupPayload {
        vault_header: vault_header_json.to_string(),
        vault_dat_b64: hex_encode(vault_dat), // hex evita padding issues; nombre histórico b64
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|_| BackupError::Io)?;
    let mut key = derive_key(master_password, &salt, m, t, p)?;
    let ciphertext = aead_encrypt(&key, &plaintext)?;
    key.zeroize();

    let header = BackupFileHeader {
        backup_version: BACKUP_FORMAT_VERSION,
        vault_id: vault_id.to_string(),
        created_at: now_ts(),
        app_version: "0.1.0".into(),
        schema_version,
        kdf_id: "argon2id".into(),
        m_cost_kib: m,
        t_cost: t,
        p_cost: p,
        salt_hex: hex_encode(&salt),
        aead_id: "aes-256-gcm".into(),
        content_hash: content_hash(&ciphertext),
        flags: 1,
    };
    let header_bytes = serde_json::to_vec(&header).map_err(|_| BackupError::Io)?;
    if header_bytes.len() > u32::MAX as usize {
        return Err(BackupError::Io);
    }

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&BACKUP_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);

    fs::write(dest, &out).map_err(|_| BackupError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(0o600));
    }
    Ok(header)
}

/// Lee cabecera pública sin descifrar.
pub fn read_cpbak_header(path: &Path) -> Result<BackupFileHeader, BackupError> {
    let bytes = fs::read(path).map_err(|_| BackupError::NotFound)?;
    parse_header_only(&bytes)
}

fn parse_header_only(bytes: &[u8]) -> Result<BackupFileHeader, BackupError> {
    if bytes.len() < 4 + 2 + 4 {
        return Err(BackupError::Corrupt);
    }
    if &bytes[0..4] != MAGIC {
        return Err(BackupError::Corrupt);
    }
    let ver = u16::from_le_bytes([bytes[4], bytes[5]]);
    if ver != BACKUP_FORMAT_VERSION {
        return Err(BackupError::UnsupportedVersion);
    }
    let header_len = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let start: usize = 10;
    let end = start + header_len;
    if end < start || end > bytes.len() {
        return Err(BackupError::Corrupt);
    }
    serde_json::from_slice(&bytes[start..end]).map_err(|_| BackupError::Corrupt)
}

/// Verifica magic, versión, hash de ciphertext y AEAD (requiere master).
pub fn verify_cpbak(path: &Path, master_password: &[u8]) -> Result<BackupFileHeader, BackupError> {
    let bytes = fs::read(path).map_err(|_| BackupError::NotFound)?;
    let header = parse_header_only(&bytes)?;
    let header_len = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let ct_start = 10 + header_len;
    if ct_start > bytes.len() {
        return Err(BackupError::Corrupt);
    }
    let ciphertext = &bytes[ct_start..];
    if content_hash(ciphertext) != header.content_hash {
        return Err(BackupError::Integrity);
    }
    let salt = hex_decode(&header.salt_hex)?;
    let mut key = derive_key(
        master_password,
        &salt,
        header.m_cost_kib,
        header.t_cost,
        header.p_cost,
    )?;
    let _plain = aead_decrypt(&key, ciphertext)?;
    key.zeroize();
    Ok(header)
}

/// Restaura ficheros de bóveda desde `.cpbak`. Si `dest_header` existe, exige `confirm_overwrite`.
pub fn restore_cpbak(
    path: &Path,
    master_password: &[u8],
    dest_header: &Path,
    dest_dat: &Path,
    preventive_dir: &Path,
    confirm_overwrite: bool,
) -> Result<BackupFileHeader, BackupError> {
    let bytes = fs::read(path).map_err(|_| BackupError::NotFound)?;
    let header = parse_header_only(&bytes)?;
    let header_len = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let ct_start = 10 + header_len;
    let ciphertext = &bytes[ct_start..];
    if content_hash(ciphertext) != header.content_hash {
        return Err(BackupError::Integrity);
    }
    let salt = hex_decode(&header.salt_hex)?;
    let mut key = derive_key(
        master_password,
        &salt,
        header.m_cost_kib,
        header.t_cost,
        header.p_cost,
    )?;
    let plain = aead_decrypt(&key, ciphertext)?;
    key.zeroize();
    let payload: BackupPayload = serde_json::from_slice(&plain).map_err(|_| BackupError::Corrupt)?;
    let vault_dat = hex_decode(&payload.vault_dat_b64)?;

    if dest_header.exists() || dest_dat.exists() {
        if !confirm_overwrite {
            return Err(BackupError::DestinationExists);
        }
        fs::create_dir_all(preventive_dir).map_err(|_| BackupError::Io)?;
        let stamp = now_ts();
        if dest_header.exists() {
            preventive_copy(
                dest_header,
                &preventive_dir.join(format!("pre-restore-header-{stamp}.json")),
            )?;
        }
        if dest_dat.exists() {
            preventive_copy(
                dest_dat,
                &preventive_dir.join(format!("pre-restore-vault-{stamp}.dat")),
            )?;
        }
    }

    if let Some(p) = dest_header.parent() {
        fs::create_dir_all(p).map_err(|_| BackupError::Io)?;
    }
    fs::write(dest_header, payload.vault_header.as_bytes()).map_err(|_| BackupError::Io)?;
    fs::write(dest_dat, &vault_dat).map_err(|_| BackupError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dest_header, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(dest_dat, fs::Permissions::from_mode(0o600));
    }
    Ok(header)
}

/// Exportación plaintext: siempre bloqueada por defecto.
pub fn export_plaintext_blocked() -> Result<(), BackupError> {
    Err(BackupError::PlaintextExportForbidden)
}

/// Import de gestores externos: requiere confirmación; stub.
pub fn import_external_stub(confirmed: bool) -> Result<(), BackupError> {
    if !confirmed {
        return Err(BackupError::ImportNeedsConfirmation);
    }
    Err(BackupError::ImportNotAvailable)
}

/// No borrar backups antiguos sin confirmación.
pub fn delete_backup_file(path: &Path, confirmed: bool) -> Result<(), BackupError> {
    if !confirmed {
        return Err(BackupError::DestinationExists);
    }
    if !path.exists() {
        return Err(BackupError::NotFound);
    }
    fs::remove_file(path).map_err(|_| BackupError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn backup_version_is_defined() {
        let svc = StubBackupService;
        assert_eq!(svc.format_version(), BACKUP_FORMAT_VERSION);
    }

    #[test]
    fn preventive_copy_works() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.dat");
        let dst = dir.path().join("backups/a.dat");
        let mut f = fs::File::create(&src).unwrap();
        f.write_all(b"ciphered").unwrap();
        preventive_copy(&src, &dst).unwrap();
        assert_eq!(fs::read(dst).unwrap(), b"ciphered");
    }

    #[test]
    fn cpbak_roundtrip_and_integrity() {
        let dir = tempdir().unwrap();
        let bak = dir.path().join("vault.cpbak");
        let master = b"BackupMaster-Test-88!!";
        let header_json = r#"{"vault_id":"vid","schema_version":4}"#;
        let dat = b"SQLCIPHER_BYTES_FAKE";

        let meta = create_cpbak(
            &bak,
            "vid",
            4,
            header_json,
            dat,
            master,
            true,
        )
        .unwrap();
        assert_eq!(meta.backup_version, 1);
        assert!(!meta.content_hash.is_empty());

        let verified = verify_cpbak(&bak, master).unwrap();
        assert_eq!(verified.vault_id, "vid");

        // tamper ciphertext
        let mut bytes = fs::read(&bak).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let tampered = dir.path().join("bad.cpbak");
        fs::write(&tampered, &bytes).unwrap();
        assert_eq!(verify_cpbak(&tampered, master), Err(BackupError::Integrity));

        let dest_h = dir.path().join("restored/vault.header");
        let dest_d = dir.path().join("restored/vault.dat");
        let prev = dir.path().join("restored/backups");
        restore_cpbak(&bak, master, &dest_h, &dest_d, &prev, false).unwrap();
        assert_eq!(fs::read_to_string(&dest_h).unwrap(), header_json);
        assert_eq!(fs::read(&dest_d).unwrap(), dat);

        // overwrite requires confirm
        assert_eq!(
            restore_cpbak(&bak, master, &dest_h, &dest_d, &prev, false),
            Err(BackupError::DestinationExists)
        );
        restore_cpbak(&bak, master, &dest_h, &dest_d, &prev, true).unwrap();
        assert!(prev.read_dir().unwrap().next().is_some());
    }

    #[test]
    fn plaintext_export_blocked_and_import_stub() {
        assert_eq!(
            export_plaintext_blocked(),
            Err(BackupError::PlaintextExportForbidden)
        );
        assert_eq!(
            import_external_stub(false),
            Err(BackupError::ImportNeedsConfirmation)
        );
        assert_eq!(
            import_external_stub(true),
            Err(BackupError::ImportNotAvailable)
        );
    }

    #[test]
    fn delete_requires_confirmation() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("old.cpbak");
        fs::write(&p, b"x").unwrap();
        assert!(delete_backup_file(&p, false).is_err());
        delete_backup_file(&p, true).unwrap();
        assert!(!p.exists());
    }
}
