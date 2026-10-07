//! Criptografía de producción (Fase 2).
//!
//! - KDF: Argon2id (parámetros versionados)
//! - AEAD: AES-256-GCM
//! - DEK envuelta con KEK derivada de la contraseña maestra
//! - Wipe best-effort con `zeroize` (límites documentados en `docs/SECURITY.md`)
//!
//! Persistencia de bóveda: orquestada por `crate::vault` (Fase 3).

mod aead;
mod derive;
mod header;
mod kdf;
mod keys;
mod wrap;

pub use aead::{decrypt, encrypt, AeadBox};
pub use derive::derive_db_key;
pub use header::{CryptoHeaderV1, AEAD_ID_AES256GCM, CRYPTO_FORMAT_VERSION, KDF_ID_ARGON2ID};
pub use kdf::{derive_kek, KdfParams};
pub use keys::{
    generate_dek, generate_salt, DataEncryptionKey, KeyEncryptionKey, KEY_LEN, SALT_LEN,
};
pub use wrap::{unwrap_dek, wrap_dek, AadKind, WrappedDek};

use thiserror::Error;

/// Errores criptográficos. Los mensajes **nunca** incluyen secretos ni material de claves.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("parámetros KDF no soportados")]
    UnsupportedKdfParams,
    #[error("versión de formato crypto no soportada")]
    UnsupportedFormatVersion,
    #[error("identificador de algoritmo no soportado")]
    UnsupportedAlgorithm,
    #[error("salt de longitud inválida")]
    InvalidSaltLength,
    #[error("derivación KDF fallida")]
    KdfFailed,
    #[error("cifrado AEAD fallido")]
    EncryptFailed,
    #[error("descifrado o autenticación AEAD fallida")]
    DecryptFailed,
    #[error("desenvoltura de clave fallida")]
    UnwrapFailed,
    #[error("envoltura de clave fallida")]
    WrapFailed,
    #[error("datos corruptos o truncados")]
    CorruptData,
    #[error("generación de aleatoriedad fallida")]
    RngFailed,
    #[error("cabecera crypto inválida")]
    InvalidHeader,
}

/// Contrato estable del motor (para DI / tests).
pub trait CryptoEngine: Send + Sync {
    fn algorithm_id(&self) -> &'static str;
    fn kdf_id(&self) -> &'static str;
    fn format_version(&self) -> u16;
}

/// Motor de producción Fase 2.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionCryptoEngine;

impl CryptoEngine for ProductionCryptoEngine {
    fn algorithm_id(&self) -> &'static str {
        AEAD_ID_AES256GCM
    }

    fn kdf_id(&self) -> &'static str {
        KDF_ID_ARGON2ID
    }

    fn format_version(&self) -> u16 {
        CRYPTO_FORMAT_VERSION
    }
}

/// Crea material de claves para una bóveda nueva (solo en memoria) con params v1.
pub fn bootstrap_key_material(
    master_password: &[u8],
    with_recovery_kit: bool,
) -> Result<BootstrapResult, CryptoError> {
    bootstrap_key_material_with_params(master_password, &KdfParams::v1(), with_recovery_kit)
}

/// Igual que [`bootstrap_key_material`] pero con parámetros KDF explícitos (tests / migración).
pub fn bootstrap_key_material_with_params(
    master_password: &[u8],
    params: &KdfParams,
    with_recovery_kit: bool,
) -> Result<BootstrapResult, CryptoError> {
    let salt = generate_salt()?;
    let dek = generate_dek()?;
    let kek = derive_kek(master_password, &salt, params)?;
    let wrapped_dek = wrap_dek(&kek, &dek, wrap::AadKind::MasterDek)?;

    let mut header = CryptoHeaderV1::new_master_wrap(*params, salt, wrapped_dek);

    let recovery_code = if with_recovery_kit {
        let code = crate::recovery::generate_recovery_code()?;
        let recovery_salt = generate_salt()?;
        let recovery_kek = derive_kek(code.as_bytes(), &recovery_salt, params)?;
        let wrapped_recovery = wrap_dek(&recovery_kek, &dek, wrap::AadKind::RecoveryDek)?;
        header.set_recovery(recovery_salt, wrapped_recovery);
        Some(code)
    } else {
        None
    };

    Ok(BootstrapResult {
        header,
        dek,
        recovery_code,
    })
}

/// Resultado de bootstrap en memoria (Fase 2; persistencia = Fase 3).
pub struct BootstrapResult {
    pub header: CryptoHeaderV1,
    pub dek: DataEncryptionKey,
    pub recovery_code: Option<zeroize::Zeroizing<String>>,
}

/// Desenvuelve la DEK con la contraseña maestra a partir de una cabecera.
pub fn unlock_dek_with_master(
    master_password: &[u8],
    header: &CryptoHeaderV1,
) -> Result<DataEncryptionKey, CryptoError> {
    header.validate()?;
    let params = header.kdf_params()?;
    let salt = header.salt_array()?;
    let kek = derive_kek(master_password, &salt, &params)?;
    unwrap_dek(&kek, &header.wrapped_dek, wrap::AadKind::MasterDek)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_password() -> &'static [u8] {
        b"correct-horse-battery-staple-phase2"
    }

    #[test]
    fn production_engine_ids() {
        let e = ProductionCryptoEngine;
        assert_eq!(e.algorithm_id(), AEAD_ID_AES256GCM);
        assert_eq!(e.kdf_id(), KDF_ID_ARGON2ID);
        assert_eq!(e.format_version(), CRYPTO_FORMAT_VERSION);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = generate_dek().unwrap();
        let pt = b"secreto-de-prueba";
        let ct = encrypt(&dek, pt, b"aad-v1").unwrap();
        let out = decrypt(&dek, &ct, b"aad-v1").unwrap();
        assert_eq!(out.as_slice(), pt);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let dek = generate_dek().unwrap();
        let other = generate_dek().unwrap();
        let ct = encrypt(&dek, b"hola", b"aad").unwrap();
        assert_eq!(
            decrypt(&other, &ct, b"aad"),
            Err(CryptoError::DecryptFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = generate_dek().unwrap();
        let mut ct = encrypt(&dek, b"hola", b"aad").unwrap();
        let last = ct.bytes.last_mut().unwrap();
        *last ^= 0x5a;
        assert_eq!(decrypt(&dek, &ct, b"aad"), Err(CryptoError::DecryptFailed));
    }

    #[test]
    fn wrong_aad_fails() {
        let dek = generate_dek().unwrap();
        let ct = encrypt(&dek, b"hola", b"aad-correct").unwrap();
        assert_eq!(
            decrypt(&dek, &ct, b"aad-wrong"),
            Err(CryptoError::DecryptFailed)
        );
    }

    #[test]
    fn corrupt_short_ciphertext_fails() {
        let dek = generate_dek().unwrap();
        let ct = AeadBox {
            bytes: vec![1, 2, 3],
        };
        assert_eq!(decrypt(&dek, &ct, b""), Err(CryptoError::CorruptData));
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let params = KdfParams::for_tests();
        let salt = generate_salt().unwrap();
        let dek = generate_dek().unwrap();
        let kek = derive_kek(test_password(), &salt, &params).unwrap();
        let wrapped = wrap_dek(&kek, &dek, wrap::AadKind::MasterDek).unwrap();
        let opened = unwrap_dek(&kek, &wrapped, wrap::AadKind::MasterDek).unwrap();
        assert_eq!(opened.expose(), dek.expose());
    }

    #[test]
    fn wrong_password_unwrap_fails() {
        let params = KdfParams::for_tests();
        let salt = generate_salt().unwrap();
        let dek = generate_dek().unwrap();
        let kek = derive_kek(test_password(), &salt, &params).unwrap();
        let wrapped = wrap_dek(&kek, &dek, wrap::AadKind::MasterDek).unwrap();
        let bad = derive_kek(b"wrong-password", &salt, &params).unwrap();
        assert!(matches!(
            unwrap_dek(&bad, &wrapped, wrap::AadKind::MasterDek),
            Err(CryptoError::UnwrapFailed)
        ));
    }

    #[test]
    fn tampered_wrapped_dek_fails() {
        let params = KdfParams::for_tests();
        let salt = generate_salt().unwrap();
        let dek = generate_dek().unwrap();
        let kek = derive_kek(test_password(), &salt, &params).unwrap();
        let mut wrapped = wrap_dek(&kek, &dek, wrap::AadKind::MasterDek).unwrap();
        *wrapped.bytes.last_mut().unwrap() ^= 0xff;
        assert!(matches!(
            unwrap_dek(&kek, &wrapped, wrap::AadKind::MasterDek),
            Err(CryptoError::UnwrapFailed)
        ));
    }

    #[test]
    fn bootstrap_and_unlock_with_master() {
        let params = KdfParams::for_tests();
        let boot = bootstrap_key_material_with_params(test_password(), &params, false).unwrap();
        assert!(boot.recovery_code.is_none());
        assert_eq!(boot.header.format_version, CRYPTO_FORMAT_VERSION);
        assert_eq!(boot.header.kdf_version, params.version);
        let dek2 = unlock_dek_with_master(test_password(), &boot.header).unwrap();
        assert_eq!(dek2.expose(), boot.dek.expose());
        assert!(unlock_dek_with_master(b"nope", &boot.header).is_err());
    }

    #[test]
    fn kdf_version_in_header_roundtrip_json() {
        let params = KdfParams::for_tests();
        let boot = bootstrap_key_material_with_params(test_password(), &params, false).unwrap();
        let json = serde_json::to_string(&boot.header).unwrap();
        let parsed: CryptoHeaderV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kdf_version, params.version);
        assert_eq!(parsed.m_cost_kib, params.m_cost_kib);
        parsed.validate().unwrap();
        let mut future = parsed.clone();
        future.format_version = CRYPTO_FORMAT_VERSION + 10;
        assert_eq!(
            future.validate(),
            Err(CryptoError::UnsupportedFormatVersion)
        );
    }

    #[test]
    fn unsupported_kdf_id_rejected() {
        let params = KdfParams::for_tests();
        let mut boot = bootstrap_key_material_with_params(test_password(), &params, false).unwrap();
        boot.header.kdf_id = "pbkdf2".into();
        assert_eq!(
            boot.header.validate(),
            Err(CryptoError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn production_v1_params_are_strong() {
        let p = KdfParams::v1();
        assert!(p.m_cost_kib >= 64 * 1024);
        assert!(p.t_cost >= 3);
        assert_eq!(p.p_cost, 1);
    }
}
