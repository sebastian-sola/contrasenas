//! Kit de emergencia — capa crypto (Fase 2).
//!
//! La contraseña maestra **nunca** se almacena de forma recuperable.
//! Persistencia de cabecera/bóveda = Fase 3.
//! Ver `docs/SECURITY.md` §2.1.

use crate::crypto::{
    derive_kek, generate_salt, unwrap_dek, wrap_dek, AadKind, CryptoError, CryptoHeaderV1,
    DataEncryptionKey, KdfParams,
};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

const RECOVERY_CODE_BYTES: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("kit de emergencia no presente en la cabecera")]
    NotPresent,
    #[error("código de recuperación inválido")]
    InvalidCode,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Contrato del kit de emergencia.
pub trait RecoveryKit: Send + Sync {
    fn design_summary(&self) -> &'static str;
}

/// Implementación de producción (APIs crypto; sin I/O de bóveda).
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductionRecoveryKit;

impl RecoveryKit for ProductionRecoveryKit {
    fn design_summary(&self) -> &'static str {
        "Kit de emergencia: código de alta entropía que envuelve la DEK por separado; \
         la contraseña maestra nunca se guarda."
    }
}

/// Alias documental: el stub de Fase 1 queda como el kit de producción a nivel de resumen.
pub type StubRecoveryKit = ProductionRecoveryKit;

/// Genera un código de recuperación (hex de 32 bytes CSPRNG). Mostrar una sola vez.
pub fn generate_recovery_code() -> Result<Zeroizing<String>, CryptoError> {
    let mut raw = [0u8; RECOVERY_CODE_BYTES];
    rand::thread_rng()
        .try_fill_bytes(&mut raw)
        .map_err(|_| CryptoError::RngFailed)?;
    let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
    raw.iter_mut().for_each(|b| *b = 0);
    Ok(Zeroizing::new(hex))
}

/// Desenvuelve la DEK con el código de emergencia (sin persistir).
pub fn unlock_dek_with_recovery(
    recovery_code: &str,
    header: &CryptoHeaderV1,
) -> Result<DataEncryptionKey, RecoveryError> {
    header.validate().map_err(RecoveryError::Crypto)?;
    let salt = header
        .recovery_salt_array()
        .map_err(RecoveryError::Crypto)?
        .ok_or(RecoveryError::NotPresent)?;
    let wrapped = header
        .wrapped_dek_recovery
        .as_ref()
        .ok_or(RecoveryError::NotPresent)?;
    let params = header.kdf_params().map_err(RecoveryError::Crypto)?;
    let kek =
        derive_kek(recovery_code.as_bytes(), &salt, &params).map_err(RecoveryError::Crypto)?;
    unwrap_dek(&kek, wrapped, AadKind::RecoveryDek).map_err(|e| match e {
        CryptoError::UnwrapFailed | CryptoError::DecryptFailed => RecoveryError::InvalidCode,
        other => RecoveryError::Crypto(other),
    })
}

/// Re-envuelve la DEK con una nueva contraseña maestra (tras recuperación).
/// No adjunta kit de emergencia: la rotación/reemisión del kit es política de Fase 3+.
pub fn rewrap_dek_with_new_master(
    dek: &DataEncryptionKey,
    new_master_password: &[u8],
    params: &KdfParams,
) -> Result<CryptoHeaderV1, CryptoError> {
    let salt = generate_salt()?;
    let kek = derive_kek(new_master_password, &salt, params)?;
    let wrapped = wrap_dek(&kek, dek, AadKind::MasterDek)?;
    Ok(CryptoHeaderV1::new_master_wrap(*params, salt, wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{bootstrap_key_material_with_params, unlock_dek_with_master};

    #[test]
    fn recovery_roundtrip_and_wrong_code() {
        let params = KdfParams::for_tests();
        let boot = bootstrap_key_material_with_params(b"master-ok", &params, true).expect("boot");
        let code = boot.recovery_code.expect("code");
        let dek = unlock_dek_with_recovery(&code, &boot.header).expect("recovery unlock");
        assert_eq!(dek.expose(), boot.dek.expose());
        assert!(matches!(
            unlock_dek_with_recovery("00".repeat(32).as_str(), &boot.header),
            Err(RecoveryError::InvalidCode)
        ));
        let via_master = unlock_dek_with_master(b"master-ok", &boot.header).unwrap();
        assert_eq!(via_master.expose(), boot.dek.expose());
    }

    #[test]
    fn design_summary_mentions_master_never_stored() {
        let kit = ProductionRecoveryKit;
        let text = kit.design_summary().to_lowercase();
        assert!(text.contains("nunca"));
        assert!(text.contains("maestra"));
    }

    #[test]
    fn rewrap_with_new_master_works() {
        let params = KdfParams::for_tests();
        let boot = bootstrap_key_material_with_params(b"old-master", &params, false).unwrap();
        let new_header = rewrap_dek_with_new_master(&boot.dek, b"new-master", &params).unwrap();
        let dek = unlock_dek_with_master(b"new-master", &new_header).unwrap();
        assert_eq!(dek.expose(), boot.dek.expose());
        assert!(unlock_dek_with_master(b"old-master", &new_header).is_err());
    }
}
