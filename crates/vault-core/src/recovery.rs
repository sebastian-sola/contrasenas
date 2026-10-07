//! Kit de emergencia — diseño D4 aprobado; **stubs Fase 1**.
//!
//! La contraseña maestra **nunca** se almacena de forma recuperable.
//! El kit es una segunda vía para desenvolver la DEK (implementación en Fase 2+).
//! Ver `docs/SECURITY.md` §2.1.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("kit de emergencia no implementado en Fase 1")]
    NotImplemented,
}

/// Contrato del kit de emergencia (sin generar ni persistir material real aún).
pub trait RecoveryKit: Send + Sync {
    /// Descripción estable del diseño para UI/docs (sin secretos).
    fn design_summary(&self) -> &'static str;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StubRecoveryKit;

impl RecoveryKit for StubRecoveryKit {
    fn design_summary(&self) -> &'static str {
        "Kit de emergencia: código de alta entropía que envuelve la DEK por separado; \
         la contraseña maestra nunca se guarda. Implementación crypto en Fase 2+."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_mentions_master_never_stored() {
        let kit = StubRecoveryKit;
        let text = kit.design_summary().to_lowercase();
        assert!(text.contains("nunca") || text.contains("never") || text.contains("maestra"));
    }
}
