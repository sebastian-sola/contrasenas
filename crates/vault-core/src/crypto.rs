//! Motor criptográfico — **stubs Fase 1**.
//!
//! La implementación real (Argon2id, AES-256-GCM, zeroize) llega en Fase 2.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("operación crypto no implementada en Fase 1")]
    NotImplemented,
}

/// Contrato del motor crypto. Sin material secreto real en esta fase.
pub trait CryptoEngine: Send + Sync {
    fn algorithm_id(&self) -> &'static str;
}

/// Stub que declara la intención sin realizar KDF ni AEAD.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubCryptoEngine;

impl CryptoEngine for StubCryptoEngine {
    fn algorithm_id(&self) -> &'static str {
        "stub-phase1-no-production-crypto"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_engine_identifies_itself() {
        let engine = StubCryptoEngine;
        assert!(engine.algorithm_id().contains("stub"));
    }
}
