//! Sumidero de auditoría — stub Fase 1 (sin persistencia ni secretos).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("auditoría no persistente en Fase 1")]
    NotImplemented,
}

/// Evento mínimo sin campos sensibles.
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
        // Fase 1: no-op seguro (no escribe a disco).
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_sink_accepts_events() {
        let sink = NullAuditSink;
        assert!(sink.record(AuditEventStub { kind: "app_start" }).is_ok());
    }
}
