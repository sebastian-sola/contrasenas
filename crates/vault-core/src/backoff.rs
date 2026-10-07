//! Backoff progresivo ante desbloqueos fallidos (público en cabecera).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Estado persistido en la cabecera pública (sin secretos).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackoffState {
    pub consecutive_failures: u32,
    /// Epoch millis; None = se puede intentar ya.
    pub next_attempt_after_unix_ms: Option<u64>,
}

impl BackoffState {
    pub fn delay_secs_for_failures(failures: u32) -> u64 {
        match failures {
            0..=2 => 0,
            3 => 2,
            4 => 5,
            5 => 15,
            6 => 30,
            _ => 60,
        }
    }

    pub fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// `Ok(())` si se permite el intento; `Err(secs_restantes)` si hay que esperar.
    pub fn check_allowed(&self) -> Result<(), u64> {
        let Some(next) = self.next_attempt_after_unix_ms else {
            return Ok(());
        };
        let now = Self::now_unix_ms();
        if now >= next {
            Ok(())
        } else {
            Err((next - now).div_ceil(1000))
        }
    }

    pub fn register_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let delay = Self::delay_secs_for_failures(self.consecutive_failures);
        if delay == 0 {
            self.next_attempt_after_unix_ms = None;
        } else {
            self.next_attempt_after_unix_ms = Some(Self::now_unix_ms() + delay * 1000);
        }
    }

    pub fn register_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_attempt_after_unix_ms = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progressive_delays() {
        assert_eq!(BackoffState::delay_secs_for_failures(1), 0);
        assert_eq!(BackoffState::delay_secs_for_failures(3), 2);
        assert_eq!(BackoffState::delay_secs_for_failures(7), 60);
    }
}
