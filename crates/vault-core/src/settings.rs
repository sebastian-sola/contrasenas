//! Ajustes de seguridad de sistema (Fase 8).

use crate::vault::VaultError;
use serde::{Deserialize, Serialize};

pub const SETTING_AUTO_LOCK_SECS: &str = "auto_lock_secs";
pub const SETTING_CLIPBOARD_CLEAR_SECS: &str = "clipboard_clear_secs";

/// Valores permitidos de auto-borrado de portapapeles: 10, 30, 60, 0=off.
pub fn normalize_clipboard_secs(secs: u64) -> u64 {
    match secs {
        0 => 0,
        1..=15 => 10,
        16..=45 => 30,
        _ => 60,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub auto_lock_secs: u64,
    /// 0 = desactivado; 10 / 30 / 60.
    pub clipboard_clear_secs: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_lock_secs: 300,
            clipboard_clear_secs: 30,
        }
    }
}

impl crate::vault::Vault {
    pub fn get_settings(&mut self) -> Result<AppSettings, VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(VaultError::Locked);
        }
        self.touch_activity();
        let header_auto = self
            .header()
            .map(|h| h.auto_lock_secs)
            .unwrap_or(300);
        let db = self.db_mut()?;
        let auto = db
            .get_setting(SETTING_AUTO_LOCK_SECS)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(header_auto);
        let clip = db
            .get_setting(SETTING_CLIPBOARD_CLEAR_SECS)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Ok(AppSettings {
            auto_lock_secs: auto,
            clipboard_clear_secs: normalize_clipboard_secs(clip),
        })
    }

    pub fn update_settings(&mut self, settings: AppSettings) -> Result<AppSettings, VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(VaultError::Locked);
        }
        let clip = normalize_clipboard_secs(settings.clipboard_clear_secs);
        let auto = settings.auto_lock_secs; // 0 = nunca
        {
            let db = self.db_mut()?;
            db.set_setting(SETTING_AUTO_LOCK_SECS, &auto.to_string())?;
            db.set_setting(SETTING_CLIPBOARD_CLEAR_SECS, &clip.to_string())?;
        }
        self.set_auto_lock_secs_persist(auto)?;
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "action".into(),
            serde_json::Value::String("settings_change".into()),
        );
        let _ = self.audit_record("settings_change", "success", None, ctx);
        Ok(AppSettings {
            auto_lock_secs: auto,
            clipboard_clear_secs: clip,
        })
    }
}
