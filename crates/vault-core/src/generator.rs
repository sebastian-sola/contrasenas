//! Generador CSPRNG de contraseñas (Fase 6) — requisitos §9 / §10.

use crate::policy::{validate_password, PasswordPolicy, PolicyValidation};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:,.?/~";
const AMBIGUOUS: &str = "0Ool1I|";

/// Identificador estable del RNG usado (solo CSPRNG del SO).
pub const GENERATOR_RNG_ID: &str = "os_csprng";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("longitud inválida")]
    InvalidLength,
    #[error("charset vacío tras exclusiones")]
    EmptyCharset,
    #[error("no se pudo cumplir la política tras varios intentos")]
    PolicyUnsatisfiable,
    #[error("fallo del generador seguro del sistema")]
    OsRngFailed,
}

/// Opciones de generación (§9).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorOptions {
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    /// Si no vacío, sustituye las clases anteriores (tras exclusiones / ambiguous).
    pub custom_charset: Option<String>,
    /// Caracteres a excluir del charset final.
    pub exclude: String,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
            custom_charset: None,
            exclude: String::new(),
        }
    }
}

/// Resultado mostrado en UI (no se guarda solo).
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
    pub length: u32,
    pub entropy_bits: f64,
    /// Muy débil | Débil | Media | Fuerte | Muy fuerte
    pub strength_label: String,
    pub charset_size: u32,
    pub policy_compliant: Option<bool>,
    pub policy_violations: Vec<String>,
    /// Siempre `os_csprng` — nunca Math.random / thread_rng no documentado.
    pub rng: String,
}

impl std::fmt::Debug for GeneratedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedPassword")
            .field("password", &"[redacted]")
            .field("length", &self.length)
            .field("entropy_bits", &self.entropy_bits)
            .field("strength_label", &self.strength_label)
            .field("charset_size", &self.charset_size)
            .field("policy_compliant", &self.policy_compliant)
            .field("policy_violations", &self.policy_violations)
            .field("rng", &self.rng)
            .finish()
    }
}

/// Construye charset según opciones.
pub fn build_charset(opts: &GeneratorOptions) -> Result<Vec<char>, GeneratorError> {
    let mut set: Vec<char> = if let Some(custom) = &opts.custom_charset {
        let t = custom.trim();
        if t.is_empty() {
            return Err(GeneratorError::EmptyCharset);
        }
        t.chars().collect()
    } else {
        let mut s = String::new();
        if opts.lowercase {
            s.push_str(LOWER);
        }
        if opts.uppercase {
            s.push_str(UPPER);
        }
        if opts.digits {
            s.push_str(DIGITS);
        }
        if opts.symbols {
            s.push_str(SYMBOLS);
        }
        if s.is_empty() {
            return Err(GeneratorError::EmptyCharset);
        }
        s.chars().collect()
    };

    if opts.avoid_ambiguous {
        set.retain(|c| !AMBIGUOUS.contains(*c));
    }
    if !opts.exclude.is_empty() {
        set.retain(|c| !opts.exclude.contains(*c));
    }

    // Dedup preservando orden
    let mut seen = std::collections::HashSet::new();
    set.retain(|c| seen.insert(*c));

    if set.is_empty() {
        return Err(GeneratorError::EmptyCharset);
    }
    Ok(set)
}

/// Estimación de fortaleza por entropía aproximada: `len * log2(charset)`.
/// No usa heurística ingenua «tiene mayúscula+dígito = fuerte».
pub fn estimate_strength(length: u32, charset_size: u32) -> (f64, String) {
    if length == 0 || charset_size < 2 {
        return (0.0, "Muy débil".into());
    }
    let bits = f64::from(length) * (f64::from(charset_size)).log2();
    let label = if bits < 28.0 {
        "Muy débil"
    } else if bits < 36.0 {
        "Débil"
    } else if bits < 60.0 {
        "Media"
    } else if bits < 128.0 {
        "Fuerte"
    } else {
        "Muy fuerte"
    };
    (bits, label.into())
}

fn secure_index(max: usize) -> Result<usize, GeneratorError> {
    if max == 0 {
        return Err(GeneratorError::EmptyCharset);
    }
    // Rejection sampling para evitar sesgo de módulo.
    let max_u = max as u32;
    let zone = u32::MAX - (u32::MAX % max_u);
    loop {
        let mut buf = [0u8; 4];
        OsRng
            .try_fill_bytes(&mut buf)
            .map_err(|_| GeneratorError::OsRngFailed)?;
        let v = u32::from_le_bytes(buf);
        if v < zone {
            return Ok((v % max_u) as usize);
        }
    }
}

fn pick_char(charset: &[char]) -> Result<char, GeneratorError> {
    let i = secure_index(charset.len())?;
    Ok(charset[i])
}

fn class_pool(opts: &GeneratorOptions, class: &str) -> Vec<char> {
    let mut v: Vec<char> = class.chars().collect();
    if opts.avoid_ambiguous {
        v.retain(|c| !AMBIGUOUS.contains(*c));
    }
    if !opts.exclude.is_empty() {
        v.retain(|c| !opts.exclude.contains(*c));
    }
    v
}

/// Genera una contraseña con OsRng. No persiste nada.
pub fn generate(opts: &GeneratorOptions) -> Result<GeneratedPassword, GeneratorError> {
    if !(4..=256).contains(&opts.length) {
        return Err(GeneratorError::InvalidLength);
    }
    let charset = build_charset(opts)?;
    let len = opts.length as usize;

    let mut chars: Vec<char> = Vec::with_capacity(len);

    // Garantizar al menos un carácter de cada clase pedida (si el charset lo permite).
    if opts.custom_charset.is_none() {
        let mut required: Vec<Vec<char>> = Vec::new();
        if opts.lowercase {
            let p = class_pool(opts, LOWER);
            if !p.is_empty() {
                required.push(p);
            }
        }
        if opts.uppercase {
            let p = class_pool(opts, UPPER);
            if !p.is_empty() {
                required.push(p);
            }
        }
        if opts.digits {
            let p = class_pool(opts, DIGITS);
            if !p.is_empty() {
                required.push(p);
            }
        }
        if opts.symbols {
            let p = class_pool(opts, SYMBOLS);
            if !p.is_empty() {
                required.push(p);
            }
        }
        if required.len() > len {
            return Err(GeneratorError::InvalidLength);
        }
        for pool in required {
            chars.push(pick_char(&pool)?);
        }
    }

    while chars.len() < len {
        chars.push(pick_char(&charset)?);
    }

    // Mezcla Fisher–Yates con OsRng
    for i in (1..chars.len()).rev() {
        let j = secure_index(i + 1)?;
        chars.swap(i, j);
    }

    let password: String = chars.into_iter().collect();
    let (entropy_bits, strength_label) = estimate_strength(opts.length, charset.len() as u32);

    Ok(GeneratedPassword {
        password,
        length: opts.length,
        entropy_bits,
        strength_label,
        charset_size: charset.len() as u32,
        policy_compliant: None,
        policy_violations: Vec::new(),
        rng: GENERATOR_RNG_ID.into(),
    })
}

/// Deriva opciones desde una política (§9 generación basada en política).
pub fn options_from_policy(
    policy: &PasswordPolicy,
    length_override: Option<u32>,
) -> GeneratorOptions {
    let min_l = policy.min_length.max(8);
    let max_l = policy.max_length.max(min_l);
    let target = length_override
        .unwrap_or_else(|| min_l.max(16).min(max_l))
        .clamp(min_l, max_l);

    GeneratorOptions {
        length: target,
        uppercase: policy.require_uppercase || !policy.require_lowercase,
        lowercase: policy.require_lowercase || !policy.require_uppercase,
        digits: policy.require_digit,
        symbols: policy.require_symbol,
        avoid_ambiguous: true,
        custom_charset: None,
        exclude: policy.forbidden_chars.clone(),
    }
}

/// Genera hasta cumplir la política (reintentos CSPRNG; no loguea secretos).
pub fn generate_for_policy(
    policy: &PasswordPolicy,
    length_override: Option<u32>,
    previous_fps: &[String],
) -> Result<(GeneratedPassword, PolicyValidation), GeneratorError> {
    let mut opts = options_from_policy(policy, length_override);
    // Asegurar clases exigidas
    if policy.require_uppercase {
        opts.uppercase = true;
    }
    if policy.require_lowercase {
        opts.lowercase = true;
    }
    if policy.require_digit {
        opts.digits = true;
    }
    if policy.require_symbol {
        opts.symbols = true;
    }
    if !policy.allow_spaces {
        // charset por defecto no incluye espacios
    }

    for _ in 0..64 {
        let mut gen = generate(&opts)?;
        // Filtrar patrones prohibidos: reintentar si aparece
        let mut bad_pattern = false;
        for pat in &policy.forbidden_patterns {
            if !pat.is_empty() && gen.password.contains(pat.as_str()) {
                bad_pattern = true;
                break;
            }
        }
        if bad_pattern {
            continue;
        }
        let validation = validate_password(&gen.password, policy, previous_fps);
        gen.policy_compliant = Some(validation.compliant);
        gen.policy_violations = validation.violations.clone();
        if validation.compliant {
            return Ok((gen, validation));
        }
    }
    Err(GeneratorError::PolicyUnsatisfiable)
}

impl crate::vault::Vault {
    /// Genera sin persistir. Opcionalmente valida / fuerza política.
    pub fn generate_password(
        &mut self,
        opts: GeneratorOptions,
        policy_id: Option<&str>,
        credential_id: Option<&str>,
    ) -> Result<GeneratedPassword, crate::vault::VaultError> {
        if self.state() != crate::session::SessionState::Unlocked {
            return Err(crate::vault::VaultError::Locked);
        }
        self.touch_activity();

        if let Some(pid) = policy_id {
            let policy = self.get_policy(pid)?;
            let previous = if policy.previous_password_count > 0 {
                if let Some(cid) = credential_id {
                    let db = self.db_mut()?;
                    db.list_password_fp_history(cid, policy.previous_password_count)?
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            let (gen, _) = generate_for_policy(&policy, Some(opts.length), &previous)
                .map_err(|_| crate::vault::VaultError::Storage)?;
            Ok(gen)
        } else {
            generate(&opts).map_err(|_| crate::vault::VaultError::Storage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::policy::PolicyInput;
    use crate::vault::Vault;
    use tempfile::tempdir;

    #[test]
    fn uses_os_csprng_id_and_varies() {
        let opts = GeneratorOptions::default();
        let a = generate(&opts).unwrap();
        let b = generate(&opts).unwrap();
        assert_eq!(a.rng, GENERATOR_RNG_ID);
        assert_eq!(b.rng, GENERATOR_RNG_ID);
        assert_ne!(a.password, b.password);
        assert_eq!(a.length, 20);
    }

    #[test]
    fn respects_charset_flags_and_exclusions() {
        let opts = GeneratorOptions {
            length: 24,
            uppercase: true,
            lowercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: true,
            custom_charset: None,
            exclude: "A".into(),
        };
        let g = generate(&opts).unwrap();
        assert!(!g.password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(!g.password.contains('A'));
        assert!(!g.password.contains('0')); // ambiguous avoided
        assert!(!g.password.contains('O'));
    }

    #[test]
    fn strength_is_entropy_based_not_naive() {
        // Charset pequeño + corto → débil aunque tenga “clases”
        let (bits_short, label_short) = estimate_strength(8, 10);
        assert!(bits_short < 36.0);
        assert!(label_short == "Muy débil" || label_short == "Débil");

        let (bits_long, label_long) = estimate_strength(20, 70);
        assert!(bits_long > 60.0);
        assert!(label_long == "Fuerte" || label_long == "Muy fuerte");

        // Misma longitud: charset mayor → más fuerte (no “tiene dígito = fuerte”)
        let (b1, _) = estimate_strength(16, 26);
        let (b2, _) = estimate_strength(16, 70);
        assert!(b2 > b1);
    }

    #[test]
    fn debug_redacts_password() {
        let g = generate(&GeneratorOptions::default()).unwrap();
        let dump = format!("{g:?}");
        assert!(dump.contains("[redacted]"));
        assert!(!dump.contains(&g.password));
    }

    #[test]
    fn policy_based_generation_is_compliant() {
        let dir = tempdir().unwrap();
        let mut v = Vault::new(AppPaths::from_data_dir(dir.path().to_path_buf()));
        v.create(b"gen-master-fase6", false).unwrap();
        v.unlock_with_master(b"gen-master-fase6").unwrap();
        let pol = v
            .create_policy(PolicyInput {
                name: "GenPol".into(),
                min_length: 14,
                max_length: 40,
                require_uppercase: true,
                require_lowercase: true,
                require_digit: true,
                require_symbol: true,
                allow_spaces: false,
                forbidden_chars: String::new(),
                forbidden_patterns: vec!["password".into()],
                previous_password_count: 0,
                expiry_days: Some(90),
                extra_rules_json: None,
            })
            .unwrap();

        let opts = GeneratorOptions {
            length: 16,
            ..GeneratorOptions::default()
        };
        let g = v.generate_password(opts, Some(&pol.id), None).unwrap();
        assert_eq!(g.policy_compliant, Some(true));
        assert!(g.violations_empty());
        assert!(g.length >= 14);
        assert_eq!(g.rng, GENERATOR_RNG_ID);
    }

    impl GeneratedPassword {
        fn violations_empty(&self) -> bool {
            self.policy_violations.is_empty()
        }
    }

    #[test]
    fn does_not_autosave() {
        let dir = tempdir().unwrap();
        let mut v = Vault::new(AppPaths::from_data_dir(dir.path().to_path_buf()));
        v.create(b"gen-master-fase6b", false).unwrap();
        v.unlock_with_master(b"gen-master-fase6b").unwrap();
        let before = v.list_credentials(None).unwrap().len();
        let _ = v
            .generate_password(GeneratorOptions::default(), None, None)
            .unwrap();
        let after = v.list_credentials(None).unwrap().len();
        assert_eq!(before, after);
    }
}
