//! Logging seguro — nunca incluir secretos (§24).

/// Redacta ocurrencias exactas de secretos conocidos en un mensaje de log.
pub fn redact_secrets(message: &str, secrets: &[&str]) -> String {
    let mut out = message.to_string();
    for s in secrets {
        if s.is_empty() {
            continue;
        }
        out = out.replace(*s, "[REDACTED]");
    }
    out
}

/// Devuelve true si el haystack contiene alguno de los secretos (para tests).
pub fn contains_any_secret(haystack: &str, secrets: &[&str]) -> bool {
    secrets.iter().any(|s| !s.is_empty() && haystack.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_and_detects_secrets() {
        let secret = "SuperSecretLogValue-9988";
        let msg = format!("error while unlocking with {secret} near end");
        assert!(contains_any_secret(&msg, &[secret]));
        let safe = redact_secrets(&msg, &[secret]);
        assert!(!contains_any_secret(&safe, &[secret]));
        assert!(safe.contains("[REDACTED]"));
    }
}
