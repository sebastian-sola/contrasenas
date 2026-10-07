# Plan de desarrollo por fases — Contraseñas

**Estado:** Fase 3 ✅ completada · **Fase 4 pendiente de aprobación**

Alineado con requisito §36. Prioridad: seguridad de secretos. Entre fases: checklist §37 + revisión de amenazas §39.

---

## Cultura de trabajo

- No inventar seguridad (§35); documentar dudas.
- Tests de crypto/auth **antes** de avanzar cuando la fase lo exija.
- Sin telemetría ni red en F0–F10 salvo decisión explícita posterior.
- Checklist de secretos antes de cada feature sensible.
- SCA, lockfiles, CI (lint/test/SCA/secret-scan) se introducen temprano (F1–F2) y se endurecen en F10.
- Code signing: preparado en arquitectura; certificados fuera del repo (fase distribución).

---

## FASE 0 — Análisis y diseño ✅

**Gate:** ✅ Aprobados D1 (Tauri), D2 (SQLCipher+AEAD), D4 (kit emergencia) — 2026-10-07.

---

## FASE 1 — Esqueleto de aplicación ✅

Esqueleto Tauri + crates stub + CI + pantalla bloqueo placeholder.

---

## FASE 2 — Criptografía ✅

Argon2id + AES-256-GCM + DEK wrap + kit crypto en memoria. Tests verdes.

---

## FASE 3 — Bóveda ✅ (esta entrega)

- Create / open / lock / unlock / close en disco.
- Backend **SQLCipher** (bundled) + AEAD de campos previsto; clave DB = HKDF(DEK). Fallback blob disponible en trait.
- Cabecera pública `vault.header` (crypto + backoff + schema).
- Backoff progresivo; auto-lock default 5 min (`auto_lock_secs = 300`).
- Wipe DEK al lock/close; master nunca en claro en disco (test).
- Kit emergencia: `wrapped_dek_recovery` en cabecera; código solo al crear.
- Schema v1 + scaffolding de migración; copia preventiva a `backups/`.
- Permisos 0o700/0o600 en Unix.

**Gate:** ✅ tests create/open/lock, wrong master, tamper header, backoff, recovery, master not on disk.  
**Smoke:** `cargo test -p vault-core -p vault-storage -p vault-backup`  
**Siguiente:** Fase 4 (CRUD credenciales) **solo tras aprobación explícita**.

---

## FASE 4 — Credenciales

- CRUD campos §5.
- Lista / detalle / crear-editar.
- Password oculta; show/hide; estados de caducidad + colores §12.
- Búsqueda/filtrado básico.
- Reutilización: conteo N sin disclosure innecesario.

**Gate:** tests CRUD; sin plaintext en DB locked.

---

## FASE 5 — Políticas

- Motor de políticas §8; validación; UI Políticas.
- Indicadores compliant / no.

**Gate:** tests de reglas.

---

## FASE 6 — Generador

- CSPRNG; opciones §9; fortaleza; cumplimiento de política.
- No autoguardar.

**Gate:** tests CSPRNG / charset; sin `Math.random`.

---

## FASE 7 — Historial y auditoría

- Historial metadatos default; opt-in secrets solo si aprobado.
- Auditoría cifrada + UI; opción A o B según decisión.
- Eventos §7.

**Gate:** tests “no secretos en audit/history default”.

---

## FASE 8 — Seguridad de sistema

- Clipboard auto-clear §14.
- Hardening IPC/CSP/paths.
- Keystore OS auxiliar solo si aprobado (nunca master recuperable).
- Logs seguros + tests de redaction.
- Borrado con confirmación + límites SSD documentados.

**Gate:** checklist OWASP desktop revisada.

---

## FASE 9 — UI completa

- Todas las pantallas §13 pulidas.
- Dashboard con avisos caducidad.
- Configuración (timeouts, clipboard, temas).
- UX de reutilización y fortaleza (zxcvbn offline opcional aquí o F6+).

**Gate:** usable end-to-end offline en plataforma prioritaria.

---

## FASE 10 — Hardening y release engineering

- SCA, Dependabot/Renovate, pipeline completo.
- Threat model actualizado; `docs/SECURITY_REVIEW.md`.
- Preparación firma/notarización (sin certs en repo).
- Instalador; tests de seguridad §26 ampliados.
- Revisión final §38 / §39.

**Gate:** candidata a release local; aún sin sync/2FA real salvo que se abra fase posterior.

---

## Posterior (solo diseño hasta entonces)

Multi-bóveda, multi-usuario rico, TOTP/WebAuthn/FIDO2/bio reales, sync, extensión browser, breach check offline/privacy-preserving, políticas corporativas, SSH/certs/API keys (§34).

---

## Dependencias entre fases

```
F0 → F1 → F2 → F3 → F4 ─┬→ F5 → F6
                        └→ F7
                              ↓
                         F8 → F9 → F10
```
