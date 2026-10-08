# Plan de desarrollo por fases — Contraseñas

**Estado:** Plan base F0–F10 ✅ completado · Futuro opcional solo con decisión explícita

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

## FASE 3 — Bóveda ✅

- Create / open / lock / unlock / close en disco.
- Backend **SQLCipher** (bundled) + AEAD de campos; clave DB = HKDF(DEK). Fallback blob disponible en trait.
- Cabecera pública `vault.header` (crypto + backoff + schema).
- Backoff progresivo; auto-lock default 5 min (`auto_lock_secs = 300`).
- Wipe DEK al lock/close; master nunca en claro en disco (test).
- Kit emergencia: `wrapped_dek_recovery` en cabecera; código solo al crear.
- Schema v1 + scaffolding de migración; copia preventiva a `backups/`.
- Permisos 0o700/0o600 en Unix.

**Gate:** ✅ tests create/open/lock, wrong master, tamper header, backoff, recovery, master not on disk.

---

## FASE 4 — Credenciales ✅

- CRUD campos §5 (servicio, usuario, password AEAD, URL, notas, caducidad, etc.).
- Schema SQLCipher v2 + soft-delete + historial solo metadatos (sin plaintext de passwords antiguas).
- Lista / detalle / crear-editar en UI; password oculta por defecto con show/hide.
- Colores de caducidad §12 (verde/amarillo/naranja/rojo) + campo `next_renewal_at`.
- Búsqueda/filtrado básico; reutilización: conteo N (fingerprint SHA-256) sin listar otros servicios.
- IPC Tauri: list/get/create/update/delete/restore/history.

**Gate:** ✅ test `crud_reuse_and_no_plaintext_on_disk`.  
**Capturas:** `media/fase4-lista.png`, `media/fase4-detalle.png`.

---

## FASE 5 — Políticas ✅

- Motor §8: min/max, upper/lower/digit/symbol, espacios, chars/patrones prohibidos, reuso de N anteriores (huellas), caducidad días, `extra_rules_json` extensible.
- Validación sin loguear plaintext; schema SQLCipher v3 (`policies` + `password_fp_history` + `policy_id`).
- CRUD UI Políticas; asociar política a credencial; badges cumple / no cumple.
- Capturas: `media/fase5-politicas.png`, `media/fase5-validacion.png`.

**Gate:** ✅ tests de reglas + CRUD/attach compliance; sin secretos en resultado de validación.

---

## FASE 6 — Generador ✅

- CSPRNG via `OsRng` (`rng: os_csprng`); nunca `Math.random` / RNG no cripto.
- Opciones §9: longitud, upper/lower/digit/symbol, evitar ambiguos, charset custom, exclusiones, generar desde política.
- UI Generador: muestra password, longitud, entropía bits, etiqueta §10 (Muy débil→Muy fuerte), cumplimiento de política.
- No autoguarda; botón «Usar en nueva credencial».
- Captura: `media/fase6-generador.png`.

**Gate:** ✅ tests CSPRNG / charset / política / fortaleza / debug redacted / no autosave.

---

## FASE 7 — Historial y auditoría ✅

- Historial de credencial: metadatos (cuándo, actor, acción, campos, motivo); **sin** plaintext de passwords antiguas.
- Auditoría SQLCipher v4 (`audit_events`): sequence + eventos §7 existentes; contexto allowlist; `prev_hash` columna lista (MVP = opción A).
- Unlock failure en cola pending → flush al desbloquear (sin material).
- UI pestaña Auditoría (filtros tipo/resultado/usuario/objeto) + historial en detalle.
- Capturas: `media/fase7-auditoria.png`, `media/fase7-historial.png`.

**Gate:** ✅ tests emiten eventos; secretos no aparecen; filtros.

---

## FASE 8 — Seguridad de sistema ✅ (esta entrega)

- Clipboard §14: copiar password → toast temporal → auto-clear tras 10/30/60 s o desactivado (default **30 s**). Límites OS documentados (historial del portapapeles).
- Configuración UI: auto-lock + clipboard timeout; avisos SSD / soft-delete.
- Backups cifrados `.cpbak` (`backup_version` = 1): crear, verificar integridad, restaurar con backup preventivo + confirmación; no borrar antiguos sin confirmación.
- Export plaintext **bloqueado** por defecto; import gestores externos = stub con confirmación obligatoria.
- Logging seguro: `redact_secrets` + tests de que secretos no aparecen.
- Eventos de auditoría: `clipboard_copy`, `backup_create` / `backup_restore`, `settings_change`, export/import intentos.
- Capturas: `media/fase8-configuracion.png`, `media/fase8-backup.png`.

**Gate:** ✅ tests clipboard/settings helpers, backup round-trip + integridad, plaintext export blocked, secrets no en logs.  
**Smoke:** `cargo test -p vault-core -p vault-storage -p vault-backup`  
**Siguiente:** Fase 9 hecha.

---

## FASE 9 — UI completa ✅ (esta entrega)

- Pantallas §13 pulidas con lenguaje visual coherente (marca Contraseñas, tipografía Fraunces/DM Sans, fondo atmosférico bosque/teal — sin clichés púrpura).
- Bloqueo / crear / abrir: hero de marca; sin datos de bóveda antes del unlock; textos en español sencillo.
- **Inicio (dashboard):** total, caducan pronto, caducadas, débiles/sin regla, reutilizadas, cambiadas (7 días).
- Contraseñas (lista + detalle + crear/editar), Reglas, Generador, Actividad, Ajustes — misma navegación.
- Estados vacío / carga / error; ventana redimensionable (mín. 720×520).
- Seguridad no se relaja por estética.
- Capturas: `media/fase9-bloqueo.png`, `media/fase9-dashboard.png`, `media/fase9-credenciales.png`.

**Gate:** ✅ app usable offline end-to-end en desktop; tests crates verdes.  
**Siguiente:** Fase 10 hecha.

---

## FASE 10 — Hardening y release engineering ✅ (esta entrega)

- SCA: `cargo audit` + `pnpm audit`; CI con audit + gitleaks (sin `continue-on-error`).
- Clippy `-D warnings` verde; tests de permisos Unix, master no en disco, redaction, sin clientes HTTP en `vault-core`.
- Revisión: permisos, logs, wipe al lock, IPC mínimo, data dir XDG (no temp por defecto), `Zeroizing` de master en IPC.
- Arquitectura de **firma de binarios** Windows/macOS/Linux documentada **sin certificados en el repo**.
- `docs/SECURITY_REVIEW.md`: controles, no implementado, riesgos, deps críticas, recomendaciones.
- README: notas de build/instalación local (no implica instalado en el PC de Sebastián).

**Gate:** ✅ candidata a uso local offline; sin sync/2FA. Plan base F0–F10 cerrado.  
**Posterior:** solo con OK explícito (firma real, 2FA, sync, etc.).

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
