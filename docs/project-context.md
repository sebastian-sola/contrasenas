# Contexto de proyecto — Contraseñas

**Actualizado:** 2026-10-07 · Fase 1 (esqueleto)

## Qué es

Gestor de contraseñas/secretos de **escritorio local**, offline-first, con prioridad absoluta en seguridad, privacidad y trazabilidad. Pliego: `docs/requisitos.md` (§1–39).

## Objetivos durables

- Cifrar todo el almacén; master password nunca almacenada (ni de forma recuperable).
- Kit de emergencia: segunda vía para recuperar acceso a la bóveda si se olvida la master (ver `SECURITY.md`).
- Sin telemetría, sin red innecesaria, dependencias mínimas.
- Historial default = metadatos; auditoría cifrada sin secretos.
- Extensible a 2FA real / multi-bóveda / sync **sin** implementarlos ahora.
- Honestidad: sin claims “100 % seguro”; documentar límites (memoria, SSD, malware root).

## Prioridad de criterios

**Seguridad > Privacidad > Fiabilidad > Mantenibilidad > Usabilidad > Estética**

## Decisiones

| ID | Decisión | Estado |
|----|----------|--------|
| D1 | Stack: **Tauri 2 + Rust + React/TS** | **Aprobado** 2026-10-07 |
| D2 | Storage: **SQLCipher + AEAD de campos**; trait + fallback blob AEAD | **Aprobado** 2026-10-07 |
| D3 | Crypto: AES-256-GCM + Argon2id (params versionados) + DEK envuelta | Propuesta (Fase 2) |
| D4 | Recuperación: **kit de emergencia** (no solo pérdida total) | **Aprobado** 2026-10-07 |
| D5 | Plataforma: arquitectura multi-OS; **priorizar Windows** si hay que recortar | Propuesta |
| D6 | Auditoría MVP: AEAD/SQLCipher (A); schema listo para hash encadenado (B) | Propuesta |
| D7 | Historial de secretos opt-in: **no en MVP temprano** (Fase 7+ si se aprueba) | Propuesta |
| D8 | Keystore OS: solo auxiliar opt-in; **nunca** master recuperable | Propuesta |
| D9 | Backup: `.cpbak` con `backup_version`; passphrase = master en MVP | Propuesta |
| D10 | Reutilización UX: mostrar conteo N; no listar otros servicios si es disclosure innecesario | Aceptado del pliego |
| D11 | Comunicación con Sebastián: lenguaje sencillo, sin jerga | Preferencia de proyecto |

## No-objetivos (F0–F10)

Sync cloud, telemetría, 2FA simulado, breach-check online, extensión browser, recuperación online de master.

## Estado del trabajo

- **Fase 0** ✅ aprobada.
- **Fase 1** esqueleto Tauri + crates + UI placeholder (sin crypto de producción).
- **Siguiente:** Fase 2 (criptografía) tras aprobación explícita.

## Rutas canónicas (Agent Store)

- Índice: `docs/arquitectura-seguridad.md`
- Pack §28: `ARCHITECTURE`, `SECURITY`, `THREAT_MODEL`, `DATABASE`, `BACKUP`, `AUDIT`, `DEVELOPMENT`
- Espejo en repo Git: `/workspace/docs/*` + `README.md`
