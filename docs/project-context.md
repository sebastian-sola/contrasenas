# Contexto de proyecto — Contraseñas

**Actualizado:** 2026-10-07 · Fase 0 (solo diseño)

## Qué es

Gestor de contraseñas/secretos de **escritorio local**, offline-first, con prioridad absoluta en seguridad, privacidad y trazabilidad. Pliego: `docs/requisitos.md` (§1–39).

## Objetivos durables

- Cifrar todo el almacén; master password nunca almacenada.
- Sin telemetría, sin red innecesaria, dependencias mínimas.
- Historial default = metadatos; auditoría cifrada sin secretos.
- Extensible a 2FA real / multi-bóveda / sync **sin** implementarlos ahora.
- Honestidad: sin claims “100 % seguro”; documentar límites (memoria, SSD, malware root).

## Prioridad de criterios

**Seguridad > Privacidad > Fiabilidad > Mantenibilidad > Usabilidad > Estética**

## Decisiones propuestas (pendientes de aprobación)

| ID | Decisión | Estado |
|----|----------|--------|
| D1 | Stack: **Tauri 2 + Rust + React/TS** | Propuesta |
| D2 | Storage: **SQLCipher + AEAD de campos**; trait + fallback blob AEAD | Propuesta |
| D3 | Crypto: AES-256-GCM + Argon2id (params versionados) + DEK envuelta | Propuesta |
| D4 | Recuperación master: **sin kit** (pérdida total) salvo que se pida | Propuesta default |
| D5 | Plataforma: arquitectura multi-OS; **priorizar Windows** si hay que recortar | Propuesta |
| D6 | Auditoría MVP: AEAD/SQLCipher (A); schema listo para hash encadenado (B) | Propuesta |
| D7 | Historial de secretos opt-in: **no en MVP temprano** (Fase 7+ si se aprueba) | Propuesta |
| D8 | Keystore OS: solo auxiliar opt-in; **nunca** master recuperable | Propuesta |
| D9 | Backup: `.cpbak` con `backup_version`; passphrase = master en MVP | Propuesta |
| D10 | Reutilización UX: mostrar conteo N; no listar otros servicios si es disclosure innecesario | Aceptado del pliego |

## No-objetivos (F0–F10)

Sync cloud, telemetría, 2FA simulado, breach-check online, extensión browser, recuperación online de master.

## Estado del trabajo

- **Fase 0** documentación lista para revisión.
- **Prohibido** código de producción hasta aprobación → Fase 1 (`DEVELOPMENT.md`).

## Rutas canónicas (Agent Store)

- Índice: `docs/arquitectura-seguridad.md`
- Pack §28: `ARCHITECTURE`, `SECURITY`, `THREAT_MODEL`, `DATABASE`, `BACKUP`, `AUDIT`, `DEVELOPMENT`
- Espejo en repo Git: `/workspace/docs/*` + `README.md`
