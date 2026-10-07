# Índice Fase 0 — Arquitectura y seguridad

**Estado:** borrador completo para revisión de Sebastián  
**Regla:** sin código de producción hasta aprobación explícita → Fase 1

Los documentos canónicos detallados están en este Agent Store. El repo Git lleva el mismo conjunto bajo `docs/` para la PR.

---

## Presentación Fase 0 (mapa)

| # | Tema | Documento |
|---|------|-----------|
| 1 | Arquitectura propuesta | [ARCHITECTURE.md](./ARCHITECTURE.md) §1 |
| 2 | Stack recomendado (comparativa) | [ARCHITECTURE.md](./ARCHITECTURE.md) §2 |
| 3 | Diagrama de componentes | [ARCHITECTURE.md](./ARCHITECTURE.md) §3 |
| 4 | Modelo de datos | [DATABASE.md](./DATABASE.md) + [ARCHITECTURE.md](./ARCHITECTURE.md) §4 |
| 5 | Modelo criptográfico | [SECURITY.md](./SECURITY.md) §1 |
| 6 | Flujo de desbloqueo | [ARCHITECTURE.md](./ARCHITECTURE.md) §6 |
| 7 | Modelo de amenazas | [THREAT_MODEL.md](./THREAT_MODEL.md) |
| 8 | Estructura de directorios | [ARCHITECTURE.md](./ARCHITECTURE.md) §8 |
| 9 | Dependencias principales | [ARCHITECTURE.md](./ARCHITECTURE.md) §9 |
| 10 | Riesgos y decisiones pendientes | [ARCHITECTURE.md](./ARCHITECTURE.md) §10 + [project-context.md](./project-context.md) |

### Resto del paquete §28

| Doc | Contenido |
|-----|-----------|
| [SECURITY.md](./SECURITY.md) | Crypto, memoria, clipboard, OS keystores, OWASP, privacidad, checklist |
| [DATABASE.md](./DATABASE.md) | **Decisión: SQLCipher + AEAD campos** (vs blob / solo campos) |
| [BACKUP.md](./BACKUP.md) | Formato `.cpbak` con `backup_version` |
| [AUDIT.md](./AUDIT.md) | Eventos, cifrado, anti-tamper A/B/C |
| [DEVELOPMENT.md](./DEVELOPMENT.md) | Fases F0–F10 |
| [requisitos.md](./requisitos.md) | Pliego completo §1–39 |
| [project-context.md](./project-context.md) | Decisiones durables |

---

## Recomendación en una línea

**Tauri 2 + Rust (`vault-core`) + UI React/TypeScript; SQLCipher + AES-256-GCM de campos; Argon2id; 100 % offline.**

---

## Top decisiones que bloquean Fase 1

1. ¿Aprobar stack Tauri 2 + Rust + React/TS?  
2. ¿Aprobar SQLCipher + AEAD (con fallback blob si el build falla)?  
3. ¿Recuperación ante olvido de master: pérdida total vs kit de emergencia?  

(Ver lista completa en `ARCHITECTURE.md` §10 y `project-context.md`.)
