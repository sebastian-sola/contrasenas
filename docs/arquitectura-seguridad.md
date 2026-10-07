# Índice Fase 0 — Arquitectura y seguridad

**Estado:** Fases 0–4 ✅ · **Fase 5 (políticas) pendiente de aprobación**  
**Regla:** no iniciar Fase 5 sin aprobación explícita

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

## Stack (aprobado)

**Tauri 2 + Rust (`vault-core`) + UI React/TypeScript; SQLCipher + AES-256-GCM de campos; Argon2id; kit de emergencia; 100 % offline.**

---

## Gate actual

**Fase 4 hecha** (CRUD credenciales cifradas). **No iniciar Fase 5** sin aprobación de Sebastián.

Pendientes: D5 plataforma, D6 auditoría, D7 historial secrets, D8 keystore, D9 passphrase backup.
