# Contexto de proyecto — Contraseñas

**Actualizado:** 2026-10-07 · Fase 3 (bóveda en disco)

## Qué es

Gestor de contraseñas/secretos de **escritorio local**, offline-first, con prioridad absoluta en seguridad, privacidad y trazabilidad. Pliego: `docs/requisitos.md` (§1–39).

## Objetivos durables

- Cifrar todo el almacén; master password nunca almacenada (ni de forma recuperable).
- Kit de emergencia: wrap de DEK en cabecera; código mostrado una vez al crear.
- Sin telemetría, sin red innecesaria, dependencias mínimas.
- Historial default = metadatos; auditoría cifrada sin secretos.
- Honestidad: sin claims “100 % seguro”; documentar límites (memoria, SSD, malware root).

## Prioridad de criterios

**Seguridad > Privacidad > Fiabilidad > Mantenibilidad > Usabilidad > Estética**

## Decisiones

| ID | Decisión | Estado |
|----|----------|--------|
| D1 | Stack: **Tauri 2 + Rust + React/TS** | **Aprobado** |
| D2 | Storage: **SQLCipher + AEAD**; fallback blob | **Aprobado + implementado F3** (SQLCipher activo) |
| D3 | Crypto: AES-256-GCM + Argon2id + DEK | **Implementado** F2 |
| D4 | Kit de emergencia | **Aprobado + persistencia wrap F3** |
| D5–D9 | Plataforma / auditoría / historial / keystore / backup passphrase | Propuestas |

## Estado del trabajo

- **Fases 0–3** ✅.
- **Siguiente:** Fase 4 (CRUD credenciales) **tras aprobación explícita**.

## Rutas canónicas

- Store: `docs/*` · Repo espejo: `/workspace/docs/*` + `README.md`
