# Contexto de proyecto — Contraseñas

**Actualizado:** 2026-10-08 · Plan base F0–F10 ✅ completado

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
| D2 | Storage: **SQLCipher + AEAD**; fallback blob | **Aprobado + implementado** |
| D3 | Crypto: AES-256-GCM + Argon2id + DEK | **Implementado** |
| D4 | Kit de emergencia | **Aprobado + persistido** |
| D6 | Auditoría MVP = SQLCipher + sequence (opción A); `prev_hash` schema-ready | **Implementado** |
| D5, D7–D9 | Plataforma / historial secrets opt-in / keystore / backup passphrase | Abiertas / futuras |

## Estado del trabajo

- **Fases 0–10 (plan base)** ✅ completadas en la VM/repo del agente.
- Revisión de seguridad: `docs/SECURITY_REVIEW.md`.
- **Nada instalado en el PC personal de Sebastián.**
- Features futuras (firma real de instaladores, 2FA, sync, etc.): **solo si se piden explícitamente**.

## Rutas canónicas

- Store: `docs/*` · Repo espejo: `/workspace/docs/*` + `README.md`
