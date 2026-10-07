# Contraseñas

Gestor de contraseñas y secretos de **escritorio local**, offline-first. Seguridad y privacidad por encima de la comodidad.

> **Fase 0 (actual):** solo análisis y diseño. **No hay código de aplicación todavía.**  
> Hay que aprobar el plan antes de la Fase 1 (esqueleto).

## Stack propuesto

**Tauri 2 + núcleo criptográfico/bóveda en Rust + UI React/TypeScript**  
Almacén: **SQLCipher + AES-256-GCM en campos sensibles**, KDF **Argon2id**.

Detalle y comparativa (Electron / nativo / Python+Qt): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Documentación Fase 0

| Documento | Contenido |
|-----------|-----------|
| [`docs/arquitectura-seguridad.md`](docs/arquitectura-seguridad.md) | Índice de la presentación Fase 0 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Arquitectura, stack, diagramas, flujos, deps, riesgos |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Modelo de amenazas |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Modelo criptográfico, hardening, clipboard, OS keystores |
| [`docs/DATABASE.md`](docs/DATABASE.md) | Decisión SQLCipher vs cifrado de campos |
| [`docs/BACKUP.md`](docs/BACKUP.md) | Backups cifrados versionados (`backup_version`) |
| [`docs/AUDIT.md`](docs/AUDIT.md) | Auditoría cifrada y anti-manipulación |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Plan F0–F10 |
| [`docs/project-context.md`](docs/project-context.md) | Decisiones durables |
| [`docs/requisitos.md`](docs/requisitos.md) | Pliego §1–39 |

Los mismos documentos viven como canónicos en el Agent Store del proyecto; este repo es el espejo para revisión en PR.

## Principios

- Sin telemetría ni red en el diseño base.
- Contraseña maestra nunca almacenada (tampoco en keystores OS de forma recuperable).
- Historial por defecto = solo metadatos.
- Sin afirmaciones de “100 % seguro”.

## Próximo paso

Revisar decisiones abiertas en `docs/ARCHITECTURE.md` §10 y aprobar → **Fase 1**.

No ejecutar la app aún: no hay binario que arrancar en esta fase.
