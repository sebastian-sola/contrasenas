# Contraseñas

Aplicación de **escritorio** para guardar contraseñas y datos de acceso **solo en tu ordenador**.  
No envía datos a Internet. La seguridad va por delante de la comodidad.

## En qué punto estamos

**Fase 2 — criptografía.** Ya existe el “candado” interno (cifrado moderno, pruebas automáticas).  
**Todavía no** se crean bóvedas guardadas en el disco ni se almacenan tus contraseñas de sitios.

La siguiente etapa (Fase 3) será guardar la bóveda en el ordenador, y **solo empezará cuando Sebastián lo apruebe**.

## Qué se ha decidido (aprobado)

- Tecnología: Tauri 2 + Rust + React/TypeScript.
- Guardado: base cifrada (SQLCipher) más cifrado extra de los campos secretos.
- Si olvidas la contraseña maestra: habrá un **kit de emergencia** (un código para guardar en papel / lugar seguro). La contraseña maestra **nunca** se guarda de forma que se pueda leer después.

Detalle técnico: carpeta [`docs/`](docs/).

## Cómo probar el esqueleto (para quien prepare el entorno)

Necesitas: Node 20+, pnpm, Rust estable. En Linux, para la ventana de escritorio completa, también las dependencias gráficas de Tauri ([guía](https://tauri.app/start/prerequisites/)).

```bash
# Comprobaciones rápidas (sin abrir la ventana gráfica)
pnpm --dir apps/desktop install
pnpm smoke
# equivalente: cargo test de los crates + typecheck del frontend
```

```bash
# Vista previa solo del interfaz en el navegador (sin Tauri)
pnpm --dir apps/desktop dev
```

```bash
# App de escritorio completa (requiere deps gráficas del sistema)
pnpm --dir apps/desktop tauri dev
```

> En Linux hace falta instalar las libs gráficas de Tauri (p. ej. `libwebkit2gtk-4.1-dev`, `librsvg2-dev`, … — ver [prerequisites](https://tauri.app/start/prerequisites/)). Sin ellas, `tauri dev` falla; igual puedes validar con `pnpm smoke` (tests Rust + typecheck web). En este agente ya se comprobó `cargo check -p contrasenas-desktop` tras instalar esas deps.

## Estructura del proyecto

```
apps/desktop/          → interfaz + shell Tauri
crates/vault-core/     → sesión, crypto (stubs), kit emergencia (stubs)
crates/vault-storage/  → almacén (stubs SQLCipher / fallback)
crates/vault-backup/   → backups (stubs)
docs/                  → plan de seguridad y fases
```

## Documentación

| Documento | Para qué |
|-----------|----------|
| [docs/arquitectura-seguridad.md](docs/arquitectura-seguridad.md) | Índice del plan |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Arquitectura y stack |
| [docs/SECURITY.md](docs/SECURITY.md) | Cifrado, kit de emergencia, límites |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Amenazas |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Fases F0–F10 |
| [docs/project-context.md](docs/project-context.md) | Decisiones del proyecto |

## Importante

- No hay telemetría.
- No subas nunca ficheros de bóveda, backups ni códigos de emergencia a Git.
- Fase 3 (bóveda en disco) **pendiente de aprobación**.
- Comprobar crypto: `cargo test -p vault-core`
