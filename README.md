# Contraseñas

Aplicación de **escritorio** para guardar contraseñas y datos de acceso **solo en tu ordenador**.  
No envía datos a Internet. La seguridad va por delante de la comodidad.

## En qué punto estamos

**Fase 5 — políticas.** Además de guardar contraseñas, puedes **definir reglas** (longitud, mayúsculas, símbolos…) por servicio y ver si cada clave **cumple o no**.

La siguiente etapa (Fase 6 — generador de contraseñas) **solo empezará cuando Sebastián lo apruebe**.

> Todo el desarrollo hasta ahora está en la máquina del agente cloud / este repositorio. **Nada se ha instalado en el ordenador personal de Sebastián.**

## Qué se ha decidido (aprobado)

- Tecnología: Tauri 2 + Rust + React/TypeScript.
- Guardado: base cifrada (SQLCipher) más cifrado extra de los campos secretos.
- Si olvidas la contraseña maestra: habrá un **kit de emergencia** (un código para guardar en papel / lugar seguro). La contraseña maestra **nunca** se guarda de forma que se pueda leer después.

Detalle técnico: carpeta [`docs/`](docs/).

## Cómo probar (para quien prepare el entorno)

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
crates/vault-core/     → sesión, crypto, bóveda, CRUD credenciales
crates/vault-storage/  → SQLCipher + AEAD / fallback
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
- Fase 6 (generador) **pendiente de aprobación**.
- Comprobar bóveda + CRUD: `cargo test -p vault-core -p vault-storage -p vault-backup`
