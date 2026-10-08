# Contraseñas

Aplicación de **escritorio** para guardar contraseñas y datos de acceso **solo en tu ordenador**.  
No envía datos a Internet. La seguridad va por delante de la comodidad.

## En qué punto estamos

**Plan base F0–F10 completado** (diseño → crypto → bóveda → credenciales → reglas → generador → auditoría → clipboard/backups → UI → hardening).

Revisión de seguridad: [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).  
**No se afirma “100 % seguro”.** Hay límites reales (memoria, SSD, malware).

> Todo el desarrollo está en la máquina del agente cloud / este repositorio. **Nada se ha instalado en el ordenador personal de Sebastián.** Instalar en un PC de usuario es un paso **futuro** (idealmente con binarios firmados).

## Qué se ha decidido (aprobado)

- Tecnología: Tauri 2 + Rust + React/TypeScript.
- Guardado: base cifrada (SQLCipher) más cifrado extra de los campos secretos.
- Si olvidas la contraseña maestra: **kit de emergencia** (código para guardar en papel). La contraseña maestra **nunca** se guarda de forma que se pueda leer después.

Detalle técnico: carpeta [`docs/`](docs/).

## Cómo probar en un entorno de desarrollo

Necesitas: Node 20+, pnpm, Rust estable. En Linux, dependencias gráficas de Tauri ([guía](https://tauri.app/start/prerequisites/)).

```bash
# Comprobaciones rápidas (sin ventana)
pnpm --dir apps/desktop install
cargo test -p vault-core -p vault-storage -p vault-backup
pnpm --dir apps/desktop exec tsc --noEmit
cargo clippy -p vault-core -p vault-storage -p vault-backup -- -D warnings
cargo audit   # opcional SCA
pnpm --dir apps/desktop audit
```

```bash
# App de escritorio (requiere deps gráficas)
pnpm --dir apps/desktop tauri dev
```

Datos locales: por defecto bajo `~/.local/share/contrasenas` (Linux) o `%APPDATA%\Contraseñas` (Windows).  
Puedes forzar otra ruta con `CONTRASENAS_DATA_DIR=/ruta/segura`.

## Notas de build / instalador (para más adelante)

Cuando se quiera empaquetar para un PC de usuario:

```bash
pnpm --dir apps/desktop tauri build
```

- Genera artefactos según el SO (AppImage/deb, MSI, dmg…).
- **Firma de código / notarización:** ver §5 de `docs/SECURITY_REVIEW.md`. Los certificados **no** van en el repo.
- Hasta que haya builds firmados, trata cualquier instalador como “solo para pruebas en máquina de confianza”.

## Estructura del proyecto

```
apps/desktop/          → interfaz + shell Tauri
crates/vault-core/     → sesión, crypto, bóveda, CRUD, ajustes
crates/vault-storage/  → SQLCipher + AEAD / fallback
crates/vault-backup/   → backups .cpbak
docs/                  → plan de seguridad, fases, SECURITY_REVIEW
```

## Documentación

| Documento | Para qué |
|-----------|----------|
| [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) | Revisión F10: controles, riesgos, firma |
| [docs/SECURITY.md](docs/SECURITY.md) | Cifrado, kit, límites |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Fases F0–F10 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Arquitectura |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Amenazas |
| [docs/project-context.md](docs/project-context.md) | Decisiones |

## Importante

- No hay telemetría.
- No subas nunca ficheros de bóveda, backups ni códigos de emergencia a Git.
- Features nuevas (2FA, sync, etc.) **solo con aprobación explícita**.
