# Revisión de seguridad — Contraseñas (FASE 10)

**Fecha:** 2026-10-08  
**Alcance:** plan base F0–F10 (escritorio offline).  
**Honestidad:** esto **no** significa “100 % seguro”. Un atacante con control del SO, malware con privilegios o acceso físico prolongado puede comprometer secretos en memoria o copias.

Complementa `SECURITY.md`, `THREAT_MODEL.md` y `ARCHITECTURE.md`.

---

## 1. Resumen ejecutivo

| Área | Veredicto F10 |
|------|----------------|
| Cifrado en reposo (SQLCipher + AEAD) | Implementado |
| Master nunca en disco en claro | Tests verdes |
| Wipe de claves al bloquear (`zeroize`) | Implementado (límites de memoria reales) |
| IPC / capacidades Tauri mínimas | `core:default` solamente |
| Red / telemetría | Sin clientes HTTP en crates de bóveda; CSP restrictiva |
| Dependencias | `cargo audit`: 0 vulns conocidas; 2 avisos (unmaintained/unsound transitivos GTK); `pnpm audit`: limpio |
| Escaneo de secretos | Sin hallazgos en `apps/` + `crates/` (patrones típicos) |
| Clippy `-D warnings` | Verde en crates + shell |
| Firma de binarios | Arquitectura documentada; **certs fuera del repo** (no firmado aún) |

---

## 2. Controles implementados

### 2.1 Criptografía y bóveda
- Argon2id → KEK; AES-256-GCM; DEK envuelta; wipe en lock/close.
- Kit de emergencia (wrap recovery); master no recuperable desde disco.
- Backoff progresivo; auto-lock configurable.
- Backups `.cpbak` cifrados (`backup_version`); export plaintext bloqueado.

### 2.2 Almacenamiento y permisos
- Data dir Unix **0o700**; ficheros bóveda/backup **0o600** (tests F10).
- Soft-delete + cifrado; sin claims de wipe físico en SSD.
- Data dir de app: `CONTRASENAS_DATA_DIR` → XDG/`APPDATA` → `~/.local/share/contrasenas` (ya no temp por defecto).

### 2.3 Aplicación / IPC
- Capacidades Tauri: solo `core:default` (sin opener/FS/HTTP globales).
- CSP WebView: `default-src 'self'`; `connect-src` limitado a self/ipc.
- Comandos Tauri allowlist explícita en `invoke_handler`.
- Master password en IPC envuelta en `Zeroizing` al crear/abrir/backup.

### 2.4 Logs, auditoría, portapapeles
- `redact_secrets` / tests de no filtrado.
- Auditoría sin secretos; historial solo metadatos.
- Clipboard auto-clear con límites OS documentados.

### 2.5 Calidad / SCA (F10)
| Comprobación | Resultado (agente, 2026-10-08) |
|--------------|--------------------------------|
| `cargo clippy … -D warnings` | OK |
| `cargo test -p vault-core -p vault-storage -p vault-backup` | OK (incl. permisos, master not on disk, redaction, no HTTP en manifest) |
| `pnpm exec tsc --noEmit` | OK |
| `cargo audit` | 0 vulnerabilities; warnings RUSTSEC-2024-0370 (`proc-macro-error` unmaintained), RUSTSEC-2024-0429 (`glib` unsound en iter — tránsito Tauri/GTK Linux) |
| `pnpm audit` | No known vulnerabilities |
| Escaneo patrones secretos | Sin matches en código de app/crates |
| CI | fmt, clippy, test, frontend lint, **cargo-audit**, **gitleaks**, **pnpm audit --prod** |

---

## 3. No implementado (honesto)

| Ítem | Estado |
|------|--------|
| Code signing / notarización reales | Solo arquitectura (§5); sin certificados en repo ni pipeline de firma |
| `mlock` / anti-core-dump | No |
| Keystore OS para unlock rápido | No (y nunca master recuperable) |
| 2FA / WebAuthn / biometría | Fuera de F0–F10 |
| Sync / extensión browser / breach-check online | Fuera de alcance |
| Import completo desde otros gestores | Stub F8 |
| Hash encadenado de auditoría (opción B) | Columna `prev_hash` lista; MVP = opción A |
| Passphrase de backup distinta de master | Decisión abierta |
| Hardening OS-specific (AppLocker, sandbox extra) | No |
| Penetration test externo / bug bounty | No realizado |

---

## 4. Riesgos y limitaciones conocidos

1. **Memoria del proceso desbloqueado:** un debugger o malware con derechos equivalentes al usuario puede leer DEK/passwords en claro. Mitigación: auto-lock, minimizar tiempo abierto — no es enclave.
2. **Portapapeles del SO:** historial de clipboard puede conservar copias tras el clear de la app.
3. **SSD / soft-delete:** no hay borrado físico garantizado.
4. **Backup = misma master (MVP):** robar `.cpbak` ≈ ataque offline a la bóveda.
5. **Dependencias GTK/glib (Linux):** aviso unsound en iterador de `glib` (tránsito); vigilar actualizaciones de Tauri/GTK.
6. **WebView:** superficie de ataque del motor del SO; CSP reduce pero no elimina bugs del motor.
7. **Entorno de desarrollo:** builds debug no son release firmados; `strip`/`lto` solo en perfil release del workspace.
8. **Amenaza física / rootkit:** fuera del modelo de protección de la app.

---

## 5. Firma de binarios (arquitectura — sin certs en repo)

### 5.1 Principios
- Certificados y claves privadas **nunca** en Git ni en artefactos públicos.
- Firma en CI con secretos del forge / HSM / Apple notarization credentials.
- Verificar firma en instalación (SmartScreen, Gatekeeper, distro packaging).

### 5.2 Windows
- **Authenticode** (SHA-256) con certificado OV/EV de code signing.
- Herramientas: `signtool` / Azure Trusted Signing.
- Opcional: timestamping RFC 3161.
- Entrega: instalador MSI/NSIS firmado; Tauri bundler + post-sign.

### 5.3 macOS
- Developer ID Application + **notarización** Apple (notarytool).
- Hardened Runtime; entitlements mínimos.
- Entrega: `.dmg` / `.app` notarizado; staple ticket.

### 5.4 Linux
- Firmas **GPG** del tarball/AppImage, o paquetes `.deb`/`.rpm` firmados por el mantenedor.
- Flathub/Snap usan sus propios canales de firma.
- Checksums SHA-256 publicados junto a releases.

### 5.5 Estado actual
Documentado para distribución futura. **FASE 10 no produce binarios firmados** ni incluye certificados.

---

## 6. Dependencias críticas

| Componente | Rol | Notas |
|------------|-----|-------|
| `aes-gcm`, `argon2`, `hkdf`, `sha2`, `rand`, `zeroize` | Crypto | Revisar advisories en cada release |
| `rusqlite` + SQLCipher vendored | DB cifrada | Bundled OpenSSL — actualizar con crate |
| `tauri` 2 + WebView OS | Shell | Capacidades mínimas; avisos glib en Linux |
| React 19 / Vite | UI | Sin red en runtime de producto |

---

## 7. Recomendaciones para “producción local” (usuario final)

1. Usar **contraseña maestra larga y única**; guardar el código de emergencia **fuera** del PC.
2. Activar auto-bloqueo corto y clear de portapapeles (defaults ya razonables).
3. Hacer backups `.cpbak` en medio offline (USB cifrado / papel no aplica al archivo).
4. No copiar bóveda/`vault.dat` a carpetas sync (Drive, Dropbox) sin entender el riesgo.
5. Instalar solo builds firmados cuando existan; verificar checksum.
6. Mantener el SO actualizado (WebView/GTK).
7. Tratar malware en el mismo usuario como compromiso total mientras la bóveda esté abierta.

---

## 8. Checklist §37 / §38 (pasada F10)

- [x] ¿Texto plano en disco? (tests master + passwords)
- [x] ¿Logs / errores? (redaction + auditoría)
- [x] ¿Memoria más tiempo del necesario? (lock wipe; límites documentados)
- [x] ¿Temps? (data dir propio; no secretos en temps de diseño)
- [x] ¿Backups / historial / auditoría?
- [x] ¿Internet? (sin clientes en crates; CSP)
- [x] ¿Portapapeles? (F8 + docs)
- [x] ¿Debug / builds? (perfil release endurecido; firmas pendientes)
- [x] SCA + secret scan en CI
- [x] Documento de revisión (este archivo)

---

## 9. Conclusión

El plan base **F0–F10 está completo a nivel de producto local offline**: crypto, bóveda, CRUD, políticas, generador, auditoría, clipboard/backups, UI y esta revisión.  
Quedan mejoras futuras opcionales (firma real, 2FA, sync, etc.) **solo con decisión explícita**.

**No se afirma seguridad absoluta.** Esta revisión reduce riesgos razonables para un gestor local frente a robo de ficheros y errores de diseño; no sustituye un pentest independiente ni protege frente a un atacante con control total del equipo.
