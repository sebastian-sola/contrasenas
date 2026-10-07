# Arquitectura — Contraseñas

**Fase 1 · Stack y storage aprobados (D1, D2, D4) · Esqueleto en repo**

Documento canónico de arquitectura lógica, stack, componentes, flujos y estructura. Detalle crypto: `SECURITY.md`. Amenazas: `THREAT_MODEL.md`. Datos: `DATABASE.md`.

---

## 1. Arquitectura propuesta

Aplicación de **escritorio local offline-first** con:

1. **UI** (WebView): pantallas de producto; no es dueña de claves ni de I/O de bóveda.
2. **Núcleo Rust (`vault-core`)**: KDF, AEAD, apertura SQLCipher, políticas, generador CSPRNG, auditoría, backups.
3. **Shell Tauri 2**: IPC tipado, ciclo de vida, auto-lock, clipboard OS, paths de datos del SO.
4. **Almacén**: SQLite cifrado (SQLCipher) + AEAD de campos secretos; backups versionados cifrados.
5. **Keystores OS (opcionales, auxiliares)**: DPAPI / Keychain / Secret Service — **nunca** master password recuperable.

Sin red, sin telemetría, sin sync en Fases 0–10 salvo requisito explícito posterior.

### Principios

- Seguridad > comodidad.
- Fallar cerrado.
- Secretos solo en núcleo, tiempo mínimo, wipe best-effort.
- Extensibilidad (2FA, multi-bóveda, sync) por ganchos, no por código simulado.

---

## 2. Stack tecnológico recomendado

### Criterios (orden fijo)

**Seguridad > Privacidad > Fiabilidad > Mantenibilidad > Usabilidad > Estética**

### Comparativa

| Criterio | **Tauri 2 + Rust + TS/React** | Electron | Nativo (WinUI/Swift/GTK) | Python + Qt |
|----------|-------------------------------|----------|---------------------------|-------------|
| Superficie de ataque | **Menor** (WebView del SO + Rust) | Alta (Chromium + Node) | Variable; 3 codebases | Interprete + bindings; supply chain PyPI |
| Crypto auditada | **Excelente** (crates maduros, `zeroize`) | Buena (Node/OpenSSL) pero más superficie | Buena por OS | Buena vía libs; wipe más frágil |
| Memoria / secretos | **Mejor control** en Rust | Strings JS difíciles de wipe | Bueno nativo | Limitado / GC |
| IPC / XSS | Allowlist comandos; CSP WebView | Requiere discipline estricta (§20) | N/A o distinto | Señales Qt |
| Privacidad offline | Natural | Natural si se disciplina | Natural | Natural |
| Multiplataforma | **Un proyecto** Win/Linux/macOS | Maduro | Costoso ×3 | Maduro pero packaging pesado |
| Rendimiento / RAM | **Ligero** | Pesado | Óptimo | Medio |
| Mantenibilidad | Buena (Rust+TS) | Amplia oferta JS | Tres stacks | Rápida al inicio, más deuda seguridad |
| Keystores OS | Plugins / FFI claros | Posible | Nativo | Posible vía libs |
| Distribución / firma | Soportable (fase posterior) | Maduro | Maduro | Variable |

### Decisión — **APROBADA (D1)**

**Tauri 2 + núcleo Rust + UI TypeScript/React.**

Justificación: máxima alineación con prioridad Seguridad/Privacidad (menor superficie que Electron, crypto y wipe en Rust), un solo codebase multiplataforma, IPC restringible, sin runtime Node en producción. Electron se descartó como default por superficie y memoria. Nativo puro pierde mantenibilidad multi-OS. Python+Qt facilita prototipos pero debilita wipe, distribución y postura de dependencias.

UI: React + TypeScript para pantallas (§13). **Toda** operación de secreto vía comandos Tauri → Rust.

**Recuperación (D4 aprobada):** kit de emergencia (segunda envoltura de la DEK). Diseño en `SECURITY.md` §2.1; stubs en `vault-core::recovery`. La master **nunca** se almacena recuperable.

---

## 3. Diagrama lógico de componentes

```
┌──────────────────────────────────────────────────────────────────┐
│                        Aplicación Contraseñas                      │
│  ┌─────────────────────┐     IPC allowlist      ┌───────────────┐ │
│  │  UI (React / TS)    │ ◄──────────────────► │  Tauri Shell  │ │
│  │  Bloqueo, Dashboard,│   invocaciones tipadas │  lifecycle,   │ │
│  │  Credenciales,      │                        │  clipboard,   │ │
│  │  Generador, Políticas│                       │  idle lock,   │ │
│  │  Auditoría, Config  │                        │  paths OS     │ │
│  └─────────────────────┘                        └───────┬───────┘ │
│                                                         │         │
│                         ┌───────────────────────────────▼───────┐ │
│                         │           vault-core (Rust)           │ │
│                         │  ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │
│                         │  │  Crypto │ │ Policy  │ │  Audit  │ │ │
│                         │  │ KDF/AEAD│ │ Engine  │ │  Log    │ │ │
│                         │  └────┬────┘ └────┬────┘ └────┬────┘ │ │
│                         │  ┌────▼────────────▼──────────▼────┐ │ │
│                         │  │     Vault / Session service      │ │ │
│                         │  │  unlock · lock · CRUD · backup   │ │ │
│                         │  └──────────────┬───────────────────┘ │ │
│                         │  ┌──────────────▼───────────────────┐ │ │
│                         │  │ Generator (CSPRNG) · Strength    │ │ │
│                         │  └──────────────────────────────────┘ │ │
│                         └───────────────────┬───────────────────┘ │
│         ┌─────────────────┬─────────────────┼──────────────┐     │
│         ▼                 ▼                 ▼              ▼     │
│   SQLCipher DB      Backups .cpbak    Keystore OS*    Logs seguros│
│   (+ AEAD campos)   (versionados)     (solo auxiliar) (sin secretos)│
└──────────────────────────────────────────────────────────────────┘
 * DPAPI / Keychain / libsecret — nunca master recuperable
```

### Pantallas UI (§13)

Bloqueo · Dashboard · Lista credenciales · Detalle · Crear/editar · Generador · Políticas · Auditoría · Configuración.

---

## 4. Modelo de datos (vista de arquitectura)

Ver detalle y decisión de cifrado en `DATABASE.md`.

Entidades lógicas dentro de la bóveda desbloqueada:

- `LocalUser`, `Credential`, `ServicePolicy`, `HistoryEntry`, `AuditEvent`, `VaultSettings`, `BackupMeta` (índice no secreto mínimo fuera si hace falta).

Historial: **default solo metadatos**; secretos previos solo opt-in cifrados.  
Caducidad (§12): estados + colores Verde / Amarillo / Naranja / Rojo.  
Reutilización (§11): conteo N en memoria; sin disclosure innecesario de otros servicios en vistas sensibles.

---

## 5. Modelo criptográfico (resumen)

Ver `SECURITY.md`.

- Argon2id (params versionados) → KEK.
- DEK aleatoria envuelta con KEK.
- SQLCipher con clave derivada/relacionada con DEK (detalle en `DATABASE.md`).
- Campos secretos: AES-256-GCM (o ChaCha20-Poly1305).
- Master password: nunca almacenada ni en keystore OS de forma recuperable.

---

## 6. Flujo de desbloqueo

```
[App start] → UI pantalla Bloqueo (sin abrir secretos)
       │
       ▼
 Usuario introduce master password
       │
       ▼
 vault-core: comprobar backoff (¿demasiados fallos?)
       │ sí → esperar / auditar fallo
       │ no
       ▼
 Argon2id(password, salt, params) → KEK
       │
       ▼
 Unwrap DEK (AEAD). ¿OK?
       │ no → wipe KEK/password; ++fallos; auditar; backoff
       │ sí
       ▼
 Abrir SQLCipher con material de sesión; cargar metadatos
       │
       ▼ (gancho futuro 2FA: TOTP / WebAuthn / bio — solo real)
       │
       ▼
 Sesión desbloqueada: DEK en SecretVec; UI → Dashboard
       │
       ├─ idle timeout / lock manual → wipe DEK/KEK; ocultar UI; auditar
       └─ clipboard copy → timer auto-clear (default 30 s)
```

Cambio de master: re-envolver DEK con nueva KEK (misma DEK).  
Olvido de master: sin recuperación mágica en diseño base (decisión abierta: kit de emergencia).

---

## 7. Modelo de amenazas

Ver `THREAT_MODEL.md` (documento dedicado §27).

---

## 8. Estructura de directorios (prevista)

```
contraseñas/   (repo)
├── README.md
├── docs/                      # planes Fase 0 (espejo del Agent Store)
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── THREAT_MODEL.md
│   ├── DATABASE.md
│   ├── BACKUP.md
│   ├── AUDIT.md
│   └── DEVELOPMENT.md
├── apps/
│   └── desktop/               # Tauri 2 (UI + shell) — no en F0
│       ├── src/               # React/TS
│       └── src-tauri/         # glue Tauri
├── crates/
│   ├── vault-core/            # crypto, session, policies, audit API
│   ├── vault-storage/         # SQLCipher schema, migraciones
│   └── vault-backup/          # formato .cpbak
├── tests/                     # integración / security tests
└── .github/ o CI config       # lint, test, SCA, secret scan (fase CI)
```

Datos de usuario (fuera del repo, permisos restrictivos):

```
{app_data_dir}/contrasenas/
  vault.db                 # SQLCipher (nombre poco revelador posible)
  vault.header             # opcional: salt/params/public header
  backups/
  logs/                    # sin secretos
```

Nunca: DB real, backups, claves ni secretos en Git (`.gitignore`).

---

## 9. Dependencias principales (orientativo, no pin aún)

### Rust (`vault-core` / storage)

| Crate | Uso |
|-------|-----|
| `argon2` | KDF Argon2id |
| `aes-gcm` | AEAD campos / envoltorio |
| `chacha20poly1305` | Alternativa AEAD si procede |
| `zeroize` / `secrecy` | Wipe / no Debug de secretos |
| `rand` / `getrandom` | CSPRNG |
| `rusqlite` + SQLCipher | DB cifrada |
| `serde` / `serde_json` | Serialización controlada |
| `blake3` o `sha2` | Digests de reutilización en sesión; hash cadena auditoría |
| `thiserror` | Errores sin filtrar secretos |

### Frontend

| Paquete | Uso |
|---------|-----|
| React + TypeScript | UI |
| Tailwind (opcional) | Estilos |
| `@tauri-apps/api` | IPC |

### Explícitamente evitadas en MVP

Telemetría, SDKs analytics, clientes HTTP innecesarios, `Math.random` para secretos.

SCA + lockfiles + Dependabot/Renovate en fases CI (§31–33).

---

## 10. Riesgos y decisiones pendientes

Ver también `project-context.md` y lista al final de este doc.

| Riesgo | Impacto | Mitigación de diseño |
|--------|---------|----------------------|
| Password maestra débil | Bóveda rompible offline | Requisitos de fortaleza + Argon2id costoso |
| SQLCipher build/cross-compile | Fricción CI/packaging | Spike en Fase 1; fallback documentado (ver `DATABASE.md`) |
| WebView retiene strings | Fuga memoria UI | Minimizar tiempo en claro; no cachear passwords |
| Carpetas cloud sync | Copia de bóveda a cloud | Detectar/avisar paths conocidos |
| Kit de emergencia perdido o robado | Acceso perdido o abuso | UX clara; kit offline; rotación tras uso (F2+) |
| Auditoría reescribible por dueño | No es forense fuerte | Documentar límites (`AUDIT.md`) |
| Pliego vs alcance F1–F10 | Scope creep | Fases estrictas; aprobación entre fases |

### Decisiones

| ID | Tema | Estado |
|----|------|--------|
| D1 | Stack Tauri 2 + Rust + React/TS | **Aprobado** |
| D2 | SQLCipher + AEAD (fallback blob) | **Aprobado** |
| D4 | Kit de emergencia (no solo pérdida total) | **Aprobado** |
| D5 | Plataforma inicial (Win-first vs las tres) | Pendiente |
| D6 | Auditoría: solo AEAD vs hash encadenado en MVP | Pendiente |
| D7 | Historial de secretos opt-in (cuándo) | Pendiente |
| D8 | Keystore OS opt-in | Pendiente |
| D9 | Passphrase de backup separada | Pendiente |

**Siguiente gate:** aprobación explícita antes de **Fase 2** (crypto real).

---

## Referencias cruzadas

| Tema | Doc |
|------|-----|
| Amenazas | `THREAT_MODEL.md` |
| Crypto, clipboard, OS secrets, OWASP | `SECURITY.md` |
| SQLCipher vs campos | `DATABASE.md` |
| Backups | `BACKUP.md` |
| Auditoría | `AUDIT.md` |
| Fases F0–F10 | `DEVELOPMENT.md` |
