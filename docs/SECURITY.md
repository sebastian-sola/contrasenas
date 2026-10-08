# Seguridad — Contraseñas

**Fase 10 · Plan base completo · Ver también `SECURITY_REVIEW.md`**

Complementa `THREAT_MODEL.md` y `ARCHITECTURE.md`. Sin afirmaciones absolutistas (§35).

---

## 1. Modelo criptográfico

### 1.0 Estado de implementación

| Capacidad | Estado |
|-----------|--------|
| Argon2id → KEK | ✅ `crypto::derive_kek` |
| AES-256-GCM encrypt/decrypt + AAD | ✅ `crypto::encrypt` / `decrypt` |
| Salt / DEK CSPRNG | ✅ `generate_salt` / `generate_dek` |
| Wrap/unwrap DEK (master + recovery AAD) | ✅ `wrap_dek` / `unwrap_dek` |
| Cabecera versionada `CryptoHeaderV1` | ✅ `format_version = 1` |
| Sesión derive → use → wipe | ✅ `VaultSession` + `zeroize` |
| Kit emergencia (capa crypto) | ✅ |
| Persistencia bóveda / SQLCipher | ✅ Fase 3 |
| Backoff + auto-lock configurable | ✅ F3 + settings UI F8 |
| CRUD credenciales | ✅ Fase 4 |
| Motor de políticas §8 | ✅ Fase 5 |
| Generador CSPRNG §9 / fortaleza §10 | ✅ Fase 6 |
| Auditoría §7 / historial §6 | ✅ Fase 7 |
| Clipboard auto-clear §14 | ✅ Fase 8 (UI + audit) |
| Backups `.cpbak` §15/§18 | ✅ Fase 8 |
| Export plaintext bloqueado | ✅ Fase 8 |
| Import gestores externos | Stub F8 (confirmación + no disponible) |
| Logs con redaction §24 | ✅ `logging::redact_secrets` |
| Soft-delete + límites SSD §19 | ✅ documentado (sin wipe físico falso) |

Errores: mensajes genéricos; **nunca** incluyen passwords, claves ni ciphertext interpretado como secreto en logs de error.

### 1.1 Algoritmos

| Uso | Elección | Notas |
|-----|----------|-------|
| AEAD de secretos / envoltorios | **AES-256-GCM** | ChaCha20-Poly1305 reservado |
| KDF | **Argon2id** | Params versionados en header |
| CSPRNG | `rand` / OsRng | Nunca PRNG no cripto |
| Digest reutilización (sesión) | SHA-256 de secreto en claro | Solo en memoria desbloqueada |
| Backup outer KDF+AEAD | Argon2id + AES-256-GCM | Master = passphrase MVP |

### 1.2 Parámetros Argon2id v1

| Parámetro | Valor v1 (`KdfParams::v1`) |
|-----------|----------------------------|
| Memoria `m` | 64 MiB (`65536` KiB) |
| Iteraciones `t` | 3 |
| Paralelismo `p` | 1 |
| Salt | 16 B CSPRNG |
| Salida | 32 B (KEK) |

`KdfParams::for_tests()` / `test_fast_kdf` en backups: memoria mínima solo en unit tests.

### 1.3 Jerarquía y ciclo de claves

```
Master password (efímera)
    → Argon2id → KEK
    → unwrap → DEK (aleatoria, estable por bóveda)
    → SQLCipher key material + AEAD de campos secretos
```

**Derive → use → wipe.** Al lock: `zeroize` de KEK, DEK, buffers de password.

Master **nunca** en disco, config, logs, URLs, telemetría ni keystore OS en forma recuperable.

### 1.4 Límites reales de memoria (Rust + WebView)

| Técnica | Estado | No garantiza |
|---------|--------|--------------|
| `zeroize` / `ZeroizeOnDrop` | ✅ | Copias compilador/OS; swap; dumps |
| `Debug` redactado | ✅ | Debugger lee memoria igual |
| Minimizar IPC de secretos | Parcial | GC del WebView |
| `mlock` | ❌ no aún | — |

**Un atacante con lectura de memoria del proceso desbloqueado puede obtener secretos.** Mitigación: auto-lock y minimizar tiempo en claro.

---

## 2. Autenticación, lock, backoff

- Master obligatoria.
- Auto-lock UI (F8): 60 s / 5 min / 15 min / nunca; **default 5 min** (`auto_lock_secs = 300`).
- Backoff progresivo tras fallos; auditar intentos; **sin lockout permanente** sin mecanismo de recuperación aprobado.
- Recuperación: kit de emergencia (D4).

### 2.1 Kit de emergencia

Al crear la bóveda se genera un código de emergencia (hex 32 B). Guardarlo fuera del PC. Permite unwrap DEK y rewrap con master nueva. **No** revela la master antigua. Pérdida de master **y** kit = datos irrecuperables.

---

## 3. Portapapeles (§14) — implementado F8

| Opción | Valor |
|--------|-------|
| Default clear | **30 s** |
| Opciones UI | 10 / 30 / 60 / desactivado (0) |
| UX | Toast temporal tras copiar; clear vía `navigator.clipboard.writeText("")` |
| Auditoría | evento `clipboard_copy` (campo, sin valor) |

**Límites honestos del SO:**

- Otros procesos pueden leer el clipboard antes del clear.
- Historial del portapapeles del OS puede conservar copias.
- No hay API portable fiable de “solo borrar si sigue siendo nuestro” en todos los SO; documentamos el límite en Configuración y `BACKUP.md`.

---

## 4. Almacenes de secretos del SO (§23)

| OS | API | Uso permitido | Prohibido |
|----|-----|---------------|-----------|
| Windows | DPAPI / Credential Manager | Auxiliares opt-in futuros | Master recuperable |
| macOS | Keychain | Igual | Igual |
| Linux | Secret Service | Igual | Igual |

No usado en F8 para master. Keystore auxiliar solo si se aprueba más adelante.

---

## 5. Segundo factor (diseño, no F0–F8)

Gancho post-password: TOTP → WebAuthn/FIDO2 → biometría OS. Sin 2FA simulado.

---

## 6. Hardening aplicación (OWASP / desktop §20)

Checklist (parcial F1–F8; endurecer en F10):

- Validar entrada en frontera IPC.
- Sin path traversal fuera del data dir.
- Deserialización conservadora (schemas versionados).
- Sin secretos en logs/errores/temps (§24); tests de redaction.
- CSP en WebView; no `eval`.
- Permisos FS mínimos; data dir del OS.
- Capacidades Tauri mínimas.

---

## 7. Privacidad (§25)

- Offline-first; sin analytics, telemetría, APIs externas en el diseño base.

---

## 8. Borrado seguro (§19)

Confirmación + auditoría. Soft-delete de credenciales.  
**Límite documentado:** en SSD/FS modernos no se afirma borrado físico garantizado. Evitar claims engañosos. Los datos siguen cifrados en reposo (SQLCipher + AEAD).

---

## 9. Logs y tests de seguridad (§24, §26)

- `vault_core::logging::redact_secrets` + `contains_any_secret`.
- Tests: crypto round-trip; unlock fallido; master no en disco; auditoría sin secretos; backup round-trip + integridad; plaintext export blocked; secrets no en línea de log redactada; clipboard settings normalizados.
- Cultura: checklist §37 antes de cada feature de secretos.

---

## 10. Firma de binarios (§33)

Arquitectura lista. Certificados **nunca** en el repo. Distribución posterior.

---

## 11. Checklist cultural (§37)

1. ¿Texto plano en disco?
2. ¿Logs / errores?
3. ¿Memoria más tiempo del necesario?
4. ¿Temps / swap / core dumps?
5. ¿Backups / historial / auditoría?
6. ¿Internet?
7. ¿Historial de shell?
8. ¿Portapapeles?
9. ¿Debug / builds de desarrollo?

---

## 12. Caducidad visual (§12) y reutilización (§11)

- Colores: Verde >30 d; Amarillo ≤30; Naranja ≤7; Rojo caducada.
- Reutilización: “Se utiliza en N servicios”; no revelar cuáles innecesariamente.

---

## 13. Auditoría ampliada F8

Tipos relevantes nuevos / usados:

| Evento | Cuándo |
|--------|--------|
| `clipboard_copy` | Copiar password (sin valor) |
| `backup_create` / `backup_restore` | Backup / restore |
| `settings_change` | Auto-lock / clipboard timeouts |
| Intentos export/import | Bloqueados / stub |
