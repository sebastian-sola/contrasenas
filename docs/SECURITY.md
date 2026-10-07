# Seguridad — Contraseñas

**Fase 2 · Crypto de producción implementada en `vault-core` (sin persistencia de bóveda)**

Complementa `THREAT_MODEL.md` y `ARCHITECTURE.md`. Sin afirmaciones absolutistas (§35).

---

## 1. Modelo criptográfico

### 1.0 Estado de implementación (Fase 2)

| Capacidad | Estado |
|-----------|--------|
| Argon2id → KEK | ✅ `crypto::derive_kek` |
| AES-256-GCM encrypt/decrypt + AAD | ✅ `crypto::encrypt` / `decrypt` |
| Salt / DEK CSPRNG | ✅ `generate_salt` / `generate_dek` |
| Wrap/unwrap DEK (master + recovery AAD) | ✅ `wrap_dek` / `unwrap_dek` |
| Cabecera versionada `CryptoHeaderV1` | ✅ serializable JSON; `format_version = 1` |
| Sesión derive → use → wipe | ✅ `VaultSession` + `zeroize` en DEK/KEK |
| Kit emergencia (capa crypto) | ✅ generar código, unlock recovery, rewrap master |
| Persistencia bóveda / SQLCipher | ❌ Fase 3 |
| CRUD credenciales | ❌ Fase 4 |

Errores (`CryptoError`, `SessionError`, `RecoveryError`): mensajes genéricos; **nunca** incluyen passwords, claves ni ciphertext interpretado como secreto en logs de error.

### 1.1 Algoritmos

| Uso | Elección | Notas |
|-----|----------|-------|
| AEAD de secretos / envoltorios | **AES-256-GCM** (implementado) | ChaCha20-Poly1305 reservado; no necesario aún |
| KDF | **Argon2id** | Params versionados en header (`kdf_version`) |
| CSPRNG | `rand` / OsRng | Nunca PRNG no cripto |
| Hash cadena auditoría (opt) | BLAKE3 o SHA-256 | Ver `AUDIT.md` (aún no) |
| Digest reutilización (sesión) | BLAKE3/SHA-256 de secreto en claro | Solo en memoria desbloqueada (Fase 4+) |

### 1.2 Parámetros Argon2id v1 (**implementados**)

| Parámetro | Valor v1 en código (`KdfParams::v1`) |
|-----------|--------------------------------------|
| Memoria `m` | 64 MiB (`65536` KiB) |
| Iteraciones `t` | 3 |
| Paralelismo `p` | 1 |
| Salt | 16 B CSPRNG |
| Salida | 32 B (KEK) |

`KdfParams::for_tests()` usa memoria mínima solo en unit tests.  
Header público: `kdf_id`, `kdf_version`, params, salt, `wrapped_dek`, opcional recovery. Migración futura: re-envoltorio de DEK con params nuevos al desbloquear.

### 1.3 Jerarquía y ciclo de claves

```
Master password (efímera)
    → Argon2id → KEK
    → unwrap → DEK (aleatoria, estable por bóveda)
    → SQLCipher key material + AEAD de campos secretos
```

**Derive → use → wipe.** Al lock: `zeroize` de KEK, DEK, buffers de password. UI limpia estado sensible.

Cambio de master: nueva KEK, misma DEK re-envuelta.  
Master **nunca** en disco, config, logs, URLs, telemetría ni keystore OS en forma recuperable.

### 1.4 Límites reales de memoria (Rust + WebView)

| Técnica | Implementado Fase 2 | No garantiza |
|---------|---------------------|--------------|
| `zeroize` / `ZeroizeOnDrop` en DEK/KEK | ✅ | Copias del compilador/OS; swap; dumps |
| `Debug` redactado en claves | ✅ | Debugger lee memoria igual |
| Minimizar IPC de secretos | Parcial (UI aún stub) | GC del WebView |
| `mlock` | ❌ no aún | — |
| Evitar core dumps | ❌ no aún | Crash reporters OS |

**Un atacante con lectura de memoria del proceso desbloqueado puede obtener secretos.** Mitigación principal: auto-lock (Fase 3/8) y minimizar tiempo en claro — no “secure enclave” software.

---

## 2. Autenticación, lock, backoff

- Master obligatoria.
- Auto-lock: 1/5/10/15/30/nunca; **default 5 min**. Cierra sesión, wipe razonable, oculta UI.
- Backoff progresivo tras fallos (ej. 0→0→2→5→15→30→60 s tope); auditar intentos; **sin lockout permanente** sin mecanismo de recuperación aprobado.
- Recuperación: **kit de emergencia aprobado (D4)** — ver §2.1. No “preguntas secretas” ni email.

### 2.1 Kit de emergencia (crypto ✅ Fase 2; persistencia UI en Fase 3+)

**Qué es (lenguaje sencillo):** al crear la bóveda, la app genera un **código de emergencia** (hex de 32 bytes aleatorios). Sebastián debe **guardarlo fuera del ordenador** (papel en lugar seguro). Si olvida la contraseña maestra, ese código permite recuperar el acceso y elegir una contraseña nueva.

**Qué no es:**

- No es un envío por correo ni un “olvidé mi contraseña” en la nube.
- **La contraseña maestra nunca se guarda** de forma que se pueda leer después.
- El kit **no revela** la master antigua; solo permite **desenvolver la misma DEK** y volver a envolverla con una master nueva (`rewrap_dek_with_new_master`).

**Implementado en código (sin guardar aún en disco):**

```
bootstrap_key_material(..., with_recovery_kit=true)
  DEK aleatoria
  ├─ wrapped_dek (AAD master)
  └─ wrapped_dek_recovery (AAD recovery) + recovery_salt
unlock_dek_with_recovery(código, header) → DEK
rewrap_dek_with_new_master(DEK, nueva_master) → nueva cabecera master
```

Rotación obligatoria del código tras uso exitoso: política a cablear en Fase 3 (UI + persistencia).

**Riesgos (honestos):**

| Riesgo | Mitigación |
|--------|------------|
| Quien robe el kit abre la bóveda | Tratarlo como llaves de casa; no cloud |
| Foto / captura en pantalla | UI de revelación única (Fase 3) |
| Pérdida de master **y** del kit | Datos irrecuperables |
| Kit débil | CSPRNG 256 bits (hex) |

---

## 3. Portapapeles (§14)

- Default clear **30 s**; opciones 10/30/60/desactivado.
- Mensaje temporal tras copiar.
- Clear preferente solo si el clipboard sigue siendo “nuestro”.
- **Documentado:** otros procesos del SO pueden leer el clipboard antes del clear.

---

## 4. Almacenes de secretos del SO (§23)

| OS | API | Uso permitido | Prohibido |
|----|-----|---------------|-----------|
| Windows | DPAPI / Credential Manager | Envolver secretos auxiliares (p. ej. token de sesión corta opt-in) | Master en claro recuperable |
| macOS | Keychain | Igual | Igual |
| Linux | Secret Service / libsecret | Igual (soporte fragmentado) | Igual |

La bóveda en reposo debe seguir siendo resistente si se copia el archivo **sin** el perfil OS. Cualquier “unlock rápido” con keystore es **opt-in**, explicado, y no sustituye Argon2id del archivo.

---

## 5. Segundo factor (diseño, no F0–F7)

Gancho post-password: TOTP → WebAuthn/FIDO2 → biometría OS.  
Solo implementaciones reales; documentar soporte por plataforma al implementarse. Sin 2FA simulado.

---

## 6. Hardening aplicación (OWASP / desktop §20)

Checklist de diseño (implementación por fases):

- Validar toda entrada en frontera IPC (IDs, paths, longitudes).
- Sin path traversal a rutas fuera del data dir.
- Deserialización conservadora (schemas versionados).
- Sin secretos en logs/errores/temps (§24); tests que fallen si aparecen.
- CSP en WebView; no `eval`; HTML escapado.
- Permisos FS mínimos; data dir del OS.
- Dependencias mínimas + SCA (§31).
- Capacidades Tauri mínimas (FS/HTTP deshabilitados salvo allowlist).

Si en el futuro hubiera Electron (no recomendado): `contextIsolation`, sandbox, `nodeIntegration=false`, preload mínimo, CSP, IPC validado — pero la elección preferida es Tauri precisamente para reducir esta superficie.

---

## 7. Privacidad (§25)

- Offline-first; sin analytics, telemetría, APIs externas, ni breach-check online en el diseño base.
- Cualquier red futura: off by default, identificada, aislada, documentada.

---

## 8. Borrado seguro (§19)

Confirmación + auditoría. Considerar WAL/journal/copias.  
**Límite:** en SSD/FS modernos no se puede afirmar borrado físico garantizado; documentar honestamente y evitar claims engañosos.

---

## 9. Logs y tests de seguridad (§24, §26)

- Logger con redaction; niveles sin payloads sensibles.
- Tests: crypto round-trip; unlock fallido; master no en disco; auditoría sin secretos; clipboard timer; sin sockets de red inesperados en MVP; no secretos en temps/hardcode.
- Cultura: checklist §37 antes de cada feature de secretos.

---

## 10. Firma de binarios (§33)

Arquitectura lista para code signing / notarization. Certificados **nunca** en el repo. Implementación en fase de distribución, no en F0.

---

## 11. Checklist cultural (§37) — antes de cada feature de secretos

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
- Reutilización: “Se utiliza en N servicios”; no revelar cuáles si la vista implica disclosure innecesario.
