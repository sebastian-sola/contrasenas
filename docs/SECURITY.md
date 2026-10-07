# Seguridad — Contraseñas

**Fase 1 · Diseño aprobado (D1, D2, D4) · Crypto de producción aún no implementada**

Complementa `THREAT_MODEL.md` y `ARCHITECTURE.md`. Sin afirmaciones absolutistas (§35).

---

## 1. Modelo criptográfico

### 1.1 Algoritmos

| Uso | Elección | Notas |
|-----|----------|-------|
| AEAD de secretos / envoltorios | **AES-256-GCM** (default) | ChaCha20-Poly1305 como alternativa compatible en formato |
| KDF | **Argon2id** | Params versionados en header |
| CSPRNG | `getrandom` / OsRng | Nunca PRNG no cripto |
| Hash cadena auditoría (opt) | BLAKE3 o SHA-256 | Ver `AUDIT.md` |
| Digest reutilización (sesión) | BLAKE3/SHA-256 de secreto en claro | Solo en memoria desbloqueada |

### 1.2 Parámetros Argon2id v1 (propuestos)

Calibrar en hardware de referencia a ~250–500 ms:

| Parámetro | Valor propuesto |
|-----------|-----------------|
| Memoria `m` | 64 MiB |
| Iteraciones `t` | 3 |
| Paralelismo `p` | 1 |
| Salt | 16 B CSPRNG / bóveda |
| Salida | 32 B (KEK) |

Header público: `kdf_id`, `kdf_version`, params, salt. Migración: re-envoltorio de DEK con params nuevos al desbloquear.

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

| Técnica | Aporta | No garantiza |
|---------|--------|--------------|
| `zeroize` / `SecretVec` | Sobrescritura al drop; menos leaks por Display | Copias del compilador/OS; swap; dumps |
| Minimizar IPC de secretos | Menos superficie JS | GC del WebView |
| `mlock` best-effort | Menos swap | Permisos / portabilidad |
| Evitar core dumps | Menos fugas a disco | Crash reporters OS |

**Un atacante con lectura de memoria del proceso desbloqueado puede obtener secretos.** Mitigación principal: auto-lock y minimizar tiempo en claro — no “secure enclave” software.

---

## 2. Autenticación, lock, backoff

- Master obligatoria.
- Auto-lock: 1/5/10/15/30/nunca; **default 5 min**. Cierra sesión, wipe razonable, oculta UI.
- Backoff progresivo tras fallos (ej. 0→0→2→5→15→30→60 s tope); auditar intentos; **sin lockout permanente** sin mecanismo de recuperación aprobado.
- Recuperación: **kit de emergencia aprobado (D4)** — ver §2.1. No “preguntas secretas” ni email.

### 2.1 Kit de emergencia (diseño; stubs en Fase 1, crypto real en Fase 2+)

**Qué es (lenguaje sencillo):** al crear la bóveda, la app genera un **código de emergencia de un solo uso de lectura** (frase o clave larga). Sebastián debe **guardarlo fuera del ordenador** (papel en lugar seguro, o medio offline). Si olvida la contraseña maestra, ese código permite recuperar el acceso y elegir una contraseña nueva.

**Qué no es:**

- No es un envío por correo ni un “olvidé mi contraseña” en la nube.
- **La contraseña maestra nunca se guarda** de forma que se pueda leer después (ni en disco, ni en el kit, ni en el almacén del sistema operativo).
- El kit **no revela** la master antigua; solo permite **desenvolver la misma clave de datos (DEK)** y volver a envolverla con una master nueva.

**Cómo funciona a alto nivel (diseño):**

```
Al crear bóveda:
  DEK aleatoria
  ├─ envuelta con KEK_master = Argon2id(master)
  └─ envuelta con KEK_recovery = KDF(código de emergencia)
  → mostrar código UNA vez → usuario confirma haberlo guardado

Al recuperar:
  código → KEK_recovery → unwrap DEK → pedir nueva master → wrap con KEK_master nueva
  (invalidar / rotar código de emergencia tras uso exitoso — política a implementar)
```

**Riesgos (honestos):**

| Riesgo | Mitigación de diseño |
|--------|----------------------|
| Quien robe el kit abre la bóveda | Tratarlo como las llaves de casa; no digitalizar en cloud |
| Foto / captura del kit en pantalla | UI de revelación única; aviso claro |
| Pérdida de master **y** del kit | Datos irrecuperables (igual que un disco cifrado sin clave) |
| Kit débil o predecible | Generación CSPRNG de alta entropía (implementación Fase 2+) |

**Fase 1:** solo documentación + stubs de API (`RecoveryKit` / traits) **sin** generar ni persistir material real.  
**Fase 2+:** implementación crypto con tests antes de usarlo en la bóveda real.

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
