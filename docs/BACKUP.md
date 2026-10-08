# Backups cifrados — Contraseñas

**Fase 8 · Implementación MVP** (diseño F0 + código F8)

Requisitos §15, §18: backup cifrado versionado; manual; restore con verificación; backup preventivo antes de sobrescribir; no borrar antiguos sin confirmación.

---

## 1. Principios

- Mismo nivel de confidencialidad que la bóveda viva.
- **No** exportar texto plano por defecto (`export_plaintext_blocked` → error).
- Formato versionado: campo obligatorio `backup_version` (actual = **1**).
- Integridad verificable antes de restaurar (`content_hash` SHA-256 del ciphertext + tag AEAD).
- Importación desde otros gestores: solo con confirmación explícita y flujo separado (stub F8: `ImportNotAvailable` tras confirmar).

---

## 2. Formato `.cpbak` (implementado)

```
+--------------------------------------+
| Magic: "CPBK" (4 B)                  |
| backup_version: u16 LE               |  ← = 1
| header_len: u32 LE                   |
+--------------------------------------+
| Header JSON (público, sin secretos)  |
|  - backup_version, vault_id          |
|  - created_at, app_version           |
|  - schema_version                    |
|  - kdf_id / m/t/p / salt_hex         |
|  - aead_id, content_hash, flags      |
+--------------------------------------+
| Payload AEAD (nonce 12 B + ct)       |
|  plaintext JSON:                     |
|    vault_header (string)             |
|    vault_dat_b64 (hex del .dat)      |
+--------------------------------------+
```

**MVP passphrase:** la master password de la bóveda cifra el payload (Argon2id → AES-256-GCM). Quien robe el `.cpbak` enfrenta el mismo ataque offline que contra la bóveda. Passphrase de backup separada: decisión abierta para fases posteriores.

Código: crate `vault-backup` (`create_cpbak`, `verify_cpbak`, `restore_cpbak`, `read_cpbak_header`, `delete_backup_file`).

---

## 3. Contenido del paquete (§15)

MVP F8 incluye el snapshot de ficheros vivos:

- `vault.header` (JSON público crypto/backoff/schema)
- `vault.dat` (SQLCipher cifrado)

Así se restauran credenciales, políticas, historial, auditoría y settings ya dentro de la DB cifrada. No se incluye master ni KEK en claro.

---

## 4. Operaciones

### 4.1 Backup manual ✅
UI Configuración → «Crear backup». Destino: carpeta `backups/` del data dir (`.cpbak`). Audita `backup_create` (sin secretos).

### 4.2 Backup automático
Diseñado (intervalo / al cerrar / antes de migrar). **No** implementado en F8 más allá de copias preventivas en restore/migración previa. Rotación: **no** borrar sin confirmación.

### 4.3 Restauración ✅
1. Leer header; comprobar `backup_version` soportado.  
2. Verificar integridad (AEAD + `content_hash`).  
3. Si destino tiene bóveda: **backup preventivo** + `confirm_overwrite`.  
4. Restaurar header/dat; auditar `backup_restore`.  
5. Fallo de integridad → abortar; no sobrescribir.

### 4.4 Borrado de backups ✅
`delete_backup_file(path, confirmed)` exige `confirmed = true`. Sin confirmación → error (no auto-delete).

### 4.5 Export/import “otros gestores”
- Export plaintext: **siempre bloqueado** (`PlaintextExportForbidden`).
- Import externos: requiere confirmación; tras confirmar → stub `ImportNotAvailable` (parsers Bitwarden/1Password/etc. fuera de F8).

---

## 5. Versionado

| Campo | Rol | Valor F8 |
|-------|-----|----------|
| `backup_version` | Formato archivo `.cpbak` | `1` |
| `schema_version` | Modelo de datos embebido | el de la bóveda al crear |

Lectores rechazan versiones futuras desconocidas.

---

## 6. Portapapeles y límites OS (honestos)

Al copiar una password, la UI borra el clipboard tras el timeout configurado (10/30/60/off). **Límites reales:**

- Otros procesos del SO pueden leer el clipboard **antes** del clear.
- Gestores de historial del portapapeles (Windows/macOS/Linux) pueden conservar copias fuera de nuestro control.
- No afirmamos “borrado absoluto” del portapapeles.

Ver también `SECURITY.md` §3.

---

## 7. Soft-delete / SSD (§19)

El borrado de credenciales es **soft-delete** (archivado + cifrado en SQLCipher). En SSD/FS modernos **no** se puede garantizar borrado físico de sectores. Documentado en UI de Configuración y aquí: evitar claims engañosos de “secure wipe”.

---

## 8. Riesgos

| Riesgo | Mitigación |
|--------|------------|
| Backup en carpeta sync cloud | Avisos de path (F9+); data dir local por defecto |
| Acumulación de copias | UI lista + borrado solo con confirmación |
| Restore de versión vieja pierde datos nuevos | Confirmación + backup preventivo |
| Passphrase = master | Robo de backup = mismo ataque offline que bóveda |

---

## 9. Decisión abierta (sigue)

¿Passphrase de backup separada opcional en fases posteriores?
