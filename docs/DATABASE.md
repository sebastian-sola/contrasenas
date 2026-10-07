# Base de datos y cifrado en reposo — Contraseñas

**Fase 3 · Implementado: SQLCipher (preferido) + AEAD de campos (capa vault-core)**

Requisito §16: evaluar cifrado de campos vs DB completa vs SQLCipher vs combinación; justificar antes de implementar; minimizar metadatos visibles sin desbloquear.

---

## 1. Opciones evaluadas

| Opción | Qué es | Pros | Contras |
|--------|--------|------|---------|
| **A. Blob AEAD único** (archivo `.cpvault` con payload CBOR/JSON) | Todo el estado cifrado con AES-GCM | Simple; mínimos metadatos; crypto story clara | Re-cifra todo al guardar; consultas/migraciones menos ergonómicas a escala |
| **B. SQLite en claro + columnas ciphertext** | Solo secretos cifrados campo a campo | SQL familiar | **Metadatos visibles** sin unlock (conteos, URLs, fechas) — inaceptable como única capa |
| **C. SQLCipher solo** | Páginas SQLite cifradas | DB opaca en reposo; queries al abrir | Un bug de SQL/export podría volcar claro; menos defensa en profundidad en columnas |
| **D. SQLCipher + AEAD de campos secretos** | Cifrado de páginas + DEK para password/notas/… | Opaqueness en reposo + defensa en profundidad + schema migrable | Más complejo; build SQLCipher multi-OS |

---

## 2. Decisión recomendada

### **Opción D: SQLCipher + cifrado AEAD de campos sensibles**

**Por qué (alineado a Seguridad > Privacidad > …):**

1. **En reposo (bloqueado):** el fichero no deja leer esquema ni metadatos útiles sin la clave (mitiga A1/A5 mejor que B).
2. **Defensa en profundidad:** aunque un dump de proceso o un bug filtre una fila “de DB”, los campos `password`, `private_notes`, secretos de historial opt-in siguen bajo AEAD con DEK.
3. **Producto:** búsquedas/filtros, políticas, caducidad y auditoría encajan en SQL versionado con migraciones (§29).
4. **Tauri + Rust:** `rusqlite` + SQLCipher es un camino conocido; el KDF (Argon2id) sigue siendo la puerta de la sesión (no “password embebida” en SQLCipher sola sin KDF fuerte).

### Relación de claves (boceto)

```
Master → Argon2id → KEK → unwrap DEK
DEK → (HKDF) → sqlcipher_key
DEK → AES-256-GCM por campo/fila sensible (nonce único)
```

Header público mínimo (archivo hermano o PRAGMA/meta cifrada al abrir): magic, versiones, salt KDF, params, `wrapped_dek`.

Si el spike de **Fase 1** demuestra bloqueo grave de empaquetado SQLCipher en algún OS objetivo, **fallback documentado:** Opción A (blob AEAD) con el mismo KDF/DEK, manteniendo el modelo de dominio idéntico detrás de un trait `VaultStore`. La arquitectura debe abstraer storage desde el día 1 (`vault-storage`).

---

## 3. Metadatos visibles sin desbloquear

**Objetivo:** lo más cercano a “nada útil”.

Permitido en claro (header público):

- Magic / versiones de formato
- Salt y parámetros Argon2id
- `wrapped_dek` (ciphertext)
- Contadores de backoff / timestamp de próximo intento (anti-bruteforce UX)
- UUID de bóveda (no secreto)

**No** en claro: nombres de servicios, usuarios, URLs, conteos de credenciales, auditoría, políticas.

Nombre de fichero: genérico bajo data dir del OS (evitar `passwords.db` si se puede; p. ej. `vault.dat`). Aviso si el path cae en carpeta de sync cloud.

---

## 4. Esquema lógico (desbloqueado)

Tipos orientativos (SQLite):

### `users_local`
`id`, `name`, `role`, `created_at`, …

### `credentials`
Identificación (§5): `id`, `service_name`, `category`, `description`, `url`, `system_app`, `environment`  
Credenciales: `username`, `password_ciphertext`, `auth_type`, `domain`, `email`, `notes_ciphertext`  
Temporal: `created_at`, `updated_at`, `password_changed_at`, `next_renewal_at`, `expiry_policy`, `status`  
Seguridad: `strength_score`, `policy_compliant`, `policy_checked_at`, `reuse_count_cache` (opcional, recalculable), `compromised_flag` (futuro, default null)

### `service_policies`
Reglas §8 por servicio/credencial.

### `history_entries`
Metadatos de cambio; `previous_secret_ciphertext` NULL por defecto / solo opt-in.

### `audit_events`
Ver `AUDIT.md` — sin secretos; cifrados en reposo vía SQLCipher (+ cadena opcional).

### `settings`
Timeouts, clipboard TTL, flags de historial de secretos, etc.

### `schema_migrations`
Versión + checksums.

**Nunca** passwords en claro en historial, auditoría, columnas auxiliares ni logs.

---

## 5. Migraciones (§29)

- `schema_version` en header/meta.
- Antes de migrar: backup cifrado + verify integridad.
- Después: verify + smoke open.
- Fallo → no dejar DB a medias; restaurar backup preventivo.

---

## 6. Permisos y ubicación (§17)

- Data dir del SO con permisos de usuario (0600 ficheros en Unix).
- Fuera del repo; `.gitignore` para cualquier path local de desarrollo.
- WAL/journal: tratarlos como sensibles (mismo dir cifrado / misma clave).

---

## 7. Decisión — **APROBADA (D2) e IMPLEMENTADA (Fase 3)**

SQLCipher + AEAD de campos (HKDF(DEK) → clave SQLCipher; AEAD de columnas secretas en CRUD Fase 4).

| Pieza | Estado F3 |
|-------|-----------|
| `rusqlite` + `bundled-sqlcipher-vendored-openssl` | ✅ compila y tests verdes |
| Cabecera pública `vault.header` | ✅ crypto + backoff + schema |
| DB `vault.dat` (SQLCipher) | ✅ schema v1 (meta, settings, credentials vacía) |
| Fallback `BlobVaultDb` | ✅ disponible en trait; no es el default |
| Permisos 0o700/0o600 | ✅ Unix |
| Migración scaffolding + backup preventivo | ✅ hooks |

Spike histórico: `docs/SQLCIPHER_SPIKE.md` (superado: SQLCipher enlazado).
