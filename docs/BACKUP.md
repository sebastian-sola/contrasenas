# Backups cifrados — Contraseñas

**Fase 0 · Boceto de diseño · Sin implementación**

Requisitos §15, §18: backup cifrado versionado; manual/automático; restore con verificación; backup preventivo antes de sobrescribir; no borrar antiguos sin confirmación.

---

## 1. Principios

- Mismo nivel de confidencialidad que la bóveda viva.
- **No** exportar texto plano por defecto.
- Formato versionado: campo obligatorio `backup_version`.
- Integridad verificable antes de restaurar.
- Importación desde otros gestores: solo con confirmación explícita y flujo separado (no es “restore nativo”).

---

## 2. Boceto de formato `.cpbak`

```
+--------------------------------------+
| Magic: "CPBK" (4 B)                  |
| backup_version: u16                  |  ← versionado del formato de backup
| header_len: u32                      |
+--------------------------------------+
| Header (CBOR/JSON en claro mínimo)   |
|  - backup_version                    |
|  - vault_id                          |
|  - created_at (UTC)                  |
|  - app_version                       |
|  - schema_version                    |
|  - kdf_id / kdf_version / params     |
|  - salt                              |
|  - aead_id                           |
|  - wrapped_dek                       |  ← misma DEK de la bóveda, envuelta
|  - content_hash (hash del ciphertext)|
|  - flags (incl. what sections)       |
+--------------------------------------+
| Payload AEAD (nonce + ciphertext)    |
|  plaintext = paquete:                |
|    credentials, policies, history,   |
|    audit, settings, users_local      |
|  (serialización estable versionada)  |
+--------------------------------------+
```

Notas:

- El backup **reutiliza** el modelo KEK/DEK: quien conoce la master puede unwrap. Alternativa futura: passphrase distinta solo para backup (decisión abierta; añade UX).
- `content_hash` + tag AEAD: detección de corrupción/manipulación.
- No incluir master password ni KEK en claro.

---

## 3. Contenido del paquete (§15)

Incluye por defecto:

- Credenciales (campos secretos ya como ciphertext AEAD o re-envueltos de forma consistente al exportar)
- Políticas
- Historial
- Auditoría
- Configuración
- Metadatos de schema

Excluye: claves en claro, telemetría, paths absolutos innecesarios del SO del emisor (opcional sanitizar).

---

## 4. Operaciones

### 4.1 Backup manual
Usuario elige destino (fuera del repo). Verificar escritura + hash. Auditar `backup_create` (sin secretos).

### 4.2 Backup automático
Configurable (intervalo / al cerrar / antes de migrar). Rotación: **no** borrar sin confirmación (o papelesera con retención y confirmación explícita).

### 4.3 Restauración
1. Leer header; comprobar `backup_version` soportado.  
2. Verificar integridad (AEAD + hash).  
3. Si destino tiene bóveda existente: **backup preventivo** + confirmación explícita.  
4. Restaurar; verificar apertura; auditar `backup_restore`.  
5. Fallo de integridad → abortar; no sobrescribir.

### 4.4 Export/import “otros gestores”
Flujo distinto, confirmación explícita, advertencias de plaintext si el formato origen lo es; preferir convertir a bóveda cifrada inmediatamente.

---

## 5. Versionado

| Campo | Rol |
|-------|-----|
| `backup_version` | Evolución del formato de archivo `.cpbak` |
| `schema_version` | Evolución del modelo de datos embebido |

Migraciones de backup: lectores deben rechazar versiones futuras desconocidas; versiones antiguas migran tras restore con backup preventivo.

---

## 6. Riesgos

| Riesgo | Mitigación |
|--------|------------|
| Backup en carpeta sync cloud | Avisos de path |
| Acumulación de copias | UI de gestión + confirmación al borrar |
| Restore de versión vieja pierde datos nuevos | Confirmación + backup preventivo |
| Passphrase = master | Robo de backup = mismo ataque offline que bóveda |

---

## 7. Decisión abierta

¿Una sola passphrase (= master) para backups en MVP, o passphrase de backup separada opcional?
