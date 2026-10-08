# Auditoría — Contraseñas

**Fase 7 · Implementado (MVP opción A)**

Requisito §7: sistema de auditoría independiente, cifrado, sin secretos; anti-manipulación MVP.

---

## 1. Objetivos

- Trazabilidad de acciones relevantes sobre la bóveda y la app.
- Soporte a accountability local (multi-usuario futuro).
- **Nunca** registrar: passwords, master, DEK/KEK, tokens, contenido de notas sensibles.

La auditoría vive **dentro** del almacén cifrado (SQLCipher schema v4, tabla `audit_events`); no es un log de texto plano en disco.

---

## 2. Eventos mínimos

| Evento | Estado F7 |
|--------|-----------|
| `app_start` | ✅ (cola si bloqueada; flush al desbloquear) |
| `unlock_success` / `unlock_failure` | ✅ (failure en cola pending; sin password) |
| `auto_lock` / `session_lock` | ✅ |
| `credential_create` / `update` / `delete` / `restore` | ✅ |
| `password_change` | ✅ |
| `password_view` | ✅ (al pulsar Mostrar) |
| `clipboard_copy` | ⏳ FASE 8 |
| `export` / `import` / `backup_*` | ⏳ fases posteriores |
| `settings_change` / `master_password_change` | ⏳ cuando existan |

Cada evento: `id`, `sequence`, `timestamp`, `event_type`, `local_user_id`, `object_id?`, `result`, `context_json` (allowlist), `prev_hash` (columna lista).

---

## 3. Cifrado

- En reposo: SQLCipher (+ misma sesión).
- Contexto: allowlist (`CONTEXT_ALLOWLIST` en `vault-core`); tests rechazan claves/secretos.

---

## 4. Anti-manipulación

| Opción | Estado |
|--------|--------|
| **A. SQLCipher + `sequence` monotónico** | ✅ **MVP activo** |
| **B. Hash encadenado `prev_hash`** | Schema listo (columna); no verificado aún |
| **C. Firma clave separada** | No |

**Honestidad:** no es prueba forense fuerte frente al poseedor de la master.

**Decisión D6 (MVP):** opción A; B activable después sin migración destructiva.

---

## 5. Consulta en UI

Pestaña **Auditoría**: filtros por tipo, resultado, usuario, objeto; sin revelar secretos.

Historial de credencial: visible en el detalle (metadatos; sin plaintext de passwords antiguas).

---

## 6. Relación historial vs auditoría

| | Historial | Auditoría |
|--|-----------|-----------|
| Foco | Cambios de una credencial | Acciones de sistema/sesión |
| Default secretos | No | Nunca |
| Actor | Usuario local | Usuario local |

---

## 7. Tests

- Operaciones emiten eventos; fixtures de password/master/notas no aparecen en dump.
- Filtros por tipo/objeto.
- Allowlist de contexto.
