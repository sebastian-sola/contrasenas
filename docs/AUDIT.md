# Auditoría — Contraseñas

**Fase 0 · Diseño · Sin implementación**

Requisito §7: sistema de auditoría independiente, cifrado, sin secretos; evaluar anti-manipulación.

---

## 1. Objetivos

- Trazabilidad de acciones relevantes sobre la bóveda y la app.
- Soporte a accountability local (multi-usuario futuro).
- **Nunca** registrar: passwords, master, DEK/KEK, tokens, contenido de notas sensibles.

La auditoría vive **dentro** del almacén cifrado (SQLCipher); no es un log de texto plano en disco.

---

## 2. Eventos mínimos

| Evento | Notas |
|--------|-------|
| `app_start` | Arranque |
| `unlock_success` / `unlock_failure` | Sin password |
| `auto_lock` / `session_lock` | |
| `credential_create` / `update` / `delete` / `restore` | IDs, no secretos |
| `password_change` | Solo IDs / flags |
| `password_view` | Consulta de secreto |
| `clipboard_copy` | Qué campo (user/pass), no valor |
| `export` / `import` / `backup_create` / `backup_restore` | |
| `settings_change` | Claves de config, no secretos |
| `master_password_change` | Sin material criptográfico |

Cada evento: `id`, `timestamp`, `type`, `local_user_id`, `object_id?`, `result`, `context` (JSON no sensible).

---

## 3. Cifrado

- En reposo: protegida por SQLCipher (+ misma sesión que el resto).
- Campos de contexto: allowlist de claves; tests que fallen si hay patrones de secreto.

---

## 4. Anti-manipulación — opciones

| Opción | Ventaja | Limitación |
|--------|---------|------------|
| **A. Solo AEAD/SQLCipher del almacén** | Simple | Quien tiene master puede reescribir auditoría “válida” |
| **B. Hash encadenado** (`prev_hash` + hash del evento) | Detecta recortes/reordenados si se conserva la cabeza | El dueño de la DEK puede regenerar la cadena |
| **C. Firma con clave de auditoría separada** | Mejor separación de roles | Complejidad; gestión de clave; overkill MVP |

### Recomendación

- **MVP (Fase 7):** Opción **A** + campo `sequence` monotónico.
- **Schema listo** para `prev_hash` (Opción B) sin activarlo hasta decisión.
- Documentar siempre: **no es prueba forense fuerte frente al poseedor de la master**.

---

## 5. Consulta en UI

Pantalla Auditoría (§13): filtros por fecha/tipo/usuario; sin revelar secretos; paginación.

---

## 6. Relación con historial de credenciales

| | Historial | Auditoría |
|--|-----------|-----------|
| Foco | Cambios de una credencial | Acciones de sistema/sesión |
| Default secretos | No | Nunca |
| Actor | Usuario local | Usuario local |

---

## 7. Tests (§26)

- Ningún evento contiene substrings de fixtures de password/master.
- Fallos de unlock se registran sin material.
- Cadena B (si se activa): tamper test corta/reordena y detecta.

---

## 8. Decisión pendiente

¿Hash encadenado (B) desde el primer release usable, o A en MVP y B después?
