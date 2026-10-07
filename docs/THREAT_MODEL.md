# Modelo de amenazas — Contraseñas

**Fase 0 · Borrador para aprobación · Sin código de producción**

Prioridad de diseño: **Seguridad > Privacidad > Fiabilidad > Mantenibilidad > Usabilidad > Estética**.  
Nunca afirmar “100 % seguro”. Toda mitigación tiene límites.

---

## 1. Activos

| Activo | Criticidad |
|--------|------------|
| Contraseña maestra | Crítica (solo efímera en memoria) |
| KEK / DEK derivadas | Crítica (sesión desbloqueada) |
| Secretos de credenciales (password, notas, tokens futuros) | Crítica |
| Metadatos de credenciales (URL, usuario, fechas) | Alta |
| Historial (metadatos; secretos solo si opt-in) | Alta |
| Auditoría | Alta |
| Backups cifrados | Crítica (misma sensibilidad que la bóveda) |
| Configuración no sensible | Baja |

---

## 2. Atacantes

| ID | Perfil | Capacidades |
|----|--------|-------------|
| A1 | Oportunista con disco | Lee archivos en reposo (portátil apagado, backup FS) |
| A2 | Usuario local no privilegiado | Home del usuario; sin root |
| A3 | Malware a nivel usuario | Keylogger, clipboard, posiblemente memoria del proceso |
| A4 | Malware admin/root | Control total del SO, debugger, hooks |
| A5 | Ladrón de archivo `.cpvault` / backup | Ataque offline (diccionario/GPU) |
| A6 | Manipulador de DB/backup | Modifica bytes sin conocer la password |
| A7 | Insider multi-usuario (futuro) | Comparte máquina |

---

## 3. Límites de confianza

```
[Usuario / SO] ──UI (WebView)──▶ [Núcleo Rust: crypto + vault + IPC]
                                      │
                                      ▼
                               [DB SQLCipher + campos AEAD]
                                      │
                               [Backups .cpbak cifrados]
         Sin red · Sin telemetría · Keystores OS solo auxiliares
```

- **Alta confianza:** `vault-core` (Rust).
- **Media:** UI (muestra secretos bajo demanda; no persiste claves).
- **No confiable:** red, otros procesos, carpetas de sync cloud.

---

## 4. Escenarios (requisito §27)

### 4.1 Acceso sin sesión (bóveda bloqueada)

| Amenaza | Mitigación | Límite residual |
|---------|------------|-----------------|
| Lectura de secretos en disco | SQLCipher + AEAD de campos; master nunca en disco | Fuerza bruta offline si password débil |
| Metadatos filtrados | Minimizar plaintext fuera del DB cifrado | Tamaño de archivo / nombres de path |
| Manipulación de DB | AEAD/SQLCipher integrity; fallar cerrado | DoS (corrupción) |

### 4.2 Acceso con sesión desbloqueada

| Amenaza | Mitigación | Límite residual |
|---------|------------|-----------------|
| Lectura de secretos en UI/memoria | Auto-lock; ocultar por defecto; minimizar copias | Quien controla el proceso ve secretos |
| Abuso de IPC | Allowlist Tauri; validación de comandos | Bugs de autorización en comandos |
| Reutilización UX | Contador N sin listar otros servicios en vistas sensibles | Actor con sesión puede abrir otros detalles |

### 4.3 Malware usuario

| Amenaza | Mitigación | Límite residual |
|---------|------------|-----------------|
| Keylogger | (limitado) no sustituible en app | Captura master al teclear |
| Clipboard | Auto-clear; documentar riesgo OS | Lectura antes del clear |
| Memory scrape | `zeroize` best-effort; ventana corta | No es enclave |

### 4.4 Malware admin/root

| Amenaza | Mitigación | Límite residual |
|---------|------------|-----------------|
| Debugger / hooks / dump | Reducir ventana; opcional anti-debug débil | **Fuera de alcance efectivo** |
| Sustitución de binario | Code signing (fase posterior) | Antes de firmar: trust-on-first-use |

### 4.5 Robo de bóveda / backup

| Amenaza | Mitigación | Límite residual |
|---------|------------|-----------------|
| Diccionario offline | Argon2id fuerte + password robusta | GPU si password débil |
| Confusión de backups | `backup_version` + verificación integridad | Usuario restaura backup viejo por error |

### 4.6 Manipulación de DB

Detectada al abrir (MAC/tag / SQLCipher). App no “repara” en silencio datos de autenticación rotos: falla cerrado y audita si es posible.

### 4.7 Portapapeles, capturas, keyloggers

Documentados como **riesgos del SO**. Mitigaciones parciales: clear, lock, no mostrar password por defecto. Sin promesas absolutas.

---

## 5. STRIDE (resumen)

| | Ejemplo | Mitigación principal |
|--|---------|----------------------|
| S | Fingir dueño | Master + backoff; 2FA futuro real |
| T | Alterar DB/backup | Cifrado autenticado + verify restore |
| R | Negar acciones | Auditoría cifrada (límites: dueño puede reescribir) |
| I | Fuga en logs/UI/disk | Política de logging + tests; AEAD |
| D | Lockout eterno | Solo backoff; sin bloqueo permanente sin recuperación |
| E | Escape UI→privilegios | IPC mínimo; sin `nodeIntegration` (N/A Tauri) |

---

## 6. Lo que no cubrimos (honestidad)

- Resistencia a malware privilegiado o rootkits.
- “Borrado seguro garantizado” en SSD (ver `SECURITY.md` / borrado).
- Recuperación de master olvidada sin kit explícito aprobado por el usuario.
- Amenazas de canal lateral físicas / TEMPEST.

---

## 7. Pregunta de diseño (§39)

Para cada decisión: ¿qué queda expuesto si roban la bóveda / tienen la sesión / modifican la DB / hay malware?
