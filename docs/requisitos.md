# Proyecto: Gestor local seguro de contraseñas

Aplicación de escritorio LOCAL para gestionar de forma segura contraseñas y credenciales de acceso a sitios, aplicaciones, servidores y servicios.

Diseño desde el principio como gestor de secretos/password manager local, con prioridad absoluta en seguridad, privacidad, trazabilidad y resistencia frente a accesos no autorizados.

## 1. Objetivo principal

La aplicación permitirá:

- Guardar credenciales de múltiples sitios y aplicaciones.
- Asociar cada credencial a un servicio/sitio concreto.
- Guardar usuario, contraseña y datos adicionales.
- Registrar cuándo se creó una contraseña.
- Registrar cuándo se modificó por última vez.
- Mantener un historial de cambios de cada contraseña.
- Registrar quién realizó cada cambio, cuando exista más de un usuario.
- Registrar qué campos fueron modificados.
- Permitir consultar la trazabilidad/auditoría.
- Generar contraseñas seguras.
- Comprobar si una contraseña cumple las reglas requeridas por un determinado servicio.
- Definir reglas específicas de contraseña para cada servicio.
- Avisar cuando una contraseña esté próxima a caducar.
- Avisar cuando una contraseña lleve demasiado tiempo sin cambiarse.
- Permitir buscar y filtrar credenciales.
- Permitir copiar temporalmente usuario/contraseña al portapapeles.
- Limpiar automáticamente el portapapeles después de un tiempo configurable.
- Bloquear automáticamente la aplicación después de un periodo de inactividad.
- Mantener todos los datos LOCALMENTE salvo que explícitamente se implemente posteriormente una funcionalidad de sincronización.

---

## 2. REQUISITOS DE SEGURIDAD — PRIORIDAD MÁXIMA

La seguridad es más importante que la comodidad.

Antes de escribir código, analiza amenazas y define una arquitectura de seguridad.

NO quiero:

- Contraseñas almacenadas en texto plano.
- Claves maestras almacenadas en archivos de configuración.
- Claves de cifrado hardcodeadas.
- Contraseñas visibles en logs.
- Contraseñas incluidas en mensajes de error.
- Contraseñas almacenadas en variables persistentes innecesariamente.
- Contraseñas incluidas en URLs.
- Contraseñas incluidas en analytics o telemetría.
- Telemetría externa.
- Conexiones externas innecesarias.
- Dependencias innecesarias.
- Funcionalidades que envíen información fuera del equipo.

La aplicación debe funcionar completamente offline.

### 2.1 Cifrado

Todo el almacén de credenciales debe estar cifrado.

Utilizar algoritmos criptográficos modernos y ampliamente auditados.

Preferencia:

- AES-256-GCM para cifrado autenticado de datos, o
- ChaCha20-Poly1305 cuando sea técnicamente más apropiado.

Para derivar la clave de cifrado a partir de la contraseña maestra utilizar un KDF moderno:

- Argon2id como primera opción.

La configuración del KDF debe incluir parámetros suficientemente fuertes y estar preparada para evolucionar en futuras versiones.

La contraseña maestra NUNCA debe almacenarse.

La aplicación deberá derivar la clave de cifrado en memoria cuando el usuario desbloquee la bóveda.

### 2.2 Protección de la contraseña maestra

La contraseña maestra:

- Nunca debe almacenarse.
- Nunca debe aparecer en logs.
- Nunca debe aparecer en mensajes de error.
- Nunca debe permanecer en memoria más tiempo del necesario.
- Debe utilizarse únicamente para desbloquear la bóveda.

Investigar posibilidades de:

- limpieza de memoria,
- minimización de copias,
- variables seguras,
- protección contra volcados de memoria,

según las capacidades reales del lenguaje/framework elegido.

No implementar falsas medidas de seguridad. Si una protección no puede garantizarse en el lenguaje elegido, documentarlo claramente.

---

## 3. AUTENTICACIÓN

### Contraseña maestra

Primera y obligatoria barrera de seguridad.

### Bloqueo automático

Configurable:

- 1 minuto
- 5 minutos
- 10 minutos
- 15 minutos
- 30 minutos
- nunca

Por defecto: 5 minutos.

Al bloquearse:

- cerrar la sesión de la bóveda,
- eliminar de memoria las claves que sea razonable eliminar,
- ocultar inmediatamente los datos sensibles.

### Protección contra intentos repetidos

Implementar protección contra ataques de fuerza bruta.

Por ejemplo:

- incremento progresivo del tiempo de espera después de intentos fallidos;
- registro de intentos fallidos;
- posibilidad de configurar políticas adicionales.

No bloquear permanentemente al usuario sin disponer de un mecanismo de recuperación seguro.

---

## 4. SEGUNDO FACTOR / DESBLOQUEO

Diseñar la arquitectura para poder incorporar posteriormente:

- TOTP
- WebAuthn/passkeys
- llave física FIDO2
- biometría del sistema operativo

No implementar funcionalidades de seguridad simuladas.

Si alguna depende del sistema operativo, documentar exactamente qué plataformas soporta.

---

## 5. MODELO DE DATOS

Cada credencial deberá contener como mínimo:

### Identificación

- ID interno único
- Nombre del servicio
- Categoría
- Descripción
- URL
- Sistema/aplicación
- Entorno: Producción, Desarrollo, Test, QA, Otro

### Credenciales

- Usuario
- Contraseña
- Tipo de autenticación
- Dominio
- Email asociado
- Notas privadas

### Gestión temporal

- Fecha de creación
- Fecha de última modificación
- Fecha del último cambio de contraseña
- Fecha prevista de próxima renovación
- Política de caducidad
- Estado: Activa, Caducada, Próxima a caducar, Bloqueada, Archivada

### Seguridad

- Fortaleza estimada de la contraseña
- Si cumple la política del servicio
- Última comprobación de política
- Indicador de reutilización
- Indicador de contraseña comprometida, si posteriormente se implementa esta funcionalidad

IMPORTANTE: Nunca almacenar contraseñas en texto plano en campos auxiliares, logs, auditorías o tablas de histórico.

---

## 6. HISTORIAL DE CONTRASEÑAS

Mantener un historial de cambios (fecha, acción, usuario, motivo).

Debe permitir saber:

- cuándo ocurrió el cambio,
- qué usuario lo realizó,
- qué tipo de operación fue,
- qué campos fueron modificados,
- motivo del cambio si se proporciona.

### MUY IMPORTANTE

No guardar automáticamente la contraseña anterior en texto plano dentro del historial.

Si se considera necesario conservar versiones anteriores para permitir recuperación, deben almacenarse cifradas dentro de la bóveda y con una política claramente definida.

Por defecto, el historial debe guardar únicamente metadatos del cambio y NO la contraseña anterior.

---

## 7. AUDITORÍA

Sistema de auditoría independiente. Registrar como mínimo:

- Inicio de aplicación
- Intento de desbloqueo correcto / incorrecto
- Bloqueo automático
- Cierre de sesión
- Creación / modificación / eliminación / restauración de credencial
- Cambio de contraseña
- Consulta de contraseña
- Copia al portapapeles
- Exportación / importación
- Cambio de configuración
- Cambio de contraseña maestra

Cada evento: ID, Timestamp, Tipo, Usuario local, ID del objeto afectado, Resultado, Información contextual no sensible.

NUNCA registrar: contraseña, contraseña maestra, clave de cifrado, tokens, secretos, contenido sensible de notas.

La auditoría también debe estar cifrada.

Evaluar protección contra manipulación (hash encadenado, firma, o equivalente) y documentar ventajas y limitaciones.

---

## 8. POLÍTICAS DE CONTRASEÑAS

Motor de políticas configurable por servicio:

- longitud mínima / máxima
- mayúsculas / minúsculas / números / símbolos requeridos
- espacios permitidos
- caracteres / patrones prohibidos
- número de contraseñas anteriores no reutilizables
- periodo de caducidad
- otras reglas extensibles

El motor deberá poder validar una contraseña contra una política.

---

## 9. GENERADOR DE CONTRASEÑAS

Generador criptográficamente seguro.

Debe permitir: longitud, mayúsculas, minúsculas, números, símbolos, evitar caracteres ambiguos, caracteres personalizados, exclusión, generación basada en política.

Usar CSPRNG del sistema/lenguaje. NO usar `Math.random()` ni equivalentes no criptográficos.

Mostrar: contraseña generada, longitud, estimación de fortaleza, cumplimiento de política.

No almacenar automáticamente una contraseña generada hasta que el usuario decida guardarla.

---

## 10. DETECCIÓN DE CONTRASEÑAS DÉBILES

Indicadores visuales: Muy débil, Débil, Media, Fuerte, Muy fuerte.

Basarse preferentemente en entropía y/o algoritmos reconocidos. Evitar heurísticas simplistas.

Evaluar integrar posteriormente zxcvbn u equivalente.

---

## 11. DETECCIÓN DE REUTILIZACIÓN

La aplicación debe detectar si una misma contraseña se utiliza en varios servicios.

IMPORTANTE:

No comparar contraseñas enviándolas a ningún servidor.

La comparación debe hacerse localmente sobre los valores descifrados en memoria durante el tiempo estrictamente necesario.

Mostrar advertencias como:

Esta contraseña se utiliza en 3 servicios.

No revelar cuáles son si ello supone un riesgo innecesario en determinadas vistas.

## 12. CADUCIDAD

Permitir definir: fecha de caducidad, número de días, periodicidad, sin caducidad.

Avisos (configurables): Verde >30 días; Amarillo ≤30; Naranja ≤7; Rojo caducada.

## 13. INTERFAZ

Escritorio moderna, limpia y profesional. Pantallas: Bloqueo, Dashboard, Credenciales, Detalle, Crear/editar, Generador, Políticas, Auditoría, Configuración.

Contraseña siempre oculta inicialmente; show/hide y copiar en detalle.

## 14. PORTAPAPELES

Copiar → mensaje temporal → limpiar tras X segundos (default 30; opciones 10/30/60/desactivado). Documentar que otros procesos del SO pueden acceder al portapapeles.

## 15. EXPORTACIÓN / IMPORTACIÓN

No texto plano por defecto. Backup cifrado versionado (`backup_version`). Incluye credenciales, políticas, historial, auditoría, configuración. Importación desde gestores habituales solo con confirmación explícita.

## 16. BASE DE DATOS

SQLite u similar. Evaluar cifrado de campos vs DB completa vs SQLCipher vs combinación. Minimizar metadatos visibles sin desbloquear. Justificar la decisión antes de implementar.

## 17. SISTEMA DE ARCHIVOS

Permisos restrictivos; directorio de datos del SO; sin nombres reveladores; fuera del repo; `.gitignore` adecuado. Nunca DB real, backups, claves ni secretos en Git.

## 18. BACKUPS

Manual y automático configurable; restauración; verificación de integridad. Antes de sobrescribir: backup preventivo, confirmación, verificar integridad. No borrar backups antiguos sin confirmación.

## 19. BORRADO SEGURO

Confirmación + auditoría. Considerar WAL/journal/backups. Documentar limitaciones reales en SSD/FS modernos; no afirmar borrado seguro garantizado.

## 20. SEGURIDAD DE LA APLICACIÓN

Principios OWASP (inyección, path traversal, deserialización, almacenamiento, secretos, logging, deps, permisos, IPC, XSS/CSRF si UI web, elevación). Si Electron: contextIsolation, sandbox, nodeIntegration=false, preload mínimo, CSP, IPC validado. Preferir Tauri u alternativa más segura si se justifica.

## 21. ELECCIÓN TECNOLÓGICA

Comparar: Tauri + frontend moderno; Electron; nativo; Python+Qt. Criterios: seguridad, superficie de ataque, cifrado, mantenimiento, rendimiento, multiplataforma, almacenamiento seguro del SO, memoria, distribución. Prioridad: Seguridad > Privacidad > Fiabilidad > Mantenibilidad > Usabilidad > Estética. No elegir solo por facilidad de programación.

## 22. MULTIPLATAFORMA

Diseñar para Windows 11, Linux, macOS. Si no las tres al inicio: empezar por Windows con arquitectura preparada. Dependencias específicas de Windows encapsuladas.

## 23. SECRETOS DEL SISTEMA OPERATIVO

Investigar DPAPI/Credential Manager, Keychain, Secret Service/libsecret. Pueden proteger secretos auxiliares; nunca la contraseña maestra en texto recuperable. Explicar qué se guarda ahí.

## 24. LOGS

Logging seguro; tests que comprueben que secretos no aparecen en logs.

## 25. PRIVACIDAD

Sin analytics, telemetría, APIs externas, ni comprobación online de contraseñas. Cualquier red futura: off by default, identificada, separada, explicada.

## 26. TESTS DE SEGURIDAD

Crypto, auth, CRUD, políticas, auditoría sin secretos, portapapeles, master password no almacenada, no secretos en logs/temps/hardcode, no red inesperada.

## 27. ANÁLISIS DE AMENAZAS

Crear `docs/THREAT_MODEL.md` con escenarios: acceso sin sesión; con sesión; malware user; malware admin/root; robo de bóveda; robo de backup; manipulación DB; portapapeles; capturas; keyloggers. Documentar limitaciones; nunca "100% seguro".

## 28. DOCUMENTACIÓN

README.md, docs/ARCHITECTURE.md, SECURITY.md, THREAT_MODEL.md, DATABASE.md, BACKUP.md, AUDIT.md, DEVELOPMENT.md.

## 29. CONTROL DE VERSIONES Y MIGRACIONES

Schema version + migraciones con backup e integridad antes/después.

## 30. CALIDAD DEL CÓDIGO

Capas, interfaces crypto/storage/audit, SOLID razonable; funciones de secretos claramente identificadas.

## 31–33. DEPENDENCIAS, CI/CD, FIRMA

Lockfiles, SCA, Dependabot/Renovate, pipeline tests/lint/SCA/secret scan/build. Arquitectura lista para code signing / notarization; sin certificados en el repo.

## 34. FUNCIONALIDADES FUTURAS

Diseñar extensibilidad (múltiples bóvedas/usuarios, TOTP, passkeys, FIDO2, certs, SSH, API keys, sync, browser, breach check, políticas corporativas) sin implementarlas ahora salvo necesidad arquitectónica.

## 35. NO INVENTAR SEGURIDAD

Investigar y documentar dudas. Sin afirmaciones absolutistas ("militarmente seguro", "imposible de hackear", "100% seguro").

## 36. FORMA DE TRABAJO — FASES

FASE 0 Análisis (esperar aprobación) → 1 Esqueleto → 2 Criptografía (tests antes de seguir) → 3 Bóveda → 4 Credenciales → 5 Políticas → 6 Generador → 7 Historial/auditoría → 8 Seguridad sistema → 9 UI → 10 Hardening.

## 37. CHECKLIST ANTES DE CADA FEATURE DE SECRETOS

¿Texto plano, logs, memoria, temps, backups, Internet, errores, historial shell, portapapeles, debug?

## 38. ENTREGABLE FINAL

Código, ejecutable, instalador, tests, docs, threat model, crypto docs, backup, auditoría, generador, políticas, historial, auto-lock, clipboard clear, import/export cifrado, `docs/SECURITY_REVIEW.md`.

## 39. REGLA FINAL

Priorizar seguridad de secretos. Cada decisión debe responder: ¿qué si roban la bóveda / tienen la sesión / modifican la DB / hay malware / qué queda expuesto?
