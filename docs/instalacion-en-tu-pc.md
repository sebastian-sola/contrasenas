# Instalar Contraseñas en tu PC (evaluación)

**Para:** Sebastián  
**Modelo:** instalación local en **tu** ordenador. Las contraseñas quedan solo en ese equipo.  
**Estado del instalador:** ver sección 0.

---

## 0. Situación actual (importante)

**Actualizado:** 2026-10-08 (preparación del instalador Windows).

Hoy la aplicación está terminada en el **plan base** y se ha probado en el ordenador del agente (nube).

| Qué | Estado |
|-----|--------|
| App usable en Try Live (nube) | Sí |
| Configuración Tauri para Windows (NSIS + MSI), nombre **Contraseñas**, iconos | Lista en el código |
| Workflow CI `windows-installer.yml` (construye en `windows-latest`) | Listo en el repo |
| Archivo instalador real `.exe` / `.msi` en Context | **Todavía no** |
| Instalado en el PC de Sebastián | **No** |

El agente trabaja en **Linux**: no puede generar aquí un instalador Windows normal. El siguiente paso es ejecutar el workflow en un GitHub con Actions (o compilar en un PC Windows). Detalle técnico: [build-windows-installer.md](build-windows-installer.md).

Cuando el instalador exista, el nombre previsto será:

- `Contrasenas-Setup-0.1.0-windows.exe` (recomendado, instalador NSIS)
- opcional: `Contrasenas-Setup-0.1.0-windows.msi`
- y su archivo `.sha256` de comprobación

Será un instalador **sin firma** de código → Windows puede mostrar **SmartScreen** (sección 3).

Mientras tanto, las instrucciones de abajo son las que seguirás **cuando tengas ese archivo**.  
Puedes seguir probando la app en [Try Live](bc-fb36c679-5180-5c68-a3b6-1e9fbd81882f#desktop) (nube), que **no** es lo mismo que tenerla en tu PC.

No uses copias raras ni enlaces de terceros: solo el archivo que te demos nosotros o que subamos a un sitio que tú controles.

---

## 1. Qué necesitas

- Un PC con **Windows 10 u 11** (recomendado Windows 11).
- Permiso para instalar programas (cuenta de administrador si Windows lo pide).
- Unos minutos y un sitio seguro para anotar el **kit de emergencia** (papel o lugar offline).
- El archivo instalador oficial (cuando esté listo).

**No necesitas** saber programar ni instalar Rust, Node, etc. Eso solo sería si se instalara “desde código”, y **no** es el camino recomendado para ti.

---

## 2. Antes de instalar (checklist)

1. Cierra otras apps si puedes (menos avisos raros).
2. Ten a mano un sitio para guardar el **kit de emergencia** (no lo dejes solo en una captura de pantalla del escritorio).
3. Decide una **contraseña maestra** fuerte que solo tú sepas. Si la olvidas y pierdes el kit, no se puede abrir la caja fuerte.
4. Si usas antivirus corporativo, puede avisar al primer instalador **sin firma**; en ese caso, confirma que el archivo viene de nosotros / de tu fuente de confianza.

---

## 3. Instalación paso a paso (cuando tengas el instalador)

### Paso 1 — Conseguir el archivo
- Te pasaremos el instalador (enlace de descarga seguro o archivo en Context / carpeta que acordemos).
- Guárdalo, por ejemplo, en **Descargas**.
- Comprueba el nombre (algo como `Contraseñas-Setup-1.0.0.exe`).

### Paso 2 — Abrir el instalador
1. Ve a la carpeta Descargas.
2. Doble clic en el archivo.
3. Si Windows pregunta “¿Quieres permitir que esta app haga cambios?”, pulsa **Sí**.

### Paso 3 — Aviso de Windows SmartScreen (si aparece)
Si sale “Windows protegió su PC”:

1. Pulsa **Más información**.
2. Pulsa **Ejecutar de todas formas** **solo** si estás seguro de que el archivo es el nuestro.
3. Cuando el instalador vaya **firmado** con certificado, este aviso suele ser mucho menos frecuente.

### Paso 4 — Asistente de instalación
1. Elige idioma si lo pide.
2. Acepta la carpeta por defecto (recomendado) o elige otra.
3. Marca “crear acceso directo” si quieres.
4. Pulsa **Instalar** y espera.
5. Pulsa **Finalizar**.

### Paso 5 — Abrir Contraseñas
1. Busca **Contraseñas** en el menú Inicio, o usa el acceso directo.
2. Se abre la pantalla de bloqueo / primera configuración.

---

## 4. Primera vez: crear tu caja fuerte

1. En la pantalla inicial, elige **crear** / abrir bóveda nueva (según el texto de la app).
2. Escribe una **contraseña maestra** fuerte y confírmala.
3. La app te mostrará un **código / kit de emergencia**.
4. **Cópialo y guárdalo fuera del PC** (papel en lugar seguro). Sin eso, si olvidas la maestra, no hay recuperación.
5. Confirma que lo has guardado (si la app lo pide).
6. Ya puedes entrar: Inicio, Contraseñas, Reglas, Generador, Actividad, Ajustes.

**Importante:** esta caja fuerte es solo de **este** ordenador. No se sube a tu servidor SaaS.

---

## 5. Uso diario (resumen)

1. Abres Contraseñas.
2. Escribes la contraseña maestra → **Abrir**.
3. Trabajas (añadir, copiar, generar…).
4. Al copiar una contraseña, se borra del portapapeles a los pocos segundos (por defecto 30 s; se puede cambiar en Ajustes).
5. Si dejas el PC, se bloquea sola tras un tiempo (por defecto 5 minutos; configurable).
6. Cierra o pulsa **Bloquear** al terminar.

---

## 6. Copias de seguridad (recomendado al evaluar)

En **Ajustes**:
1. Crea un **backup cifrado** (archivo `.cpbak`).
2. Guárdalo en un sitio seguro (disco externo / carpeta privada).
3. De vez en cuando verifica el backup desde la propia app.

Ese backup también va protegido; no es un Word con contraseñas en claro.

---

## 7. Desinstalar (si quieres quitarla)

1. Windows → **Configuración** → **Aplicaciones** → buscar **Contraseñas** → Desinstalar.  
2. La desinstalación puede **dejar** la carpeta de datos (caja fuerte). En Windows, cuando la app esté empaquetada, los datos suelen estar en algo como:  
   `%APPDATA%\Contraseñas`  
   (carpeta oculta de tu usuario; no está dentro de Cursor). Si quieres borrarlo todo, desinstala y luego elimina esa carpeta.

---

## 8. Qué no hacer

- No instales desde webs desconocidas.
- No compartas la contraseña maestra ni el kit de emergencia por email/WhatsApp.
- No copies la caja fuerte a un servidor web “porque sí”.
- No esperes que Try Live (el escritorio del agente) sea lo mismo que tu PC: eso es solo la prueba en la nube.

---

## 9. Siguiente paso práctico (para Sebastián)

1. Cuando te pasemos el archivo `Contrasenas-Setup-0.1.0-windows.exe` (desde el artefacto de Actions o desde Context), guárdalo en Descargas.
2. Sigue las secciones **2–4** de este documento (instalación + SmartScreen + primera bóveda).
3. Evalúas la app **en tu PC Windows**.
4. La distribución por tu SaaS queda **pausada** hasta que termines esa evaluación.

---

*Documento de instrucciones. No instala nada por sí solo.*
