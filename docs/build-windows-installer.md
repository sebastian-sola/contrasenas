# Cómo generar el instalador Windows de Contraseñas

**Versión documentada:** 0.1.0  
**Producto:** Contraseñas (`app.contrasenas.desktop`)  
**Salida esperada:** `Contrasenas-Setup-0.1.0-windows.exe` (NSIS) y, si aplica, `.msi`  
**Firma:** sin firma de código en esta etapa (evaluación). Windows SmartScreen puede avisar.

---

## Situación de este entorno

Este repositorio se ha trabajado desde un agente en **Linux**. Desde Linux **no** se genera de forma fiable un instalador Windows normal (hace falta Windows o CI `windows-latest`).

El workflow [`.github/workflows/windows-installer.yml`](../.github/workflows/windows-installer.yml) está preparado para producir el `.exe` / `.msi` en un runner Windows.

Si el remoto es un repo temporal de agente (Origin / `agent_temp`) **sin GitHub Actions**, el workflow no se ejecutará hasta que el código esté en un GitHub (u otro forge) con Actions habilitado, o hasta que alguien compile en un PC Windows.

---

## Opción A — GitHub Actions (recomendada)

1. Empuja esta rama (o fusiónala a `main`) a un repositorio con **GitHub Actions**.
2. Ve a **Actions** → workflow **Windows installer**.
3. Lanza **Run workflow** (`workflow_dispatch`), o espera a un push a `main` / `cursor/windows-installer*`.
4. Cuando el job termine en verde, abre el run → **Artifacts**.
5. Descarga `Contrasenas-Setup-0.1.0-windows` (incluye `.exe`, opcional `.msi`, y `.sha256`).
6. Entrega el archivo a Sebastián y sigue [`instalacion-en-tu-pc.md`](instalacion-en-tu-pc.md) (secciones 2–4).

**Avisos esperados:** instalador **sin firmar** → SmartScreen “Windows protegió su PC” → Más información → Ejecutar de todas formas (solo si el archivo viene de esta fuente de confianza).

---

## Opción B — PC Windows con herramientas de desarrollo

En un Windows 10/11 con Node 22+, pnpm 9, Rust estable:

```powershell
pnpm --dir apps/desktop install
pnpm --dir apps/desktop tauri build --bundles nsis,msi
```

Busca los instaladores en (según layout Cargo):

- `target/release/bundle/nsis/*-setup.exe`
- `target/release/bundle/msi/*.msi`

Renombra/copia a nombres claros:

```text
Contrasenas-Setup-0.1.0-windows.exe
Contrasenas-Setup-0.1.0-windows.msi
```

Genera SHA-256 (PowerShell):

```powershell
Get-FileHash -Algorithm SHA256 .\Contrasenas-Setup-0.1.0-windows.exe
```

---

## Opción C — Cross-compile desde Linux (último recurso)

Tauri documenta NSIS vía `cargo-xwin` + target `x86_64-pc-windows-msvc`.  
Este proyecto usa **SQLCipher + OpenSSL vendored**; el cross-compile suele fallar o ser frágil. Preferir Opción A o B.

---

## Qué NO hacer en esta etapa

- No subir el instalador a un SaaS público todavía (distribución pausada hasta evaluación).
- No afirmar que Contraseñas ya está instalada en el PC de Sebastián.
- No meter certificados de firma en el repositorio.

---

## Checklist de entrega a Sebastián

- [ ] Existe `Contrasenas-Setup-0.1.0-windows.exe` (y `.sha256`)
- [ ] Procedencia clara (Actions artifact o copia acordada en Context)
- [ ] Instrucciones SmartScreen explicadas
- [ ] Actualizado el §0 de `instalacion-en-tu-pc.md` con el nombre exacto del archivo
