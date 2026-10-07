# Spike SQLCipher (Fase 1 — nota)

**Estado:** pendiente de build real multi-OS.  
**Decisión aprobada (D2):** SQLCipher + AEAD de campos; fallback blob AEAD si el empaquetado bloquea.

## Qué se hizo en Fase 1

- Trait `VaultStore` + `StorageBackendKind::{SqlCipherAead, BlobAeadFallback}` en `crates/vault-storage`.
- Preferencia por defecto: SQLCipher.
- **No** se enlazó aún `rusqlite`/`libsqlcipher` (evita romper CI sin deps nativas).

## Qué falta (Fase 3 / spike dedicado)

1. Probar `rusqlite` con feature SQLCipher en Windows (prioridad), Linux y macOS.
2. Documentar flags de `OPENSSL`/`SQLCIPHER` en el entorno de build.
3. Si un OS objetivo falla de forma bloqueante: activar `BlobAeadFallback` detrás del mismo trait sin cambiar el modelo de dominio.

## Criterio de éxito del spike

Abrir/crear un fichero cifrado de prueba (sin secretos de usuario) en el OS prioritario y verificar que sin clave no se leen páginas/metadatos útiles.
