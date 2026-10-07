import { FormEvent, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type PhaseInfo = {
  phase: number;
  schemaVersion: number;
  sessionState: string;
  storageBackend: string;
  recoverySummary: string;
  backupFormatVersion: number;
  dataDirHint: string;
  productionCrypto: boolean;
};

function App() {
  const [info, setInfo] = useState<PhaseInfo | null>(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await invoke<PhaseInfo>("get_phase_info");
        if (!cancelled) setInfo(data);
      } catch (err) {
        if (!cancelled) {
          setLoadError(
            "Modo vista previa web: el desbloqueo real solo existe dentro de la app de escritorio.",
          );
          setInfo({
            phase: 1,
            schemaVersion: 0,
            sessionState: "locked",
            storageBackend: "sqlcipher_aead",
            recoverySummary:
              "Kit de emergencia (diseño): código aparte; la contraseña maestra nunca se guarda.",
            backupFormatVersion: 1,
            dataDirHint: "(data-dir-del-SO)",
            productionCrypto: false,
          });
        }
        console.debug("get_phase_info", err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setMessage(null);
    try {
      await invoke("try_unlock", { masterPassword: password });
      setMessage("Desbloqueo inesperado (no debería ocurrir en Fase 1).");
    } catch {
      setMessage(
        "Fase 1: el desbloqueo real aún no está activo. La contraseña no se guarda.",
      );
    } finally {
      setPassword("");
    }
  }

  return (
    <main className="lock-screen">
      <div className="lock-card">
        <p className="brand">Contraseñas</p>
        <h1>Bóveda bloqueada</h1>
        <p className="lede">
          Gestor local de secretos. Estamos en la <strong>fase 1</strong>:
          esqueleto de la aplicación. Todavía no se crean ni abren bóvedas
          reales.
        </p>

        <form className="lock-form" onSubmit={onSubmit}>
          <label htmlFor="master">
            Contraseña maestra (solo prueba de interfaz)
          </label>
          <input
            id="master"
            type="password"
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
            placeholder="No se almacena en esta fase"
          />
          <button type="submit">Intentar desbloqueo (stub)</button>
        </form>

        {message && (
          <p className="toast" role="status">
            {message}
          </p>
        )}
        {loadError && <p className="hint">{loadError}</p>}

        {info && (
          <dl className="meta">
            <div>
              <dt>Fase</dt>
              <dd>{info.phase}</dd>
            </div>
            <div>
              <dt>Sesión</dt>
              <dd>{info.sessionState}</dd>
            </div>
            <div>
              <dt>Almacén previsto</dt>
              <dd>{info.storageBackend}</dd>
            </div>
            <div>
              <dt>Crypto de producción</dt>
              <dd>{info.productionCrypto ? "sí" : "no (aún)"}</dd>
            </div>
            <div className="wide">
              <dt>Kit de emergencia</dt>
              <dd>{info.recoverySummary}</dd>
            </div>
          </dl>
        )}
      </div>
    </main>
  );
}

export default App;
