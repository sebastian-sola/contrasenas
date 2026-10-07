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
  vaultExists: boolean;
};

function App() {
  const [info, setInfo] = useState<PhaseInfo | null>(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [recoveryOnce, setRecoveryOnce] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  async function refresh() {
    try {
      const data = await invoke<PhaseInfo>("get_phase_info");
      setInfo(data);
      setLoadError(null);
    } catch (err) {
      setLoadError(
        "Modo vista previa web: la bóveda real solo funciona en la app de escritorio.",
      );
      setInfo({
        phase: 3,
        schemaVersion: 1,
        sessionState: "locked",
        storageBackend: "sqlcipher_aead",
        recoverySummary:
          "Kit de emergencia: código aparte; la contraseña maestra nunca se guarda.",
        backupFormatVersion: 1,
        dataDirHint: "(data-dir-del-SO)",
        productionCrypto: true,
        vaultExists: false,
      });
      console.debug("get_phase_info", err);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setMessage(null);
    setRecoveryOnce(null);
    try {
      const code = await invoke<string>("vault_create", {
        masterPassword: password,
      });
      setPassword("");
      if (code) {
        setRecoveryOnce(code);
        setMessage(
          "Bóveda creada. Guarda el código de emergencia en un lugar seguro (papel). No se volverá a mostrar.",
        );
      } else {
        setMessage("Bóveda creada.");
      }
      await refresh();
    } catch (err) {
      setMessage(String(err));
      setPassword("");
    }
  }

  async function onUnlock(e: FormEvent) {
    e.preventDefault();
    setMessage(null);
    try {
      await invoke("try_unlock", { masterPassword: password });
      setMessage("Bóveda desbloqueada.");
      setPassword("");
      await refresh();
    } catch (err) {
      setMessage(String(err));
      setPassword("");
      await refresh();
    }
  }

  async function onLock() {
    try {
      await invoke("lock_session");
      setMessage("Bóveda bloqueada. Claves borradas de memoria.");
      await refresh();
    } catch (err) {
      setMessage(String(err));
    }
  }

  return (
    <main className="lock-screen">
      <div className="lock-card">
        <p className="brand">Contraseñas</p>
        <h1>
          {info?.sessionState === "unlocked"
            ? "Bóveda abierta"
            : "Bóveda bloqueada"}
        </h1>
        <p className="lede">
          Fase <strong>3</strong>: ya se puede crear y abrir una bóveda en el
          disco. Todavía no se guardan contraseñas de sitios (eso es la fase
          4).
        </p>

        {info && !info.vaultExists && info.sessionState === "locked" && (
          <form className="lock-form" onSubmit={onCreate}>
            <label htmlFor="master-create">Crear bóveda — contraseña maestra</label>
            <input
              id="master-create"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              placeholder="Elige una contraseña fuerte"
            />
            <button type="submit">Crear bóveda</button>
          </form>
        )}

        {info?.vaultExists && info.sessionState === "locked" && (
          <form className="lock-form" onSubmit={onUnlock}>
            <label htmlFor="master">Contraseña maestra</label>
            <input
              id="master"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              placeholder="Desbloquear"
            />
            <button type="submit">Desbloquear</button>
          </form>
        )}

        {info?.sessionState === "unlocked" && (
          <button type="button" onClick={onLock}>
            Bloquear
          </button>
        )}

        {recoveryOnce && (
          <p className="toast" role="status">
            Código de emergencia (cópialo ahora): <code>{recoveryOnce}</code>
          </p>
        )}
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
              <dt>Almacén</dt>
              <dd>{info.storageBackend}</dd>
            </div>
            <div>
              <dt>Bóveda en disco</dt>
              <dd>{info.vaultExists ? "sí" : "no"}</dd>
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
