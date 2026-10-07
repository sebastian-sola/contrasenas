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

type CredentialSummary = {
  id: string;
  serviceName: string;
  username: string | null;
  category: string | null;
  environment: string | null;
  status: string;
  expiryColor: string;
  nextRenewalAt: string | null;
  reuseCount: number;
};

type Credential = {
  id: string;
  serviceName: string;
  category: string | null;
  description: string | null;
  url: string | null;
  systemApp: string | null;
  environment: string | null;
  username: string | null;
  password: string;
  authType: string | null;
  domain: string | null;
  email: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  passwordChangedAt: string | null;
  nextRenewalAt: string | null;
  expiryPolicy: string | null;
  status: string;
  strengthScore: number | null;
  policyCompliant: boolean | null;
  deleted: boolean;
  reuseCount: number;
  expiryColor: string;
};

type HistoryEntry = {
  id: string;
  credentialId: string;
  timestamp: string;
  actor: string | null;
  action: string;
  fieldsChanged: string[];
  reason: string | null;
};

type FormState = {
  serviceName: string;
  username: string;
  password: string;
  url: string;
  email: string;
  category: string;
  environment: string;
  notes: string;
  nextRenewalAt: string;
  reason: string;
};

const emptyForm = (): FormState => ({
  serviceName: "",
  username: "",
  password: "",
  url: "",
  email: "",
  category: "",
  environment: "",
  notes: "",
  nextRenewalAt: "",
  reason: "",
});

function opt(value: string): string | null {
  const t = value.trim();
  return t.length ? t : null;
}

function daysFromNowInput(days: number): string {
  const secs = Math.floor(Date.now() / 1000) + days * 86400;
  return String(secs);
}

function expiryLabel(color: string): string {
  switch (color) {
    case "green":
      return "OK (>30 días)";
    case "yellow":
      return "≤30 días";
    case "orange":
      return "≤7 días";
    case "red":
      return "Caducada";
    default:
      return "Sin fecha";
  }
}

function App() {
  const [info, setInfo] = useState<PhaseInfo | null>(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [recoveryOnce, setRecoveryOnce] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [items, setItems] = useState<CredentialSummary[]>([]);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Credential | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showPassword, setShowPassword] = useState(false);
  const [mode, setMode] = useState<"list" | "create" | "edit">("list");
  const [form, setForm] = useState<FormState>(emptyForm());
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      const data = await invoke<PhaseInfo>("get_phase_info");
      setInfo(data);
      setLoadError(null);
      return data;
    } catch (err) {
      setLoadError(
        "Modo vista previa web: la bóveda real solo funciona en la app de escritorio.",
      );
      setInfo({
        phase: 4,
        schemaVersion: 2,
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
      return null;
    }
  }

  async function loadList(q?: string) {
    try {
      const list = await invoke<CredentialSummary[]>("credentials_list", {
        query: q && q.trim() ? q.trim() : null,
      });
      setItems(list);
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function loadDetail(id: string) {
    try {
      const cred = await invoke<Credential>("credentials_get", { id });
      setDetail(cred);
      setShowPassword(false);
      const hist = await invoke<HistoryEntry[]>("credentials_history", { id });
      setHistory(hist);
    } catch (err) {
      setMessage(String(err));
      setDetail(null);
      setHistory([]);
    }
  }

  useEffect(() => {
    void (async () => {
      const data = await refresh();
      if (data?.sessionState === "unlocked") {
        await loadList("");
      }
    })();
  }, []);

  async function onCreateVault(e: FormEvent) {
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
      await loadList("");
      setMode("list");
      setSelectedId(null);
      setDetail(null);
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
      setItems([]);
      setDetail(null);
      setHistory([]);
      setSelectedId(null);
      setMode("list");
      setForm(emptyForm());
      await refresh();
    } catch (err) {
      setMessage(String(err));
    }
  }

  function openCreate() {
    setMode("create");
    setSelectedId(null);
    setDetail(null);
    setHistory([]);
    setForm({
      ...emptyForm(),
      nextRenewalAt: daysFromNowInput(45),
    });
    setShowPassword(true);
  }

  function openEdit() {
    if (!detail) return;
    setMode("edit");
    setForm({
      serviceName: detail.serviceName,
      username: detail.username ?? "",
      password: detail.password,
      url: detail.url ?? "",
      email: detail.email ?? "",
      category: detail.category ?? "",
      environment: detail.environment ?? "",
      notes: detail.notes ?? "",
      nextRenewalAt: detail.nextRenewalAt ?? "",
      reason: "",
    });
    setShowPassword(false);
  }

  async function onSaveCredential(e: FormEvent) {
    e.preventDefault();
    if (!form.serviceName.trim() || !form.password) {
      setMessage("Servicio y contraseña son obligatorios.");
      return;
    }
    setBusy(true);
    setMessage(null);
    const input = {
      serviceName: form.serviceName.trim(),
      category: opt(form.category),
      description: null as string | null,
      url: opt(form.url),
      systemApp: null as string | null,
      environment: opt(form.environment),
      username: opt(form.username),
      password: form.password,
      authType: null as string | null,
      domain: null as string | null,
      email: opt(form.email),
      notes: opt(form.notes),
      nextRenewalAt: opt(form.nextRenewalAt),
      expiryPolicy: null as string | null,
      reason: opt(form.reason),
    };
    try {
      const saved =
        mode === "edit" && selectedId
          ? await invoke<Credential>("credentials_update", {
              id: selectedId,
              input,
            })
          : await invoke<Credential>("credentials_create", { input });
      setMessage(
        mode === "edit" ? "Credencial actualizada." : "Credencial guardada.",
      );
      setMode("list");
      setSelectedId(saved.id);
      await loadList(query);
      await loadDetail(saved.id);
      setForm(emptyForm());
    } catch (err) {
      setMessage(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (!selectedId || !detail) return;
    if (
      !window.confirm(
        `¿Archivar «${detail.serviceName}»? Se puede restaurar más adelante.`,
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      await invoke("credentials_delete", { id: selectedId });
      setMessage("Credencial archivada.");
      setSelectedId(null);
      setDetail(null);
      setHistory([]);
      await loadList(query);
    } catch (err) {
      setMessage(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function selectItem(id: string) {
    setMode("list");
    setSelectedId(id);
    await loadDetail(id);
  }

  async function onSearch(e: FormEvent) {
    e.preventDefault();
    await loadList(query);
  }

  if (info?.sessionState === "unlocked") {
    return (
      <main className="vault-app">
        <header className="vault-top">
          <div>
            <p className="brand">Contraseñas</p>
            <h1>Tus credenciales</h1>
            <p className="lede">
              Fase {info.phase}: guardar, buscar y editar. La contraseña se
              oculta; el reuso solo muestra cuántas veces se repite.
            </p>
          </div>
          <div className="vault-actions">
            <button type="button" className="secondary" onClick={onLock}>
              Bloquear
            </button>
            <button type="button" onClick={openCreate}>
              Nueva
            </button>
          </div>
        </header>

        {message && (
          <p className="toast banner" role="status">
            {message}
          </p>
        )}

        <div className="vault-grid">
          <section className="panel list-panel" aria-label="Lista">
            <form className="search-row" onSubmit={onSearch}>
              <label htmlFor="search" className="sr-only">
                Buscar
              </label>
              <input
                id="search"
                value={query}
                onChange={(e) => setQuery(e.currentTarget.value)}
                placeholder="Buscar servicio, usuario…"
              />
              <button type="submit" className="secondary">
                Buscar
              </button>
            </form>

            {items.length === 0 ? (
              <p className="empty">
                No hay credenciales todavía. Pulsa <strong>Nueva</strong> para
                guardar la primera.
              </p>
            ) : (
              <ul className="cred-list">
                {items.map((item) => (
                  <li key={item.id}>
                    <button
                      type="button"
                      className={
                        selectedId === item.id ? "cred-row active" : "cred-row"
                      }
                      onClick={() => void selectItem(item.id)}
                    >
                      <span className="cred-name">{item.serviceName}</span>
                      <span className="cred-meta">
                        {item.username || "sin usuario"}
                        {item.reuseCount > 1
                          ? ` · reusada ${item.reuseCount}×`
                          : ""}
                      </span>
                      <span
                        className={`dot expiry-${item.expiryColor}`}
                        title={expiryLabel(item.expiryColor)}
                      />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="panel detail-panel" aria-label="Detalle">
            {(mode === "create" || mode === "edit") && (
              <form className="cred-form" onSubmit={onSaveCredential}>
                <h2>{mode === "create" ? "Nueva credencial" : "Editar"}</h2>
                <label htmlFor="svc">Servicio *</label>
                <input
                  id="svc"
                  value={form.serviceName}
                  onChange={(e) =>
                    setForm({ ...form, serviceName: e.currentTarget.value })
                  }
                  required
                />
                <label htmlFor="user">Usuario</label>
                <input
                  id="user"
                  value={form.username}
                  onChange={(e) =>
                    setForm({ ...form, username: e.currentTarget.value })
                  }
                />
                <label htmlFor="pwd">Contraseña *</label>
                <div className="pw-row">
                  <input
                    id="pwd"
                    type={showPassword ? "text" : "password"}
                    value={form.password}
                    onChange={(e) =>
                      setForm({ ...form, password: e.currentTarget.value })
                    }
                    required
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => setShowPassword((v) => !v)}
                  >
                    {showPassword ? "Ocultar" : "Mostrar"}
                  </button>
                </div>
                <label htmlFor="url">URL</label>
                <input
                  id="url"
                  value={form.url}
                  onChange={(e) =>
                    setForm({ ...form, url: e.currentTarget.value })
                  }
                />
                <label htmlFor="email">Correo</label>
                <input
                  id="email"
                  value={form.email}
                  onChange={(e) =>
                    setForm({ ...form, email: e.currentTarget.value })
                  }
                />
                <div className="two-col">
                  <div>
                    <label htmlFor="cat">Categoría</label>
                    <input
                      id="cat"
                      value={form.category}
                      onChange={(e) =>
                        setForm({ ...form, category: e.currentTarget.value })
                      }
                    />
                  </div>
                  <div>
                    <label htmlFor="env">Entorno</label>
                    <input
                      id="env"
                      value={form.environment}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          environment: e.currentTarget.value,
                        })
                      }
                      placeholder="prod / test"
                    />
                  </div>
                </div>
                <label htmlFor="renew">Caducidad (unix seconds)</label>
                <input
                  id="renew"
                  value={form.nextRenewalAt}
                  onChange={(e) =>
                    setForm({ ...form, nextRenewalAt: e.currentTarget.value })
                  }
                  placeholder="opcional"
                />
                <div className="chip-row">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() =>
                      setForm({
                        ...form,
                        nextRenewalAt: daysFromNowInput(45),
                      })
                    }
                  >
                    +45 días
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    onClick={() =>
                      setForm({
                        ...form,
                        nextRenewalAt: daysFromNowInput(7),
                      })
                    }
                  >
                    +7 días
                  </button>
                </div>
                <label htmlFor="notes">Notas</label>
                <textarea
                  id="notes"
                  rows={3}
                  value={form.notes}
                  onChange={(e) =>
                    setForm({ ...form, notes: e.currentTarget.value })
                  }
                />
                {mode === "edit" && (
                  <>
                    <label htmlFor="reason">Motivo del cambio</label>
                    <input
                      id="reason"
                      value={form.reason}
                      onChange={(e) =>
                        setForm({ ...form, reason: e.currentTarget.value })
                      }
                      placeholder="opcional"
                    />
                  </>
                )}
                <div className="form-actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      setMode("list");
                      setForm(emptyForm());
                      if (selectedId) void loadDetail(selectedId);
                    }}
                  >
                    Cancelar
                  </button>
                  <button type="submit" disabled={busy}>
                    Guardar
                  </button>
                </div>
              </form>
            )}

            {mode === "list" && !detail && (
              <p className="empty">
                Elige una credencial de la lista o crea una nueva.
              </p>
            )}

            {mode === "list" && detail && (
              <div className="detail-view">
                <div className="detail-head">
                  <h2>{detail.serviceName}</h2>
                  <span className={`badge expiry-${detail.expiryColor}`}>
                    {detail.status} · {expiryLabel(detail.expiryColor)}
                  </span>
                </div>
                <dl className="detail-fields">
                  <div>
                    <dt>Usuario</dt>
                    <dd>{detail.username || "—"}</dd>
                  </div>
                  <div className="wide">
                    <dt>Contraseña</dt>
                    <dd className="pw-row">
                      <code>
                        {showPassword ? detail.password : "••••••••••••"}
                      </code>
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => setShowPassword((v) => !v)}
                      >
                        {showPassword ? "Ocultar" : "Mostrar"}
                      </button>
                    </dd>
                  </div>
                  <div>
                    <dt>URL</dt>
                    <dd>{detail.url || "—"}</dd>
                  </div>
                  <div>
                    <dt>Correo</dt>
                    <dd>{detail.email || "—"}</dd>
                  </div>
                  <div>
                    <dt>Categoría</dt>
                    <dd>{detail.category || "—"}</dd>
                  </div>
                  <div>
                    <dt>Entorno</dt>
                    <dd>{detail.environment || "—"}</dd>
                  </div>
                  <div>
                    <dt>Reutilización</dt>
                    <dd>
                      {detail.reuseCount > 1
                        ? `Misma contraseña en ${detail.reuseCount} servicios`
                        : "No reusada"}
                    </dd>
                  </div>
                  <div>
                    <dt>Caducidad</dt>
                    <dd>{detail.nextRenewalAt || "—"}</dd>
                  </div>
                  <div className="wide">
                    <dt>Notas</dt>
                    <dd>{detail.notes || "—"}</dd>
                  </div>
                </dl>
                <div className="form-actions">
                  <button type="button" onClick={openEdit}>
                    Editar
                  </button>
                  <button
                    type="button"
                    className="danger"
                    onClick={() => void onDelete()}
                    disabled={busy}
                  >
                    Archivar
                  </button>
                </div>
                {history.length > 0 && (
                  <div className="history">
                    <h3>Historial (sin contraseñas antiguas)</h3>
                    <ul>
                      {history.map((h) => (
                        <li key={h.id}>
                          <strong>{h.action}</strong>
                          {h.fieldsChanged.length
                            ? `: ${h.fieldsChanged.join(", ")}`
                            : ""}
                          {h.reason ? ` — ${h.reason}` : ""}
                          <span className="hist-time"> · {h.timestamp}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      </main>
    );
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
          Fase <strong>4</strong>: puedes guardar y editar contraseñas de sitios
          dentro de la bóveda cifrada.
        </p>

        {info && !info.vaultExists && info.sessionState === "locked" && (
          <form className="lock-form" onSubmit={onCreateVault}>
            <label htmlFor="master-create">
              Crear bóveda — contraseña maestra
            </label>
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
