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
  policyId: string | null;
  policyCompliant: boolean | null;
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
  policyId: string | null;
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

type PasswordPolicy = {
  id: string;
  name: string;
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  allowSpaces: boolean;
  forbiddenChars: string;
  forbiddenPatterns: string[];
  previousPasswordCount: number;
  expiryDays: number | null;
  extraRulesJson: string | null;
  createdAt: string;
  updatedAt: string;
};

type PolicyValidation = {
  compliant: boolean;
  violations: string[];
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
  policyId: string;
  reason: string;
};

type PolicyForm = {
  name: string;
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  allowSpaces: boolean;
  forbiddenChars: string;
  forbiddenPatterns: string;
  previousPasswordCount: number;
  expiryDays: string;
  extraRulesJson: string;
  testPassword: string;
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
  policyId: "",
  reason: "",
});

const emptyPolicyForm = (): PolicyForm => ({
  name: "",
  minLength: 12,
  maxLength: 64,
  requireUppercase: true,
  requireLowercase: true,
  requireDigit: true,
  requireSymbol: true,
  allowSpaces: false,
  forbiddenChars: "",
  forbiddenPatterns: "",
  previousPasswordCount: 3,
  expiryDays: "90",
  extraRulesJson: "",
  testPassword: "",
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

function violationLabel(code: string): string {
  const map: Record<string, string> = {
    min_length: "Demasiado corta",
    max_length: "Demasiado larga",
    require_uppercase: "Falta mayúscula",
    require_lowercase: "Falta minúscula",
    require_digit: "Falta número",
    require_symbol: "Falta símbolo",
    spaces_not_allowed: "No se permiten espacios",
    forbidden_chars: "Caracteres prohibidos",
    forbidden_patterns: "Patrón prohibido",
    previous_password_reuse: "Ya usada antes",
    min_unique_chars: "Pocos caracteres distintos",
  };
  return map[code] ?? code;
}

function App() {
  const [info, setInfo] = useState<PhaseInfo | null>(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [recoveryOnce, setRecoveryOnce] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [tab, setTab] = useState<"creds" | "policies" | "generator">("creds");
  const [genOpts, setGenOpts] = useState({
    length: 20,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    avoidAmbiguous: true,
    customCharset: "",
    exclude: "",
    policyId: "",
  });
  const [generated, setGenerated] = useState<{
    password: string;
    length: number;
    entropyBits: number;
    strengthLabel: string;
    charsetSize: number;
    policyCompliant: boolean | null;
    policyViolations: string[];
    rng: string;
  } | null>(null);
  const [showGenPassword, setShowGenPassword] = useState(true);
  const [items, setItems] = useState<CredentialSummary[]>([]);
  const [policies, setPolicies] = useState<PasswordPolicy[]>([]);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Credential | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showPassword, setShowPassword] = useState(false);
  const [mode, setMode] = useState<"list" | "create" | "edit">("list");
  const [form, setForm] = useState<FormState>(emptyForm());
  const [busy, setBusy] = useState(false);

  const [policyMode, setPolicyMode] = useState<"list" | "create" | "edit">(
    "list",
  );
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [policyForm, setPolicyForm] = useState<PolicyForm>(emptyPolicyForm());
  const [validation, setValidation] = useState<PolicyValidation | null>(null);

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
        phase: 5,
        schemaVersion: 3,
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

  async function loadPolicies() {
    try {
      const list = await invoke<PasswordPolicy[]>("policies_list");
      setPolicies(list);
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
        await loadPolicies();
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
      await loadPolicies();
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
      setPolicies([]);
      setDetail(null);
      setHistory([]);
      setSelectedId(null);
      setMode("list");
      setForm(emptyForm());
      setPolicyMode("list");
      setValidation(null);
      await refresh();
    } catch (err) {
      setMessage(String(err));
    }
  }

  function openCreate() {
    setTab("creds");
    setMode("create");
    setSelectedId(null);
    setDetail(null);
    setHistory([]);
    setForm({
      ...emptyForm(),
      nextRenewalAt: daysFromNowInput(45),
      policyId: policies[0]?.id ?? "",
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
      policyId: detail.policyId ?? "",
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
      policyId: opt(form.policyId),
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

  function openPolicyCreate() {
    setPolicyMode("create");
    setSelectedPolicyId(null);
    setPolicyForm(emptyPolicyForm());
    setValidation(null);
  }

  function openPolicyEdit(p: PasswordPolicy) {
    setPolicyMode("edit");
    setSelectedPolicyId(p.id);
    setPolicyForm({
      name: p.name,
      minLength: p.minLength,
      maxLength: p.maxLength,
      requireUppercase: p.requireUppercase,
      requireLowercase: p.requireLowercase,
      requireDigit: p.requireDigit,
      requireSymbol: p.requireSymbol,
      allowSpaces: p.allowSpaces,
      forbiddenChars: p.forbiddenChars,
      forbiddenPatterns: p.forbiddenPatterns.join(", "),
      previousPasswordCount: p.previousPasswordCount,
      expiryDays: p.expiryDays != null ? String(p.expiryDays) : "",
      extraRulesJson: p.extraRulesJson ?? "",
      testPassword: "",
    });
    setValidation(null);
  }

  function policyInputFromForm() {
    const days = policyForm.expiryDays.trim();
    return {
      name: policyForm.name.trim(),
      minLength: policyForm.minLength,
      maxLength: policyForm.maxLength,
      requireUppercase: policyForm.requireUppercase,
      requireLowercase: policyForm.requireLowercase,
      requireDigit: policyForm.requireDigit,
      requireSymbol: policyForm.requireSymbol,
      allowSpaces: policyForm.allowSpaces,
      forbiddenChars: policyForm.forbiddenChars,
      forbiddenPatterns: policyForm.forbiddenPatterns
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      previousPasswordCount: policyForm.previousPasswordCount,
      expiryDays: days ? Number(days) : null,
      extraRulesJson: opt(policyForm.extraRulesJson),
    };
  }

  async function onSavePolicy(e: FormEvent) {
    e.preventDefault();
    if (!policyForm.name.trim()) {
      setMessage("El nombre de la política es obligatorio.");
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const input = policyInputFromForm();
      const saved =
        policyMode === "edit" && selectedPolicyId
          ? await invoke<PasswordPolicy>("policies_update", {
              id: selectedPolicyId,
              input,
            })
          : await invoke<PasswordPolicy>("policies_create", { input });
      setMessage(
        policyMode === "edit" ? "Política actualizada." : "Política creada.",
      );
      setPolicyMode("list");
      setSelectedPolicyId(saved.id);
      await loadPolicies();
    } catch (err) {
      setMessage(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDeletePolicy(id: string) {
    if (!window.confirm("¿Eliminar esta política? Se desasociará de las credenciales.")) {
      return;
    }
    setBusy(true);
    try {
      await invoke("policies_delete", { id });
      setMessage("Política eliminada.");
      setPolicyMode("list");
      setSelectedPolicyId(null);
      await loadPolicies();
      await loadList(query);
    } catch (err) {
      setMessage(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onValidateTest() {
    const pid = selectedPolicyId;
    if (!pid && policyMode !== "edit") {
      setMessage("Guarda la política primero para probarla, o edita una existente.");
      return;
    }
    const id = pid ?? selectedPolicyId;
    if (!id || !policyForm.testPassword) {
      setMessage("Escribe una contraseña de prueba.");
      return;
    }
    try {
      // Si estamos editando sin guardar, validamos con reglas guardadas en disco.
      const result = await invoke<PolicyValidation>("policies_validate", {
        policyId: id,
        password: policyForm.testPassword,
        credentialId: null,
      });
      setValidation(result);
      setMessage(
        result.compliant
          ? "Cumple la política."
          : "No cumple la política.",
      );
    } catch (err) {
      setMessage(String(err));
    }
  }

  function policyName(id: string | null | undefined): string {
    if (!id) return "Sin política";
    return policies.find((p) => p.id === id)?.name ?? "Política";
  }

  async function onGenerate() {
    setBusy(true);
    setMessage(null);
    try {
      const result = await invoke<{
        password: string;
        length: number;
        entropyBits: number;
        strengthLabel: string;
        charsetSize: number;
        policyCompliant: boolean | null;
        policyViolations: string[];
        rng: string;
      }>("generator_generate", {
        options: {
          length: genOpts.length,
          uppercase: genOpts.uppercase,
          lowercase: genOpts.lowercase,
          digits: genOpts.digits,
          symbols: genOpts.symbols,
          avoidAmbiguous: genOpts.avoidAmbiguous,
          customCharset: opt(genOpts.customCharset),
          exclude: genOpts.exclude,
        },
        policyId: opt(genOpts.policyId),
        credentialId: null,
      });
      setGenerated(result);
      setShowGenPassword(true);
      setMessage(
        result.policyCompliant === false
          ? "Generada, pero no cumple la política."
          : "Contraseña generada (aún no guardada).",
      );
    } catch (err) {
      setMessage(String(err));
    } finally {
      setBusy(false);
    }
  }

  function useGeneratedInForm() {
    if (!generated) return;
    setTab("creds");
    setMode("create");
    setSelectedId(null);
    setDetail(null);
    setForm({
      ...emptyForm(),
      password: generated.password,
      policyId: genOpts.policyId,
      nextRenewalAt: daysFromNowInput(45),
    });
    setShowPassword(true);
    setMessage(
      "Contraseña copiada al formulario. Completa el servicio y pulsa Guardar si quieres guardarla.",
    );
  }

  if (info?.sessionState === "unlocked") {
    return (
      <main className="vault-app">
        <header className="vault-top">
          <div>
            <p className="brand">Contraseñas</p>
            <h1>
              {tab === "creds"
                ? "Tus credenciales"
                : tab === "policies"
                  ? "Políticas"
                  : "Generador"}
            </h1>
            <p className="lede">
              Fase {info.phase}: generador seguro (CSPRNG). No se guarda sola —
              tú decides si usarla en una credencial.
            </p>
          </div>
          <div className="vault-actions">
            <button type="button" className="secondary" onClick={onLock}>
              Bloquear
            </button>
            {tab === "creds" && (
              <button type="button" onClick={openCreate}>
                Nueva
              </button>
            )}
            {tab === "policies" && (
              <button type="button" onClick={openPolicyCreate}>
                Nueva política
              </button>
            )}
          </div>
        </header>

        <nav className="tabs" aria-label="Secciones">
          <button
            type="button"
            className={tab === "creds" ? "tab active" : "tab"}
            onClick={() => setTab("creds")}
          >
            Credenciales
          </button>
          <button
            type="button"
            className={tab === "policies" ? "tab active" : "tab"}
            onClick={() => {
              setTab("policies");
              void loadPolicies();
            }}
          >
            Políticas
          </button>
          <button
            type="button"
            className={tab === "generator" ? "tab active" : "tab"}
            onClick={() => {
              setTab("generator");
              void loadPolicies();
            }}
          >
            Generador
          </button>
        </nav>

        {message && (
          <p className="toast banner" role="status">
            {message}
          </p>
        )}

        {tab === "creds" && (
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
                  No hay credenciales todavía. Pulsa <strong>Nueva</strong>.
                </p>
              ) : (
                <ul className="cred-list">
                  {items.map((item) => (
                    <li key={item.id}>
                      <button
                        type="button"
                        className={
                          selectedId === item.id
                            ? "cred-row active"
                            : "cred-row"
                        }
                        onClick={() => void selectItem(item.id)}
                      >
                        <span className="cred-name">{item.serviceName}</span>
                        <span className="cred-meta">
                          {item.username || "sin usuario"}
                          {item.reuseCount > 1
                            ? ` · reusada ${item.reuseCount}×`
                            : ""}
                          {item.policyCompliant === true
                            ? " · cumple"
                            : item.policyCompliant === false
                              ? " · no cumple"
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
                  <label htmlFor="pol">Política</label>
                  <select
                    id="pol"
                    value={form.policyId}
                    onChange={(e) =>
                      setForm({ ...form, policyId: e.currentTarget.value })
                    }
                  >
                    <option value="">Sin política</option>
                    {policies.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
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
                      setForm({
                        ...form,
                        nextRenewalAt: e.currentTarget.value,
                      })
                    }
                    placeholder="opcional / la política puede fijarla"
                  />
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
                    {detail.policyCompliant === true && (
                      <span className="badge compliant">Cumple política</span>
                    )}
                    {detail.policyCompliant === false && (
                      <span className="badge noncompliant">
                        No cumple política
                      </span>
                    )}
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
                      <dt>Política</dt>
                      <dd>{policyName(detail.policyId)}</dd>
                    </div>
                    <div>
                      <dt>URL</dt>
                      <dd>{detail.url || "—"}</dd>
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
        )}

        {tab === "policies" && (
          <div className="vault-grid">
            <section className="panel list-panel" aria-label="Políticas">
              {policies.length === 0 ? (
                <p className="empty">
                  No hay políticas. Crea una (p. ej. «Corporativa») y asígnala a
                  un servicio.
                </p>
              ) : (
                <ul className="cred-list">
                  {policies.map((p) => (
                    <li key={p.id}>
                      <button
                        type="button"
                        className={
                          selectedPolicyId === p.id
                            ? "cred-row active"
                            : "cred-row"
                        }
                        onClick={() => openPolicyEdit(p)}
                      >
                        <span className="cred-name">{p.name}</span>
                        <span className="cred-meta">
                          {p.minLength}–{p.maxLength} chars
                          {p.requireSymbol ? " · símbolos" : ""}
                          {p.expiryDays != null
                            ? ` · caduca ${p.expiryDays}d`
                            : ""}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="panel detail-panel" aria-label="Editor política">
              {(policyMode === "create" || policyMode === "edit") && (
                <form className="cred-form" onSubmit={onSavePolicy}>
                  <h2>
                    {policyMode === "create"
                      ? "Nueva política"
                      : "Editar política"}
                  </h2>
                  <label htmlFor="pname">Nombre *</label>
                  <input
                    id="pname"
                    value={policyForm.name}
                    onChange={(e) =>
                      setPolicyForm({
                        ...policyForm,
                        name: e.currentTarget.value,
                      })
                    }
                    required
                  />
                  <div className="two-col">
                    <div>
                      <label htmlFor="pmin">Longitud mín.</label>
                      <input
                        id="pmin"
                        type="number"
                        min={1}
                        value={policyForm.minLength}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            minLength: Number(e.currentTarget.value),
                          })
                        }
                      />
                    </div>
                    <div>
                      <label htmlFor="pmax">Longitud máx.</label>
                      <input
                        id="pmax"
                        type="number"
                        min={1}
                        value={policyForm.maxLength}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            maxLength: Number(e.currentTarget.value),
                          })
                        }
                      />
                    </div>
                  </div>
                  <fieldset className="checks">
                    <legend>Requisitos</legend>
                    <label>
                      <input
                        type="checkbox"
                        checked={policyForm.requireUppercase}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            requireUppercase: e.currentTarget.checked,
                          })
                        }
                      />{" "}
                      Mayúsculas
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={policyForm.requireLowercase}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            requireLowercase: e.currentTarget.checked,
                          })
                        }
                      />{" "}
                      Minúsculas
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={policyForm.requireDigit}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            requireDigit: e.currentTarget.checked,
                          })
                        }
                      />{" "}
                      Números
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={policyForm.requireSymbol}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            requireSymbol: e.currentTarget.checked,
                          })
                        }
                      />{" "}
                      Símbolos
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={policyForm.allowSpaces}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            allowSpaces: e.currentTarget.checked,
                          })
                        }
                      />{" "}
                      Permitir espacios
                    </label>
                  </fieldset>
                  <label htmlFor="pforbid">Caracteres prohibidos</label>
                  <input
                    id="pforbid"
                    value={policyForm.forbiddenChars}
                    onChange={(e) =>
                      setPolicyForm({
                        ...policyForm,
                        forbiddenChars: e.currentTarget.value,
                      })
                    }
                    placeholder="ej. ¡¿"
                  />
                  <label htmlFor="ppat">Patrones prohibidos (coma)</label>
                  <input
                    id="ppat"
                    value={policyForm.forbiddenPatterns}
                    onChange={(e) =>
                      setPolicyForm({
                        ...policyForm,
                        forbiddenPatterns: e.currentTarget.value,
                      })
                    }
                    placeholder="password, 1234"
                  />
                  <div className="two-col">
                    <div>
                      <label htmlFor="pprev">No reutilizar últimas N</label>
                      <input
                        id="pprev"
                        type="number"
                        min={0}
                        value={policyForm.previousPasswordCount}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            previousPasswordCount: Number(
                              e.currentTarget.value,
                            ),
                          })
                        }
                      />
                    </div>
                    <div>
                      <label htmlFor="pexp">Caducidad (días)</label>
                      <input
                        id="pexp"
                        value={policyForm.expiryDays}
                        onChange={(e) =>
                          setPolicyForm({
                            ...policyForm,
                            expiryDays: e.currentTarget.value,
                          })
                        }
                        placeholder="opcional"
                      />
                    </div>
                  </div>
                  <label htmlFor="pextra">Reglas extra (JSON)</label>
                  <input
                    id="pextra"
                    value={policyForm.extraRulesJson}
                    onChange={(e) =>
                      setPolicyForm({
                        ...policyForm,
                        extraRulesJson: e.currentTarget.value,
                      })
                    }
                    placeholder='{"min_unique_chars":8}'
                  />

                  {policyMode === "edit" && selectedPolicyId && (
                    <div className="validate-box">
                      <h3>Probar validación</h3>
                      <label htmlFor="ptestpw">Contraseña de prueba</label>
                      <div className="pw-row">
                        <input
                          id="ptestpw"
                          type="password"
                          value={policyForm.testPassword}
                          onChange={(e) =>
                            setPolicyForm({
                              ...policyForm,
                              testPassword: e.currentTarget.value,
                            })
                          }
                          autoComplete="off"
                        />
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => void onValidateTest()}
                        >
                          Validar
                        </button>
                      </div>
                      {validation && (
                        <p
                          className={
                            validation.compliant
                              ? "validate-ok"
                              : "validate-bad"
                          }
                        >
                          {validation.compliant
                            ? "Cumple"
                            : `No cumple: ${validation.violations
                                .map(violationLabel)
                                .join(", ")}`}
                        </p>
                      )}
                    </div>
                  )}

                  <div className="form-actions">
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => {
                        setPolicyMode("list");
                        setValidation(null);
                      }}
                    >
                      Cancelar
                    </button>
                    {policyMode === "edit" && selectedPolicyId && (
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => void onDeletePolicy(selectedPolicyId)}
                      >
                        Eliminar
                      </button>
                    )}
                    <button type="submit" disabled={busy}>
                      Guardar
                    </button>
                  </div>
                </form>
              )}
              {policyMode === "list" && (
                <p className="empty">
                  Elige una política o crea una nueva. Luego asígnala a una
                  credencial.
                </p>
              )}
            </section>
          </div>
        )}

        {tab === "generator" && (
          <div className="vault-grid gen-grid">
            <section className="panel" aria-label="Opciones generador">
              <h2>Opciones</h2>
              <label htmlFor="glen">Longitud: {genOpts.length}</label>
              <input
                id="glen"
                type="range"
                min={8}
                max={64}
                value={genOpts.length}
                onChange={(e) =>
                  setGenOpts({
                    ...genOpts,
                    length: Number(e.currentTarget.value),
                  })
                }
              />
              <fieldset className="checks">
                <legend>Conjuntos</legend>
                <label>
                  <input
                    type="checkbox"
                    checked={genOpts.lowercase}
                    onChange={(e) =>
                      setGenOpts({
                        ...genOpts,
                        lowercase: e.currentTarget.checked,
                      })
                    }
                  />{" "}
                  Minúsculas
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={genOpts.uppercase}
                    onChange={(e) =>
                      setGenOpts({
                        ...genOpts,
                        uppercase: e.currentTarget.checked,
                      })
                    }
                  />{" "}
                  Mayúsculas
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={genOpts.digits}
                    onChange={(e) =>
                      setGenOpts({
                        ...genOpts,
                        digits: e.currentTarget.checked,
                      })
                    }
                  />{" "}
                  Números
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={genOpts.symbols}
                    onChange={(e) =>
                      setGenOpts({
                        ...genOpts,
                        symbols: e.currentTarget.checked,
                      })
                    }
                  />{" "}
                  Símbolos
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={genOpts.avoidAmbiguous}
                    onChange={(e) =>
                      setGenOpts({
                        ...genOpts,
                        avoidAmbiguous: e.currentTarget.checked,
                      })
                    }
                  />{" "}
                  Evitar ambiguos (0Ool1I|)
                </label>
              </fieldset>
              <label htmlFor="gex">Excluir caracteres</label>
              <input
                id="gex"
                value={genOpts.exclude}
                onChange={(e) =>
                  setGenOpts({ ...genOpts, exclude: e.currentTarget.value })
                }
                placeholder="opcional"
              />
              <label htmlFor="gcustom">Charset personalizado</label>
              <input
                id="gcustom"
                value={genOpts.customCharset}
                onChange={(e) =>
                  setGenOpts({
                    ...genOpts,
                    customCharset: e.currentTarget.value,
                  })
                }
                placeholder="vacío = usar conjuntos de arriba"
              />
              <label htmlFor="gpol">Generar según política</label>
              <select
                id="gpol"
                value={genOpts.policyId}
                onChange={(e) =>
                  setGenOpts({ ...genOpts, policyId: e.currentTarget.value })
                }
              >
                <option value="">Ninguna (solo opciones)</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <div className="form-actions">
                <button
                  type="button"
                  onClick={() => void onGenerate()}
                  disabled={busy}
                >
                  Generar
                </button>
              </div>
            </section>

            <section className="panel" aria-label="Resultado generador">
              <h2>Resultado</h2>
              {!generated ? (
                <p className="empty">
                  Pulsa <strong>Generar</strong>. La clave no se guarda sola.
                </p>
              ) : (
                <div className="gen-result">
                  <div className="pw-row">
                    <code className="gen-pw">
                      {showGenPassword
                        ? generated.password
                        : "••••••••••••••••"}
                    </code>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => setShowGenPassword((v) => !v)}
                    >
                      {showGenPassword ? "Ocultar" : "Mostrar"}
                    </button>
                  </div>
                  <dl className="detail-fields">
                    <div>
                      <dt>Longitud</dt>
                      <dd>{generated.length}</dd>
                    </div>
                    <div>
                      <dt>Entropía ≈</dt>
                      <dd>{generated.entropyBits.toFixed(1)} bits</dd>
                    </div>
                    <div>
                      <dt>Fortaleza</dt>
                      <dd>
                        <span
                          className={`badge strength-${generated.strengthLabel
                            .toLowerCase()
                            .replace(/\s+/g, "-")}`}
                        >
                          {generated.strengthLabel}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt>Charset</dt>
                      <dd>{generated.charsetSize} símbolos</dd>
                    </div>
                    <div>
                      <dt>RNG</dt>
                      <dd>
                        <code>{generated.rng}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Política</dt>
                      <dd>
                        {generated.policyCompliant == null
                          ? "—"
                          : generated.policyCompliant
                            ? "Cumple"
                            : `No cumple: ${generated.policyViolations
                                .map(violationLabel)
                                .join(", ")}`}
                      </dd>
                    </div>
                  </dl>
                  <div className="form-actions">
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => void onGenerate()}
                      disabled={busy}
                    >
                      Otra
                    </button>
                    <button type="button" onClick={useGeneratedInForm}>
                      Usar en nueva credencial
                    </button>
                  </div>
                  <p className="hint">
                    No se ha guardado en la bóveda. Solo se guarda si completas
                    el formulario y pulsas Guardar.
                  </p>
                </div>
              )}
            </section>
          </div>
        )}
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
          Fase <strong>6</strong>: generador seguro de contraseñas (CSPRNG) y
          estimación de fortaleza.
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
          </dl>
        )}
      </div>
    </main>
  );
}

export default App;
