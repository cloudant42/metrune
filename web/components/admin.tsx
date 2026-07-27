"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import type { AdminData } from "@/lib/api";
import type { ClassifierSettings, Installation, OrgSettings, ProviderCredential, Team } from "@/lib/api";
import { formatTime } from "@/lib/format";

const tabs = [
  { id: "teams", label: "Teams & clients" },
  { id: "classifier", label: "Classifier & vault" },
  { id: "organization", label: "Organization" },
] as const;

export function AdminTabs({ data, initialTab }: { data: AdminData; initialTab?: string }) {
  const [active, setActive] = useState(() => tabs.some(tab => tab.id === initialTab) ? (initialTab as string) : "teams");
  return (
    <>
      <nav className="tabs" aria-label="Admin sections">
        {tabs.map(tab => (
          <button key={tab.id} type="button" className={active === tab.id ? "active" : ""} aria-pressed={active === tab.id} onClick={() => setActive(tab.id)}>
            {tab.label}
          </button>
        ))}
      </nav>
      {active === "teams" && (
        <div className="admin-grid teams-grid">
          <TeamsPanel teams={data.teams} />
          <InstallationsPanel installations={data.installations} teams={data.teams} />
        </div>
      )}
      {active === "classifier" && (
        <div className="stack">
          <ClassifierPanel classifier={data.classifier} credentials={data.credentials} />
          <CredentialsPanel credentials={data.credentials} />
        </div>
      )}
      {active === "organization" && (
        <div className="admin-grid">
          <SettingsPanel settings={data.settings} />
          <section className="panel" aria-labelledby="pricing-link-title">
            <div className="panel-header">
              <div><p className="eyebrow">Cost governance</p><h2 id="pricing-link-title">Provider and model pricing</h2></div>
              <Link className="btn ghost small" href="/admin/pricing">Manage pricing</Link>
            </div>
            <p className="panel-note">Review default catalog prices and create organization or self-hosted overrides.</p>
          </section>
          <IdentityPanel settings={data.settings} />
        </div>
      )}
    </>
  );
}

async function send(path: string, method: string, body?: unknown): Promise<string | null> {
  const response = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.ok) return null;
  const payload = await response.json().catch(() => ({}));
  return payload.error ?? `Request failed with ${response.status}`;
}

export function TeamsPanel({ teams }: { teams: Team[] }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<string | null>) {
    setBusy(true);
    setError(null);
    const failure = await action();
    setError(failure);
    setBusy(false);
    if (!failure) router.refresh();
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = new FormData(form).get("name") as string;
    await run(() => send("/api/admin/teams", "POST", { name }));
    form.reset();
  }

  async function rename(team: Team) {
    const name = window.prompt("Rename team", team.name)?.trim();
    if (!name || name === team.name) return;
    await run(() => send(`/api/admin/teams/${team.id}`, "PATCH", { name }));
  }

  async function remove(team: Team) {
    if (!window.confirm(`Delete team "${team.name}"? Its installations become unassigned.`)) return;
    await run(() => send(`/api/admin/teams/${team.id}`, "DELETE"));
  }

  return (
    <section className="panel" aria-labelledby="teams-title">
      <div className="panel-header">
        <div><p className="eyebrow">Grouping</p><h2 id="teams-title">Teams</h2></div>
        <form className="inline-form" onSubmit={create}>
          <input name="name" required maxLength={80} placeholder="New team name" aria-label="New team name" />
          <button className="btn" type="submit" disabled={busy}>Create</button>
        </form>
      </div>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="table-scroll">
        <table>
          <thead><tr><th>Team</th><th>Installations</th><th className="actions-col">Actions</th></tr></thead>
          <tbody>
            {teams.map(team => (
              <tr key={team.id}>
                <td><strong>{team.name}</strong></td>
                <td>{team.installations}</td>
                <td className="actions-col">
                  <button className="btn ghost small" onClick={() => rename(team)} disabled={busy}>Rename</button>
                  <button className="btn danger small" onClick={() => remove(team)} disabled={busy}>Delete</button>
                </td>
              </tr>
            ))}
            {teams.length === 0 && <tr><td colSpan={3} className="empty">No teams yet. Create one to group installations.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function InstallationsPanel({ installations, teams }: { installations: Installation[]; teams: Team[] }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const sorted = [...installations].sort((a, b) => {
    if (a.revoked !== b.revoked) return a.revoked ? 1 : -1;
    return (b.lastSeenAt ?? "").localeCompare(a.lastSeenAt ?? "");
  });
  const visible = showRevoked ? sorted : sorted.filter(item => !item.revoked);
  const revokedCount = installations.filter(item => item.revoked).length;

  async function assign(installationId: string, teamId: string) {
    setError(null);
    const failure = await send(`/api/admin/installations/${installationId}`, "PATCH", { teamId: teamId || null });
    setError(failure);
    if (!failure) router.refresh();
  }

  return (
    <section className="panel" aria-labelledby="installations-title">
      <div className="panel-header">
        <div><p className="eyebrow">Enrolled clients</p><h2 id="installations-title">Installations</h2></div>
        {revokedCount > 0 && (
          <label className="check-field">
            <input type="checkbox" checked={showRevoked} onChange={event => setShowRevoked(event.target.checked)} />
            <span>Show {revokedCount} revoked</span>
          </label>
        )}
      </div>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="table-scroll">
        <table>
          <thead><tr><th>Name</th><th>Team</th><th>Last seen</th><th>Enrolled</th></tr></thead>
          <tbody>
            {visible.map(installation => (
              <tr key={installation.id} className={installation.revoked ? "muted-row" : undefined}>
                <td><strong>{installation.name}</strong>{installation.revoked && <span className="badge warn">revoked</span>}</td>
                <td>
                  <select
                    aria-label={`Team for ${installation.name}`}
                    value={installation.teamId ?? ""}
                    disabled={installation.revoked}
                    onChange={event => assign(installation.id, event.target.value)}
                  >
                    <option value="">Unassigned</option>
                    {teams.map(team => <option key={team.id} value={team.id}>{team.name}</option>)}
                  </select>
                </td>
                <td>{installation.lastSeenAt ? formatTime(Date.parse(installation.lastSeenAt)) : "Never"}</td>
                <td>{new Date(installation.createdAt).toLocaleDateString("en", { month: "short", day: "numeric" })}</td>
              </tr>
            ))}
            {visible.length === 0 && <tr><td colSpan={4} className="empty">No active installations.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function SettingsPanel({ settings }: { settings: OrgSettings }) {
  const router = useRouter();
  const [days, setDays] = useState(String(settings.retentionDays));
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    setError(null);
    const failure = await send("/api/admin/settings", "PATCH", { retentionDays: Number(days) });
    setBusy(false);
    if (failure) {
      setError(failure);
    } else {
      setMessage("Retention updated. Stored snapshots are restamped in the background.");
      router.refresh();
    }
  }

  return (
    <section className="panel" aria-labelledby="settings-title">
      <div className="panel-header">
        <div><p className="eyebrow">Data governance</p><h2 id="settings-title">Retention</h2></div>
      </div>
      <div className="panel-body">
        <form className="inline-form" onSubmit={save}>
          <label>
            <span>Keep session analytics for</span>
            <input type="number" min={1} max={3650} value={days} onChange={event => setDays(event.target.value)} aria-label="Retention days" />
          </label>
          <span className="inline-hint">days (1–3650)</span>
          <button className="btn" type="submit" disabled={busy}>Save</button>
        </form>
        {message && <p className="form-ok" role="status">{message}</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
        <p className="panel-note">Enforced by ClickHouse TTL on the stamped per-row retention. Existing rows are restamped when you change this value.</p>
      </div>
    </section>
  );
}

export function IdentityPanel({ settings }: { settings: OrgSettings }) {
  return (
    <section className="panel" aria-labelledby="identity-title">
      <div className="panel-header">
        <div><p className="eyebrow">Authentication</p><h2 id="identity-title">Identity</h2></div>
      </div>
      <div className="panel-body identity-grid">
        <div className="identity-row">
          <span>Local password sign-in</span>
          <span className={`badge ${settings.localLoginEnabled ? "ok" : ""}`}>{settings.localLoginEnabled ? "enabled" : "disabled"}</span>
        </div>
        <div className="identity-row">
          <span>SSO enforcement</span>
          <span className={`badge ${settings.ssoEnforced ? "ok" : ""}`}>{settings.ssoEnforced ? "enforced" : "off"}</span>
        </div>
        <div className="identity-row">
          <span>OIDC providers (Entra ID, Okta, Keycloak)</span>
          <span className="badge">none connected</span>
        </div>
        <p className="panel-note">
          Local password sign-in is active and stays available for easy setup. It is disabled automatically
          for an organization once SSO is enforced. OIDC connections (Entra ID, Okta, Keycloak) and SCIM
          provisioning build on the provisioned identity schema in the next milestone.
        </p>
      </div>
    </section>
  );
}

const providerPresets = {
  openrouter: {
    label: "OpenRouter",
    endpoint: "https://openrouter.ai/api/v1/chat/completions",
    modelPlaceholder: "inclusionai/ling-3.0-flash:free",
    hint: "Broad hosted model catalog with automatic capability fallback.",
  },
  openai: {
    label: "OpenAI",
    endpoint: "https://api.openai.com/v1/chat/completions",
    modelPlaceholder: "gpt-4.1-mini",
    hint: "Direct OpenAI access through the chat completions protocol.",
  },
  ollama: {
    label: "Ollama / local",
    endpoint: "http://localhost:11434/v1/chat/completions",
    modelPlaceholder: "qwen2.5-coder:7b",
    hint: "Runs locally and does not require a provider credential.",
  },
  custom: {
    label: "Custom OpenAI-compatible",
    endpoint: "",
    modelPlaceholder: "your-model-id",
    hint: "For LM Studio, vLLM, LocalAI, or another compatible endpoint.",
  },
} as const;

type ProviderPresetId = keyof typeof providerPresets;

function normalizedProvider(providerId: string): ProviderPresetId {
  return providerId in providerPresets ? providerId as ProviderPresetId : "custom";
}

export function ClassifierPanel({ classifier, credentials }: { classifier: ClassifierSettings; credentials: ProviderCredential[] }) {
  const router = useRouter();
  const [enabled, setEnabled] = useState(classifier.enabled);
  const [providerId, setProviderId] = useState<ProviderPresetId>(normalizedProvider(classifier.providerId));
  const [endpoint, setEndpoint] = useState(classifier.endpoint);
  const [model, setModel] = useState(classifier.model);
  const [credentialId, setCredentialId] = useState(classifier.credentialId);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [detectedResponseMode, setDetectedResponseMode] = useState<ClassifierSettings["responseMode"]>(classifier.responseMode);
  const preset = providerPresets[providerId];
  const effectiveEndpoint = providerId === "custom" ? endpoint : preset.endpoint;
  const storedCredentialAvailable = credentialId
    ? credentials.some(item => item.credentialId === credentialId) || (credentialId === classifier.credentialId && classifier.credentialAvailable)
    : false;
  const credentialRequired = providerId === "openrouter" || providerId === "openai";
  const readyToTest = !credentialRequired || storedCredentialAvailable;

  function selectProvider(next: ProviderPresetId) {
    setProviderId(next);
    setEndpoint(providerPresets[next].endpoint);
    if (!credentialId || credentialId === classifier.providerId) {
      setCredentialId(next === "ollama" ? "" : next);
    }
    setMessage(null);
    setError(null);
    setDetectedResponseMode(next === "openrouter" || next === "openai" ? "auto" : "prompt_json");
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    setError(null);
    const failure = await send("/api/admin/classifier", "PATCH", {
      enabled, providerId, endpoint: effectiveEndpoint, model, credentialId, responseMode: detectedResponseMode,
    });
    setBusy(false);
    if (failure) setError(failure);
    else {
      setMessage("Classifier configuration saved. New enrollments receive this profile.");
      router.refresh();
    }
  }

  async function testClassifier() {
    setTesting(true);
    setMessage(null);
    setError(null);
    const response = await fetch("/api/admin/classifier/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true, providerId, endpoint: effectiveEndpoint, model, credentialId }),
    });
    const payload = await response.json().catch(() => ({}));
    setTesting(false);
    if (!response.ok) {
      setError(payload.error ?? "Classifier test failed.");
      return;
    }
    const handling = payload.responseMode === "structured" ? "structured JSON" : "prompt JSON fallback";
    setDetectedResponseMode(payload.responseMode);
    setMessage(`Connection verified: ${payload.category} (${Math.round(payload.confidence * 100)}%). Used ${handling}${payload.repaired ? " with one repair retry" : ""}.`);
  }

  return (
    <section className="panel" aria-labelledby="classifier-title">
      <div className="panel-header">
        <div><p className="eyebrow">Semantic categorization</p><h2 id="classifier-title">Organization classifier</h2></div>
        <span className={`badge ${enabled ? "ok" : ""}`}>{enabled ? "enabled" : "disabled"}</span>
      </div>
      <div className="panel-body">
        <form className="settings-form" onSubmit={save}>
          <label className="toggle-field">
            <input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} />
            <span>Offer this classifier to enrolled clients</span>
          </label>
          <div className="form-grid">
            <label className="field">
              <span>Provider</span>
              <select disabled={!enabled} value={providerId} onChange={event => selectProvider(event.target.value as ProviderPresetId)}>
                {Object.entries(providerPresets).map(([id, item]) => <option key={id} value={id}>{item.label}</option>)}
              </select>
              <small>{preset.hint}</small>
            </label>
            <label className="field">
              <span>Model</span>
              <input required={enabled} disabled={!enabled} value={model} onChange={event => setModel(event.target.value)} placeholder={preset.modelPlaceholder} />
              <small>Use the exact model ID provided by {preset.label}.</small>
            </label>
            {providerId === "custom" ? (
              <label className="field wide">
                <span>OpenAI-compatible endpoint</span>
                <input type="url" required={enabled} disabled={!enabled} value={endpoint} onChange={event => setEndpoint(event.target.value)} placeholder="https://provider.example/v1/chat/completions" />
                <small>HTTPS is required except for localhost and 127.0.0.1.</small>
              </label>
            ) : (
              <div className="provider-summary wide" aria-label="Provider endpoint">
                <span>Endpoint</span>
                <code>{effectiveEndpoint}</code>
              </div>
            )}
            <label className="field wide">
              <span>Credential</span>
              <select disabled={!enabled || providerId === "ollama"} value={credentialId} onChange={event => setCredentialId(event.target.value)}>
                <option value="">{providerId === "ollama" ? "Not required for local Ollama" : "Select a credential"}</option>
                {credentials.map(item => <option key={item.credentialId} value={item.credentialId}>{item.credentialId} · {item.providerId} · v{item.version}</option>)}
              </select>
              <small>Credentials are created and rotated in the encrypted vault below.</small>
            </label>
          </div>
          <div className="form-actions">
            <div className="button-row">
              <button className="btn" type="submit" disabled={busy || testing}>{busy ? "Saving…" : "Save classifier"}</button>
              <button className="btn ghost" type="button" disabled={!enabled || busy || testing || !model || !readyToTest} onClick={testClassifier}>{testing ? "Testing…" : "Test configuration"}</button>
            </div>
            {enabled && <span className={`badge ${readyToTest ? "ok" : "warn"}`}>{readyToTest ? "ready to test" : "credential not configured"}</span>}
          </div>
        </form>
        {message && <p className="form-ok" role="status">{message}</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
        <p className="panel-note">Response handling is automatic: Metrune uses structured JSON when supported, falls back to prompt-based JSON, and retries one malformed response. The test sends only synthetic text—never session content.</p>
      </div>
    </section>
  );
}

export function CredentialsPanel({ credentials }: { credentials: ProviderCredential[] }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryPassword, setRecoveryPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    const form = event.currentTarget;
    const data = new FormData(form);
    const failure = await send("/api/admin/credentials", "POST", {
      credentialId: data.get("credentialId"),
      providerId: data.get("providerId"),
      secret: data.get("secret"),
      graceHours: Number(data.get("graceHours")),
    });
    setBusy(false);
    if (failure) setError(failure);
    else {
      form.reset();
      setMessage("Credential encrypted and activated. Existing clients refresh on their next provisioning.");
      router.refresh();
    }
  }

  async function revoke(credentialId: string) {
    if (!window.confirm(`Revoke credential "${credentialId}"? New client provisioning will no longer receive it.`)) return;
    setError(await send(`/api/admin/credentials/${encodeURIComponent(credentialId)}`, "DELETE"));
    router.refresh();
  }

  async function exportRecovery() {
    if (!recoveryPassword) return;
    setError(null);
    const response = await fetch("/api/admin/vault/recovery", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: recoveryPassword }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) setError(payload.error ?? "Could not export recovery key.");
    else {
      setRecoveryKey(payload.recoveryKey);
      setShowRecovery(false);
    }
    setRecoveryPassword("");
  }

  return (
    <section className="panel" aria-labelledby="credentials-title">
      <div className="panel-header">
        <div><p className="eyebrow">Encrypted server vault</p><h2 id="credentials-title">Provider credentials</h2></div>
        <button className="btn ghost small" type="button" onClick={() => setShowRecovery(value => !value)} aria-expanded={showRecovery}>Export recovery key</button>
      </div>
      <div className="panel-body">
        {showRecovery && !recoveryKey && (
          <form className="recovery-form" onSubmit={(event) => { event.preventDefault(); void exportRecovery(); }}>
            <label className="field">
              <span>Confirm your password</span>
              <input type="password" autoComplete="current-password" value={recoveryPassword} onChange={(event) => setRecoveryPassword(event.target.value)} required autoFocus />
              <small>The recovery key is shown only once. Store it outside this server.</small>
            </label>
            <div className="form-actions">
              <button className="btn" type="submit">Show recovery key</button>
              <button className="btn ghost" type="button" onClick={() => { setShowRecovery(false); setRecoveryPassword(""); }}>Cancel</button>
            </div>
          </form>
        )}
        <form className="settings-form" onSubmit={save}>
          <div className="form-grid">
            <label className="field"><span>Credential ID</span><input name="credentialId" required placeholder="openrouter" /></label>
            <label className="field"><span>Provider</span><select name="providerId" required defaultValue="openrouter">{Object.entries(providerPresets).map(([id, item]) => <option key={id} value={id}>{item.label}</option>)}</select></label>
            <label className="field wide"><span>API key</span><input name="secret" type="password" required autoComplete="new-password" /><small>Write-only. The plaintext value is never returned by the server.</small></label>
            <label className="field"><span>Rotation grace period</span><input name="graceHours" type="number" min={0} max={168} defaultValue={24} /></label>
          </div>
          <button className="btn" type="submit" disabled={busy}>{busy ? "Encrypting…" : "Save credential"}</button>
        </form>
        {message && <p className="form-ok" role="status">{message}</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
        {recoveryKey && <div className="recovery-key" role="status"><strong>Store this recovery key now. It cannot be exported again.</strong><div className="copy-row"><code>{recoveryKey}</code><button className="btn ghost small" type="button" onClick={() => navigator.clipboard.writeText(recoveryKey)}>Copy</button></div></div>}
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Credential</th><th>Provider</th><th>Version</th><th>Clients refreshed</th><th className="actions-col">Action</th></tr></thead>
          <tbody>
            {credentials.map(item => <tr key={item.credentialId}><td><strong>{item.credentialId}</strong></td><td>{item.providerId}</td><td>v{item.version}</td><td>{item.clientsOnVersion}</td><td className="actions-col"><button className="btn danger small" type="button" onClick={() => revoke(item.credentialId)}>Revoke</button></td></tr>)}
            {credentials.length === 0 && <tr><td colSpan={5} className="empty">No encrypted credentials stored yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}
