"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent } from "react";
import type { MyInstallation } from "@/lib/api";
import { formatTime } from "@/lib/format";

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function UsageFilter({ installations, selected }: { installations: MyInstallation[]; selected?: string }) {
  const router = useRouter();
  const names = installations.map(item => item.name);
  const duplicates = new Set(names.filter((name, index) => names.indexOf(name) !== index));
  const seen = new Map<string, number>();
  const optionLabel = (item: MyInstallation) => {
    let base = item.name;
    if (duplicates.has(item.name)) {
      base = `${item.name} · ${item.lastSeenAt ? `last seen ${formatTime(Date.parse(item.lastSeenAt))}` : "never uploaded"}`;
      const ordinal = (seen.get(base) ?? 0) + 1;
      seen.set(base, ordinal);
      if (ordinal > 1) base = `${base} · ${item.id.slice(0, 6)}`;
    }
    return item.revoked ? `${base} (revoked)` : base;
  };
  return (
    <div className="profile-usage-filter">
      <label className="field">
        <span>Usage from</span>
        <select
          value={selected ?? ""}
          aria-label="Filter usage by client"
          onChange={event => router.push(event.target.value ? `/profile?installation=${encodeURIComponent(event.target.value)}` : "/profile")}
        >
          <option value="">All my clients</option>
          {installations.map(item => (
            <option key={item.id} value={item.id}>{optionLabel(item)}</option>
          ))}
        </select>
      </label>
      {selected && <a className="btn ghost" href="/profile">Reset</a>}
      <p>Only your enrolled clients are available here. Organization analytics remain aggregated.</p>
    </div>
  );
}

export function ClientEnrollment({
  installations,
  serverUrl,
  releaseBaseUrl,
}: {
  installations: MyInstallation[];
  serverUrl: string;
  releaseBaseUrl: string;
}) {
  const router = useRouter();
  const [platform, setPlatform] = useState("linux");
  const [installationName, setInstallationName] = useState("My workstation");
  const [prepared, setPrepared] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const command = useMemo(
    () => `metrune enroll --server ${shellQuote(serverUrl)} --name ${shellQuote(installationName)} --platform ${shellQuote(platform)}`,
    [installationName, platform, serverUrl],
  );
  // The installer is rendered by this server from the signed release manifest:
  // it picks the artifact for the machine it runs on and verifies the download
  // against the published SHA-256 before installing it.
  const installCommand = platform === "windows"
    ? null
    : `curl -fsSL ${shellQuote(`${serverUrl.replace(/\/+$/, "")}/v1/client/install.sh`)} | sh`;

  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setPrepared(true);
  }

  async function revoke(id: string, name: string) {
    if (!window.confirm(`Revoke "${name}"? It will no longer be able to upload usage.`)) return;
    const response = await fetch(`/api/profile/installations/${id}`, { method: "DELETE" });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(payload.error ?? "Could not revoke the client.");
      return;
    }
    router.refresh();
  }

  const [showRevoked, setShowRevoked] = useState(false);
  const revokedCount = installations.filter(client => client.revoked).length;
  const visibleClients = showRevoked ? installations : installations.filter(client => !client.revoked);

  return (
    <>
      <section className="panel" aria-labelledby="enroll-title">
        <div className="panel-header">
          <div><p className="eyebrow">Browser-approved device code</p><h2 id="enroll-title">Enroll a client</h2></div>
        </div>
        <div className="panel-body">
          <div className="platform-tabs" role="tablist" aria-label="Client platform">
            {["linux", "windows", "macos"].map(value => (
              <button key={value} type="button" role="tab" aria-selected={platform === value}
                className={platform === value ? "active" : ""} onClick={() => { setPlatform(value); setPrepared(false); }}>
                {value === "macos" ? "macOS" : value[0].toUpperCase() + value.slice(1)}
              </button>
            ))}
          </div>
          <form className="enrollment-form" onSubmit={prepare}>
            <label className="field">
              <span>Client name</span>
              <input
                value={installationName}
                onChange={event => {
                  setInstallationName(event.target.value);
                  setPrepared(false);
                }}
                required
                maxLength={120}
                pattern="[A-Za-z0-9 ._-]+"
                title="Use letters, numbers, spaces, dots, underscores, or hyphens."
                placeholder="My workstation"
              />
            </label>
            <p className="enrollment-team-note">You can choose a team on the browser approval screen.</p>
            <button className="btn" type="submit">Prepare enrollment</button>
          </form>
          {error && <p className="form-error" role="alert">{error}</p>}
          {prepared && (
            <div className="enrollment-result" role="status">
              <div><strong>1. Install the client</strong><p>{platform === "windows" ? "Download the Windows executable for this machine, then verify it against the published checksum." : "The installer picks the build for this machine and verifies it against the signed release manifest."}</p></div>
              {installCommand ? (
                <div className="copy-row"><code>{installCommand}</code><button className="btn ghost small" type="button" onClick={() => navigator.clipboard.writeText(installCommand)}>Copy</button></div>
              ) : (
                <a className="btn ghost" href={`${releaseBaseUrl.replace(/\/+$/, "")}/metrune-windows-x86_64.exe`}>Download client</a>
              )}
              <div><strong>2. Enroll it</strong><p>The CLI shows a 10-minute device code and browser link. Sign in, confirm the matching client, and choose its team.</p></div>
              <div className="copy-row"><code>{command}</code><button className="btn ghost small" type="button" onClick={() => navigator.clipboard.writeText(command)}>Copy</button></div>
            </div>
          )}
        </div>
      </section>
      <section className="panel" aria-labelledby="clients-title">
        <div className="panel-header">
          <div><p className="eyebrow">Clients enrolled to you, visible only to you</p><h2 id="clients-title">My clients</h2></div>
          {revokedCount > 0 && (
            <label className="check-field">
              <input type="checkbox" checked={showRevoked} onChange={event => setShowRevoked(event.target.checked)} />
              <span>Show {revokedCount} revoked</span>
            </label>
          )}
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Name</th><th>Platform</th><th>Team</th><th>Client version</th><th>Last seen</th><th className="actions-col">Action</th></tr></thead>
            <tbody>
              {visibleClients.map(client => (
                <tr key={client.id} className={client.revoked ? "muted-row" : undefined}>
                  <td><strong>{client.name}</strong>{client.revoked && <span className="badge warn">revoked</span>}</td>
                  <td>{client.platform === "wsl" ? "LINUX" : client.platform.toUpperCase()}</td><td>{client.teamName ?? "Unassigned"}</td>
                  <td>{client.lastClientVersion ?? "Not reported"}</td>
                  <td>{client.lastSeenAt ? formatTime(Date.parse(client.lastSeenAt)) : "Waiting for first upload"}</td>
                  <td className="actions-col">{!client.revoked && <button className="btn danger small" onClick={() => revoke(client.id, client.name)}>Revoke</button>}</td>
                </tr>
              ))}
              {visibleClients.length === 0 && <tr><td colSpan={6} className="empty">No clients are enrolled to your profile yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
