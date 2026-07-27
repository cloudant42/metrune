"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, type FormEvent } from "react";
import type { MyInstallation, Team } from "@/lib/api";
import { formatTime } from "@/lib/format";

type Enrollment = { code: string; expiresAt: string; installationName: string; platform: string };

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
  teams,
  serverUrl,
  releaseBaseUrl,
}: {
  installations: MyInstallation[];
  teams: Team[];
  serverUrl: string;
  releaseBaseUrl: string;
}) {
  const router = useRouter();
  const [platform, setPlatform] = useState("linux");
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const command = useMemo(() => enrollment
    ? `metrune enroll --server ${serverUrl} --token ${enrollment.code} --name "${enrollment.installationName}" --platform ${enrollment.platform}`
    : "", [enrollment, serverUrl]);
  const installCommand = platform === "windows"
    ? null
    : platform === "macos"
      ? `arch="$(uname -m)"; case "$arch" in arm64) asset="metrune-macos-arm64";; x86_64) asset="metrune-macos-x86_64";; *) echo "Unsupported macOS architecture: $arch" >&2; exit 1;; esac; curl -fsSL "${releaseBaseUrl}/$asset" -o /tmp/metrune && chmod +x /tmp/metrune && sudo install /tmp/metrune /usr/local/bin/metrune`
      : `curl -fsSL "${releaseBaseUrl}/metrune-linux-x86_64" -o /tmp/metrune && chmod +x /tmp/metrune && sudo install /tmp/metrune /usr/local/bin/metrune`;

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setEnrollment(null);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/enrollment-codes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        installationName: form.get("installationName"),
        platform,
        teamId: form.get("teamId") || null,
      }),
    });
    const payload = await response.json().catch(() => ({}));
    setBusy(false);
    if (!response.ok) setError(payload.error ?? "Could not create enrollment code.");
    else setEnrollment(payload);
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
          <div><p className="eyebrow">Owner-bound setup</p><h2 id="enroll-title">Enroll a client</h2></div>
        </div>
        <div className="panel-body">
          <div className="platform-tabs" role="tablist" aria-label="Client platform">
            {["linux", "windows", "macos"].map(value => (
              <button key={value} type="button" role="tab" aria-selected={platform === value}
                className={platform === value ? "active" : ""} onClick={() => { setPlatform(value); setEnrollment(null); }}>
                {value === "macos" ? "macOS" : value[0].toUpperCase() + value.slice(1)}
              </button>
            ))}
          </div>
          <form className="enrollment-form" onSubmit={create}>
            <label className="field"><span>Client name</span><input name="installationName" required maxLength={120} placeholder="My workstation" /></label>
            <label className="field"><span>Team</span><select name="teamId"><option value="">Unassigned</option>{teams.map(team => <option key={team.id} value={team.id}>{team.name}</option>)}</select></label>
            <button className="btn" type="submit" disabled={busy}>{busy ? "Creating…" : "Create one-time code"}</button>
          </form>
          {error && <p className="form-error" role="alert">{error}</p>}
          {enrollment && (
            <div className="enrollment-result" role="status">
              <div><strong>1. Install the client</strong><p>{platform === "windows" ? "Download the Windows executable for this machine." : platform === "macos" ? "Run this command in macOS; it selects Intel or Apple Silicon automatically." : "Run this command in Linux."}</p></div>
              {installCommand ? (
                <div className="copy-row"><code>{installCommand}</code><button className="btn ghost small" type="button" onClick={() => navigator.clipboard.writeText(installCommand)}>Copy</button></div>
              ) : (
                <a className="btn ghost" href={`${releaseBaseUrl}/metrune-windows-x86_64.exe`}>Download client</a>
              )}
              <div><strong>2. Enroll it</strong><p>This code expires at {new Date(enrollment.expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} and works once.</p></div>
              <div className="copy-row"><code>{command}</code><button className="btn ghost small" type="button" onClick={() => navigator.clipboard.writeText(command)}>Copy</button></div>
            </div>
          )}
        </div>
      </section>
      <section className="panel" aria-labelledby="clients-title">
        <div className="panel-header">
          <div><p className="eyebrow">Private ownership</p><h2 id="clients-title">My clients</h2></div>
          {revokedCount > 0 && (
            <label className="check-field">
              <input type="checkbox" checked={showRevoked} onChange={event => setShowRevoked(event.target.checked)} />
              <span>Show {revokedCount} revoked</span>
            </label>
          )}
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Name</th><th>Platform</th><th>Team</th><th>Last seen</th><th className="actions-col">Action</th></tr></thead>
            <tbody>
              {visibleClients.map(client => (
                <tr key={client.id} className={client.revoked ? "muted-row" : undefined}>
                  <td><strong>{client.name}</strong>{client.revoked && <span className="badge warn">revoked</span>}</td>
                  <td>{client.platform === "wsl" ? "LINUX" : client.platform.toUpperCase()}</td><td>{client.teamName ?? "Unassigned"}</td>
                  <td>{client.lastSeenAt ? formatTime(Date.parse(client.lastSeenAt)) : "Waiting for first upload"}</td>
                  <td className="actions-col">{!client.revoked && <button className="btn danger small" onClick={() => revoke(client.id, client.name)}>Revoke</button>}</td>
                </tr>
              ))}
              {visibleClients.length === 0 && <tr><td colSpan={5} className="empty">No clients are enrolled to your profile yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
