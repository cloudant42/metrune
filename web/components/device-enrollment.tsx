"use client";

import { useState, type FormEvent } from "react";
import type { Team } from "@/lib/api";
import { MarkIcon } from "./icons";

type DeviceDetails = {
  userCode: string;
  installationName: string;
  platform: string;
  expiresAt: string;
};

type Decision = "approved" | "denied";

export function DeviceEnrollmentApproval({
  initialCode,
  organizationName,
  teams,
}: {
  initialCode: string;
  organizationName: string;
  teams: Team[];
}) {
  const [code, setCode] = useState(initialCode);
  const [details, setDetails] = useState<DeviceDetails | null>(null);
  const [teamId, setTeamId] = useState("");
  const [decision, setDecision] = useState<Decision | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(action: "inspect" | "approve" | "deny") {
    setBusy(true);
    setError(null);
    const response = await fetch("/api/device-enrollment", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, userCode: code, teamId }),
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    setBusy(false);
    if (!response.ok) {
      setError(payload.error ?? "The device request could not be processed.");
      return;
    }
    if (action === "inspect") {
      setDetails(payload as DeviceDetails);
      setCode(payload.userCode);
      return;
    }
    setDecision(payload.status as Decision);
  }

  function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void send("inspect");
  }

  if (decision) {
    return (
      <main className="device-screen">
        <section className="device-card" aria-labelledby="device-result-title">
          <header className="device-heading">
            <span className="brand-mark" aria-hidden="true"><MarkIcon size={26} /></span>
            <div>
              <p className="eyebrow">Device enrollment</p>
              <h1 id="device-result-title">
                {decision === "approved" ? "Client approved" : "Client denied"}
              </h1>
            </div>
          </header>
          <p className="auth-copy" role="status">
            {decision === "approved"
              ? `${details?.installationName ?? "The client"} can now finish enrollment. Return to the terminal.`
              : "No credential was issued. You can close this page."}
          </p>
          <a className="btn ghost" href="/profile">Go to my clients</a>
        </section>
      </main>
    );
  }

  return (
    <main className="device-screen">
      <section className="device-card" aria-labelledby="device-title">
        <header className="device-heading">
          <span className="brand-mark" aria-hidden="true"><MarkIcon size={26} /></span>
          <div>
            <p className="eyebrow">Browser-approved enrollment</p>
            <h1 id="device-title">Approve a Metrune client</h1>
          </div>
        </header>
        {!details ? (
          <form className="device-code-form" onSubmit={inspect}>
            <p className="auth-copy">
              Enter the code shown by <code>metrune enroll</code>. You will review the machine before anything is approved.
            </p>
            <label className="field">
              <span>Device code</span>
              <input
                value={code}
                onChange={event => {
                  setCode(event.target.value.toUpperCase());
                  setError(null);
                }}
                autoComplete="one-time-code"
                inputMode="text"
                maxLength={12}
                pattern="[A-Za-z0-9 -]{8,12}"
                placeholder="ABCD-2345"
                required
                autoFocus
              />
            </label>
            {error && <p className="form-error" role="alert">{error}</p>}
            <button className="btn auth-submit" type="submit" disabled={busy}>
              {busy ? "Checking…" : "Review this client"}
            </button>
          </form>
        ) : (
          <div className="device-review">
            <div className="device-code-match">
              <span>Confirm this code matches the terminal</span>
              <strong>{details.userCode}</strong>
            </div>
            <dl className="device-facts">
              <div><dt>Client</dt><dd>{details.installationName}</dd></div>
              <div><dt>Platform</dt><dd>{details.platform === "wsl" ? "WSL" : details.platform}</dd></div>
              <div><dt>Workspace</dt><dd>{organizationName}</dd></div>
              <div><dt>Expires</dt><dd>{new Date(details.expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</dd></div>
            </dl>
            <label className="field">
              <span>Team</span>
              <select value={teamId} onChange={event => setTeamId(event.target.value)}>
                <option value="">Unassigned</option>
                {teams.map(team => <option key={team.id} value={team.id}>{team.name}</option>)}
              </select>
            </label>
            <p className="device-security-note">
              Approve only if you started this enrollment and both codes match. The client receives a revocable installation credential—not your browser session.
            </p>
            {error && <p className="form-error" role="alert">{error}</p>}
            <div className="device-actions">
              <button className="btn danger" type="button" disabled={busy} onClick={() => void send("deny")}>
                Deny
              </button>
              <button className="btn" type="button" disabled={busy} onClick={() => void send("approve")}>
                {busy ? "Saving…" : "Approve client"}
              </button>
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
