"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import type { CurrentUser } from "@/lib/api";
import { MarkIcon } from "./icons";

export function WorkspaceChooser({ user }: { user: CurrentUser }) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function openWorkspace(organizationId: string) {
    if (organizationId === user.organizationId) {
      router.replace("/");
      return;
    }
    setBusy(organizationId);
    setError(null);
    const response = await fetch("/api/auth/organization", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ organizationId }),
    });
    const payload = await response.json().catch(() => ({}));
    setBusy(null);
    if (!response.ok) {
      setError(payload.error ?? "Could not open that workspace.");
      return;
    }
    router.replace("/");
    router.refresh();
  }

  async function createWorkspace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") ?? "").trim();
    if (!name) return;
    setBusy("create");
    setError(null);
    const response = await fetch("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const payload = await response.json().catch(() => ({}));
    setBusy(null);
    if (!response.ok) {
      setError(payload.error ?? "Could not create the workspace.");
      return;
    }
    form.reset();
    router.replace("/");
    router.refresh();
  }

  async function signOut() {
    setBusy("logout");
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  return (
    <main className="workspace-screen">
      <section className="workspace-card" aria-labelledby="workspace-title">
        <header className="workspace-heading">
          <span className="brand-mark" aria-hidden="true"><MarkIcon size={26} /></span>
          <div>
            <p className="eyebrow">Signed in as {user.displayName ?? user.email}</p>
            <h1 id="workspace-title">Choose a workspace</h1>
            <p>Each workspace keeps its members, clients, settings, credentials, and analytics isolated.</p>
          </div>
        </header>

        <div className="workspace-list" aria-label="Your workspaces">
          {user.organizations.map(organization => (
            <article className="workspace-option" key={organization.id}>
              <span className="workspace-avatar" aria-hidden="true">{organization.name.slice(0, 2).toUpperCase()}</span>
              <div>
                <strong>{organization.name}</strong>
                <small>{organization.role} access</small>
              </div>
              <button
                className="btn"
                type="button"
                disabled={busy !== null}
                onClick={() => openWorkspace(organization.id)}
              >
                {busy === organization.id ? "Opening…" : organization.id === user.organizationId ? "Continue" : "Open workspace"}
              </button>
            </article>
          ))}
          {user.organizations.length === 0 && (
            <p className="empty">You do not have an active workspace membership yet. Create a workspace or ask an administrator to add your account.</p>
          )}
        </div>

        <form className="workspace-create" onSubmit={createWorkspace}>
          <div>
            <h2>Create a workspace</h2>
            <p>Use a separate workspace for each company, business unit, or independent account.</p>
          </div>
          <label className="field">
            <span>Workspace name</span>
            <input name="name" required maxLength={120} placeholder="Acme Engineering" />
          </label>
          <button className="btn ghost" type="submit" disabled={busy !== null}>
            {busy === "create" ? "Creating…" : "Create workspace"}
          </button>
        </form>

        {error && <p className="form-error" role="alert">{error}</p>}
        <footer className="workspace-footer">
          <span>{user.email}</span>
          <button className="btn ghost small" type="button" onClick={signOut} disabled={busy !== null}>
            {busy === "logout" ? "Signing out…" : "Sign out"}
          </button>
        </footer>
      </section>
    </main>
  );
}
