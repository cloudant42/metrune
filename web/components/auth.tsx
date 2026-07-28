"use client";

import { useRouter } from "next/navigation";
import { MarkIcon } from "./icons";
import { useState, type FormEvent } from "react";

export function LoginForm() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
    });
    const payload = await response.json().catch(() => ({}));
    setBusy(false);
    if (!response.ok) {
      setError(payload.error ?? "Sign-in failed.");
      return;
    }
    const next = new URLSearchParams(window.location.search).get("next");
    router.replace(next?.startsWith("/") ? next : payload.user?.organizationId ? "/" : "/organizations");
    router.refresh();
  }

  return (
    <form className="auth-card" onSubmit={submit}>
      <div className="auth-heading">
        <span className="brand-mark" aria-hidden="true"><MarkIcon size={26} /></span>
        <div><p className="eyebrow">Private, self-hosted workspace</p><h1>Sign in to Metrune</h1></div>
      </div>
      <p className="auth-copy">Sign in once, then open any workspace you belong to.</p>
      <label className="field">
        <span>Email</span>
        <input name="email" type="email" autoComplete="username" required />
      </label>
      <label className="field">
        <span>Password</span>
        <input name="password" type="password" autoComplete="current-password" required />
      </label>
      {error && <p className="form-error auth-error" role="alert">{error}</p>}
      <button className="btn auth-submit" type="submit" disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <a className="auth-link" href="/forgot-password">Forgot your password?</a>
      <p className="auth-note">Local password sign-in is enabled until your organization enforces SSO.</p>
    </form>
  );
}

export function LogoutButton() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  async function logout() {
    setBusy(true);
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }
  return <button className="btn ghost small" onClick={logout} disabled={busy}>{busy ? "Signing out…" : "Sign out"}</button>;
}
