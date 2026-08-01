"use client";

import { useRouter } from "next/navigation";
import { MarkIcon } from "./icons";
import { useState, type FormEvent } from "react";
import type { AuthMethods } from "@/lib/auth-config";
import { safeNextPath } from "@/lib/navigation";

const ssoErrors: Record<string, string> = {
  access_denied: "Sign-in was canceled. Start again when you are ready.",
  account_conflict: "This identity cannot be linked automatically. Ask your Metrune administrator for help.",
  account_unavailable: "Your identity is valid, but it has no Metrune access. Ask your administrator to invite you.",
  invalid_state: "This sign-in request expired or was already used. Start again.",
  invalid_token: "The identity provider returned a token Metrune could not verify. Start again or contact your administrator.",
  not_configured: "Single sign-on is not configured for this deployment.",
  provider_error: "The identity provider could not complete sign-in. Try again.",
  temporarily_unavailable: "Single sign-on is temporarily unavailable. Try again shortly.",
};

export function LoginForm({
  methods,
  nextPath,
  ssoError,
}: {
  methods: AuthMethods | null;
  nextPath: string | null;
  ssoError: string | null;
}) {
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
    const safeNext = safeNextPath(next);
    router.replace(safeNext ?? (payload.user?.organizationId ? "/" : "/organizations"));
    router.refresh();
  }

  const externalError = ssoError
    ? ssoErrors[ssoError] ?? "Single sign-on could not be completed. Start again."
    : null;
  const ssoHref = `/api/auth/sso/start${nextPath ? `?next=${encodeURIComponent(nextPath)}` : ""}`;

  return (
    <section className="auth-card">
      <div className="auth-heading">
        <span className="brand-mark" aria-hidden="true"><MarkIcon size={26} /></span>
        <div><p className="eyebrow">Private, self-hosted workspace</p><h1>Sign in to Metrune</h1></div>
      </div>
      {methods?.ssoEnabled ? (
        <>
          <p className="auth-copy">Use your organization’s identity provider to continue.</p>
          {(externalError || error) && <p className="form-error auth-error" role="alert">{externalError ?? error}</p>}
          <a className="btn auth-submit auth-sso" href={ssoHref}>
            Continue with {methods.providerName ?? "single sign-on"}
          </a>
          <p className="auth-note">Metrune does not accept passwords while single sign-on is configured.</p>
        </>
      ) : methods?.passwordEnabled ? (
        <form className="auth-fields" onSubmit={submit}>
          <p className="auth-copy">Sign in once, then open any workspace you belong to.</p>
          <label className="field">
            <span>Email</span>
            <input name="email" type="email" autoComplete="username" required />
          </label>
          <label className="field">
            <span>Password</span>
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          {(externalError || error) && <p className="form-error auth-error" role="alert">{externalError ?? error}</p>}
          <button className="btn auth-submit" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <a className="auth-link" href="/forgot-password">Forgot your password?</a>
          <p className="auth-note">This deployment does not have single sign-on configured.</p>
        </form>
      ) : (
        <>
          <p className="form-error auth-error" role="alert">
            Sign-in settings could not be loaded. Check the Metrune API and try again.
          </p>
          <a className="btn ghost auth-submit" href="/login">Try again</a>
        </>
      )}
    </section>
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
