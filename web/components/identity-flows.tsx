"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { MarkIcon } from "./icons";

type InvitationInspection = {
  organizationName: string;
  maskedEmail: string;
  role: "viewer" | "analyst" | "admin";
  existingAccount: boolean;
  expiresAt: string;
};

function AuthHeading({ title, eyebrow }: { title: string; eyebrow: string }) {
  return (
    <div className="auth-heading">
      <span className="brand-mark" aria-hidden="true"><MarkIcon size={26} /></span>
      <div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1></div>
    </div>
  );
}

function fragmentToken(storageKey: string): string {
  const fromFragment = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
  if (fromFragment) sessionStorage.setItem(storageKey, fromFragment);
  window.history.replaceState(null, "", window.location.pathname);
  return fromFragment || sessionStorage.getItem(storageKey) || "";
}

export function AcceptInvitationForm({
  ssoEnabled,
  authConfigurationAvailable,
}: {
  ssoEnabled: boolean;
  authConfigurationAvailable: boolean;
}) {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [invitation, setInvitation] = useState<InvitationInspection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    const value = fragmentToken("metrune_invite_token");
    // The token lives in the URL fragment, which is never sent to the server and
    // is unreadable until after mount, so this cannot move into render.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setToken(value);
    if (!value) {
      setError("This invitation link is missing its secure token.");
      setBusy(false);
      return;
    }
    void fetch("/api/auth/invitations/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: value }),
      cache: "no-store",
    }).then(async response => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error ?? "This invitation is unavailable.");
      setInvitation(payload as InvitationInspection);
    }).catch(reason => {
      setError(reason instanceof Error ? reason.message : "This invitation is unavailable.");
    }).finally(() => setBusy(false));
  }, []);

  async function accept(body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    const response = await fetch("/api/auth/invitations/accept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, ...body }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(payload.error ?? "The invitation could not be accepted.");
      setBusy(false);
      return;
    }
    sessionStorage.removeItem("metrune_invite_token");
    router.replace(invitation?.existingAccount ? "/organizations" : "/login");
    router.refresh();
  }

  async function createAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    if (password !== String(form.get("confirmPassword") ?? "")) {
      setError("Passwords do not match.");
      return;
    }
    await accept({ displayName: form.get("displayName"), password });
  }

  async function createSsoAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await accept({ displayName: form.get("displayName") });
  }

  return (
    <section className="auth-card">
      <AuthHeading title="Accept invitation" eyebrow="Workspace invitation" />
      {busy && !invitation && <p className="auth-copy">Checking your invitation…</p>}
      {invitation && (
        <>
          <p className="auth-copy">
            Join <strong>{invitation.organizationName}</strong> as <strong>{invitation.role}</strong> using {invitation.maskedEmail}.
          </p>
          {invitation.existingAccount ? (
            <div className="auth-actions">
              <p className="auth-note">Sign in with the invited email, then return here to accept access.</p>
              <a className="btn ghost" href="/login?next=/accept-invite">Sign in first</a>
              <button className="btn" type="button" disabled={busy} onClick={() => accept({})}>
                {busy ? "Accepting…" : "Accept invitation"}
              </button>
            </div>
          ) : !authConfigurationAvailable ? (
            <p className="form-error auth-error" role="alert">
              Sign-in settings could not be loaded. Check the Metrune API and try again.
            </p>
          ) : ssoEnabled ? (
            <form className="auth-fields" onSubmit={createSsoAccount}>
              <p className="auth-note">
                Accept the invitation, then sign in through your organization’s identity provider.
              </p>
              <label className="field">
                <span>Display name <small>(optional)</small></span>
                <input name="displayName" autoComplete="name" maxLength={120} />
              </label>
              <button className="btn auth-submit" type="submit" disabled={busy}>
                {busy ? "Accepting…" : "Accept invitation"}
              </button>
            </form>
          ) : (
            <form className="auth-fields" onSubmit={createAccount}>
              <label className="field">
                <span>Display name</span>
                <input name="displayName" autoComplete="name" required maxLength={120} />
              </label>
              <label className="field">
                <span>Password</span>
                <input name="password" type="password" autoComplete="new-password" minLength={12} maxLength={128} required />
              </label>
              <label className="field">
                <span>Confirm password</span>
                <input name="confirmPassword" type="password" autoComplete="new-password" minLength={12} maxLength={128} required />
              </label>
              <button className="btn auth-submit" type="submit" disabled={busy}>
                {busy ? "Creating account…" : "Create account and join"}
              </button>
            </form>
          )}
        </>
      )}
      {error && <p className="form-error auth-error" role="alert">{error}</p>}
      {!busy && !invitation && <a className="auth-link" href="/login">Return to sign in</a>}
    </section>
  );
}

export function ForgotPasswordForm() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const response = await fetch("/api/auth/password-reset/request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    setBusy(false);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(payload.error ?? "The reset request could not be processed.");
      return;
    }
    setSent(true);
  }

  return (
    <form className="auth-card" onSubmit={submit}>
      <AuthHeading title="Reset your password" eyebrow="Account recovery" />
      <p className="auth-copy">
        {sent
          ? "If that address belongs to an active account, a single-use reset link has been sent."
          : "Enter your account email. Metrune never reveals whether an address is registered."}
      </p>
      {!sent && (
        <>
          <label className="field">
            <span>Email</span>
            <input value={email} onChange={event => setEmail(event.target.value)} type="email" autoComplete="email" required />
          </label>
          <button className="btn auth-submit" type="submit" disabled={busy}>
            {busy ? "Sending…" : "Send reset link"}
          </button>
        </>
      )}
      {error && <p className="form-error auth-error" role="alert">{error}</p>}
      <a className="auth-link" href="/login">Return to sign in</a>
    </form>
  );
}

export function ResetPasswordForm() {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const value = fragmentToken("metrune_reset_token");
    // The token lives in the URL fragment, which is never sent to the server and
    // is unreadable until after mount, so this cannot move into render.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setToken(value);
    if (!value) setError("This reset link is missing its secure token.");
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const newPassword = String(form.get("password") ?? "");
    if (newPassword !== String(form.get("confirmPassword") ?? "")) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    const response = await fetch("/api/auth/password-reset/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, newPassword }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(payload.error ?? "The password could not be reset.");
      setBusy(false);
      return;
    }
    sessionStorage.removeItem("metrune_reset_token");
    router.replace("/login");
    router.refresh();
  }

  return (
    <form className="auth-card" onSubmit={submit}>
      <AuthHeading title="Choose a new password" eyebrow="Account recovery" />
      <p className="auth-copy">Your reset link is single-use. Completing it signs out all existing browser sessions.</p>
      <label className="field">
        <span>New password</span>
        <input name="password" type="password" autoComplete="new-password" minLength={12} maxLength={128} required disabled={!token} />
      </label>
      <label className="field">
        <span>Confirm password</span>
        <input name="confirmPassword" type="password" autoComplete="new-password" minLength={12} maxLength={128} required disabled={!token} />
      </label>
      {error && <p className="form-error auth-error" role="alert">{error}</p>}
      <button className="btn auth-submit" type="submit" disabled={busy || !token}>
        {busy ? "Updating…" : "Update password"}
      </button>
      <a className="auth-link" href="/login">Return to sign in</a>
    </form>
  );
}
