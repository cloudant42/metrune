/**
 * Web session tokens are minted with an `mts_` prefix by both sign-in paths:
 * password login (`crates/metrune-api/src/app.rs`) and SSO
 * (`crates/metrune-api/src/oidc.rs`).
 *
 * The check matters because the API's `dashboard_auth` resolves service tokens
 * *before* browser sessions, so a dashboard token (`met_`) presented as a
 * `metrune_session` cookie would authorize organization reads and mutations
 * through the proxy while carrying an organization role and no user identity.
 * The dashboard forwards a browser session or nothing.
 */
const SESSION_TOKEN_PREFIX = "mts_";

export function isSessionToken(value: string | undefined | null): value is string {
  return typeof value === "string" && value.startsWith(SESSION_TOKEN_PREFIX);
}

/**
 * Whether the session cookie is marked `Secure`.
 *
 * A browser discards a `Secure` cookie sent over plain HTTP, and the
 * development stack is served over `http://localhost`. Safari enforces that
 * even for localhost, so keying this off `NODE_ENV` — which the production
 * build sets regardless of deployment — silently made sign-in impossible
 * there. Production Compose always sets `METRUNE_ENV=production`, so this
 * stays secure by default and relaxes only for a declared development server.
 */
export function sessionCookieIsSecure(): boolean {
  return process.env.METRUNE_ENV !== "development";
}
