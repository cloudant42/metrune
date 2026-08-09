/**
 * Routes reachable without a browser session.
 *
 * This is deliberately separate from the chrome-less list in `components/shell.tsx`:
 * that one also covers `/organizations` and `/device`, which render without the
 * sidebar but still require a signed-in user.
 */
const PUBLIC_PATHS = [
  "/login",
  "/accept-invite",
  "/forgot-password",
  "/reset-password",
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/sso/start",
  "/api/auth/password-reset",
  "/api/auth/invitations",
];

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some(path => pathname === path || pathname.startsWith(`${path}/`));
}

/**
 * Accept only same-origin relative continuation paths.
 *
 * This is intentionally stricter than URL parsing: values are eventually
 * concatenated into browser routes and must never become an absolute URL,
 * protocol-relative URL, or a path containing control characters/backslashes.
 */
export function safeNextPath(value: string | null | undefined): string | null {
  const candidate = value?.trim() ?? "";
  if (
    !candidate ||
    candidate.length > 2048 ||
    !candidate.startsWith("/") ||
    candidate.startsWith("//") ||
    candidate.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(candidate)
  ) {
    return null;
  }
  return candidate;
}
