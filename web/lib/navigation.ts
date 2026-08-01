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
