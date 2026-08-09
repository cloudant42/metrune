import { NextResponse, type NextRequest } from "next/server";
import { isPublicPath, safeNextPath } from "@/lib/navigation";
import { isSessionToken } from "@/lib/session";

/**
 * Fail closed before anything renders.
 *
 * Page-level guards run inside a streamed Suspense boundary, so a `redirect()`
 * there arrives as a meta refresh after the shell — including the organization
 * name — has already been flushed. Checking the session here turns that into a
 * real 307 and keeps organization data out of anonymous responses entirely.
 *
 * This only proves a browser session token is present, not that it is still
 * valid. The API remains the authority on that, and the pages keep their
 * `getCurrentUser()` checks.
 */
export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (isPublicPath(pathname)) return NextResponse.next();
  if (isSessionToken(request.cookies.get("metrune_session")?.value)) return NextResponse.next();

  // Proxy routes are called by scripts and fetch(), not navigated to. Answer
  // them the way the API would rather than redirecting a POST to a login page.
  if (pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }

  const login = new URL("/login", request.url);
  const next = safeNextPath(`${pathname}${search}`);
  if (next && next !== "/") login.searchParams.set("next", next);
  return NextResponse.redirect(login, 307);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg|.*\\.(?:png|jpg|jpeg|gif|svg|webp|ico|woff2?)$).*)"],
};
