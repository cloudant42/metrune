import { NextResponse } from "next/server";
import { sessionCookieIsSecure } from "@/lib/session";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body?.email || !body?.password) {
    return NextResponse.json({ error: "Email and password are required." }, { status: 400 });
  }
  try {
    const response = await fetch(`${process.env.METRUNE_API_URL ?? "http://localhost:8080"}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: body.email, password: body.password }),
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      return NextResponse.json({ error: payload.error ?? "Sign-in failed." }, { status: response.status });
    }
    const result = NextResponse.json({ user: payload.user });
    result.cookies.set("metrune_session", payload.sessionToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: sessionCookieIsSecure(),
      path: "/",
      expires: new Date(payload.expiresAt),
    });
    return result;
  } catch {
    return NextResponse.json({ error: "The Metrune API is unavailable." }, { status: 502 });
  }
}
