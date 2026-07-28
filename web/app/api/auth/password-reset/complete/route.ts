import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.text();
  const forwardedFor = request.headers.get("x-forwarded-for");
  try {
    const response = await fetch(`${process.env.METRUNE_API_URL ?? "http://localhost:8080"}/v1/auth/password-reset/complete`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(forwardedFor ? { "X-Forwarded-For": forwardedFor } : {}),
      },
      body,
      cache: "no-store",
    });
    if (response.status === 204) return new NextResponse(null, { status: 204 });
    const payload = await response.json().catch(() => ({}));
    return NextResponse.json(payload, { status: response.status });
  } catch {
    return NextResponse.json({ error: "The Metrune API is unavailable." }, { status: 502 });
  }
}
