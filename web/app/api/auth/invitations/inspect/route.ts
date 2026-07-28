import { NextResponse } from "next/server";

export async function POST(request: Request) {
  return forward(request, "/v1/auth/invitations/inspect");
}

async function forward(request: Request, path: string) {
  const body = await request.text();
  const forwardedFor = request.headers.get("x-forwarded-for");
  try {
    const response = await fetch(`${process.env.METRUNE_API_URL ?? "http://localhost:8080"}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(forwardedFor ? { "X-Forwarded-For": forwardedFor } : {}),
      },
      body,
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    return NextResponse.json(payload, {
      status: response.status,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json({ error: "The Metrune API is unavailable." }, { status: 502 });
  }
}
