import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.text();
  const store = await cookies();
  const session = store.get("metrune_session")?.value;
  const forwardedFor = request.headers.get("x-forwarded-for");
  try {
    const response = await fetch(`${process.env.METRUNE_API_URL ?? "http://localhost:8080"}/v1/auth/invitations/accept`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(session ? { Authorization: `Bearer ${session}` } : {}),
        ...(forwardedFor ? { "X-Forwarded-For": forwardedFor } : {}),
      },
      body,
      cache: "no-store",
    });
    if (response.status === 204) return new NextResponse(null, { status: 204 });
    const payload = await response.json().catch(() => ({}));
    return NextResponse.json(payload, {
      status: response.status,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json({ error: "The Metrune API is unavailable." }, { status: 502 });
  }
}
