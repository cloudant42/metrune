import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body) return NextResponse.json({ error: "Enrollment details are required." }, { status: 400 });
  const auth = await import("next/headers").then(module => module.cookies());
  const token = auth.get("metrune_session")?.value;
  if (!token) return NextResponse.json({ error: "Sign in to enroll a client." }, { status: 401 });
  try {
    const response = await fetch(`${process.env.METRUNE_API_URL ?? "http://localhost:8080"}/v1/me/enrollment-codes`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) return NextResponse.json({ error: payload.error ?? "Enrollment failed." }, { status: response.status });
    return NextResponse.json(payload, { status: 201 });
  } catch {
    return NextResponse.json({ error: "The Metrune API is unavailable." }, { status: 502 });
  }
}
