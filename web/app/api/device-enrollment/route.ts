import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body?.userCode || !["inspect", "approve", "deny"].includes(body.action)) {
    return NextResponse.json({ error: "A device code and action are required." }, { status: 400 });
  }
  const token = (await cookies()).get("metrune_session")?.value;
  if (!token) {
    return NextResponse.json({ error: "Sign in to approve a client." }, { status: 401 });
  }
  const inspecting = body.action === "inspect";
  const path = inspecting
    ? "/v1/oauth/device/verification"
    : "/v1/oauth/device/approval";
  const payload = inspecting
    ? { userCode: body.userCode }
    : {
        userCode: body.userCode,
        decision: body.action,
        teamId: body.teamId || null,
      };
  try {
    const response = await fetch(
      `${process.env.METRUNE_API_URL ?? "http://localhost:8080"}${path}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
        cache: "no-store",
      },
    );
    const result = await response.json().catch(() => ({}));
    const outgoing = NextResponse.json(
      response.ok ? result : { error: result.error ?? "The device request could not be processed." },
      { status: response.status },
    );
    outgoing.headers.set("Cache-Control", "no-store");
    return outgoing;
  } catch {
    return NextResponse.json(
      { error: "The Metrune API is unavailable." },
      { status: 502, headers: { "Cache-Control": "no-store" } },
    );
  }
}
