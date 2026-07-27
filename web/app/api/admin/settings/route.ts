import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

export async function PATCH(request: Request) {
  const body = await request.json().catch(() => null);
  const days = Number(body?.retentionDays);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return NextResponse.json({ error: "retentionDays must be an integer between 1 and 3650" }, { status: 400 });
  }
  const result = await adminMutation("/v1/org/settings", "PATCH", { retentionDays: days });
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return new NextResponse(null, { status: 204 });
}
