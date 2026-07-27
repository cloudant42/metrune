import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

type RouteContext = { params: Promise<{ id: string }> };

export async function PATCH(request: Request, context: RouteContext) {
  const { id } = await context.params;
  const body = await request.json().catch(() => ({}));
  const result = await adminMutation(`/v1/org/installations/${id}`, "PATCH", { teamId: body.teamId ?? null });
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return new NextResponse(null, { status: 204 });
}
