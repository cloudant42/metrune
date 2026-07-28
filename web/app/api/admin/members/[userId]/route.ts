import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

type RouteContext = { params: Promise<{ userId: string }> };

export async function PATCH(request: Request, context: RouteContext) {
  const { userId } = await context.params;
  const body = await request.json().catch(() => null);
  const result = await adminMutation(`/v1/org/members/${userId}`, "PATCH", body);
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  return new NextResponse(null, { status: 204 });
}

export async function DELETE(_request: Request, context: RouteContext) {
  const { userId } = await context.params;
  const result = await adminMutation(`/v1/org/members/${userId}`, "DELETE");
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  return new NextResponse(null, { status: 204 });
}
