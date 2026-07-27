import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

type Context = { params: Promise<{ id: string }> };

export async function PATCH(request: Request, context: Context) {
  const { id } = await context.params;
  const body = await request.json().catch(() => null);
  if (!body) return NextResponse.json({ error: "A price definition is required." }, { status: 400 });
  const result = await adminMutation(`/v1/org/prices/${id}`, "PATCH", body);
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return NextResponse.json({ ok: true });
}

export async function DELETE(_request: Request, context: Context) {
  const { id } = await context.params;
  const result = await adminMutation(`/v1/org/prices/${id}`, "DELETE");
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return new NextResponse(null, { status: 204 });
}
