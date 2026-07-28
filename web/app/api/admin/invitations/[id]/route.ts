import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

type Context = { params: Promise<{ id: string }> };

export async function DELETE(_: Request, context: Context) {
  const { id } = await context.params;
  const result = await adminMutation(`/v1/org/invitations/${id}`, "DELETE");
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  return new NextResponse(null, { status: 204 });
}
