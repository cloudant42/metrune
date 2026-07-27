import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

export async function DELETE(_: Request, context: { params: Promise<{ credentialId: string }> }) {
  const { credentialId } = await context.params;
  const result = await adminMutation(`/v1/org/credentials/${encodeURIComponent(credentialId)}`, "DELETE");
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return new NextResponse(null, { status: 204 });
}
