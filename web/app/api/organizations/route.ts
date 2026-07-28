import { adminJsonMutation, type CurrentUser } from "@/lib/api";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body?.name?.trim()) {
    return NextResponse.json({ error: "Workspace name is required." }, { status: 400 });
  }
  const result = await adminJsonMutation<CurrentUser>("/v1/organizations", {
    name: body.name.trim(),
  });
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  return NextResponse.json({ user: result.data }, { status: 201 });
}
