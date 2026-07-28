import { adminJsonMutation, type CurrentUser } from "@/lib/api";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body?.organizationId) {
    return NextResponse.json({ error: "Choose a workspace." }, { status: 400 });
  }
  const result = await adminJsonMutation<CurrentUser>("/v1/auth/organization", body);
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  return NextResponse.json({ user: result.data });
}
