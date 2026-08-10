import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

type RouteContext = { params: Promise<{ userId: string }> };

export async function POST(_request: Request, context: RouteContext) {
  const { userId } = await context.params;
  const result = await adminMutation(
    `/v1/org/members/${userId}/password-reset`,
    "POST",
  );
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  return NextResponse.json(result.data ?? {});
}
