import { adminJsonMutation } from "@/lib/api";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  const result = await adminJsonMutation<{ recoveryKey: string }>("/v1/org/vault/recovery", body);
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return NextResponse.json(result.data);
}
