import { adminJsonMutation } from "@/lib/api";
import { NextResponse } from "next/server";

type ClassifierTestResult = {
  category: string;
  confidence: number;
  responseMode: "auto" | "structured" | "prompt_json";
  repaired: boolean;
};

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  const result = await adminJsonMutation<ClassifierTestResult>("/v1/org/classifier/test", body);
  if (!result.ok) return NextResponse.json({ error: result.error }, { status: result.status });
  return NextResponse.json(result.data);
}
