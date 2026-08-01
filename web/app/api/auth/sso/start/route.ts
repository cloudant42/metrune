import { NextResponse } from "next/server";
import { safeNextPath } from "@/lib/navigation";

export async function GET(request: Request) {
  try {
    const publicApi = process.env.METRUNE_PUBLIC_API_URL ?? "http://localhost:8080";
    const target = new URL("/v1/auth/sso/start", publicApi);
    const next = safeNextPath(new URL(request.url).searchParams.get("next"));
    if (next) target.searchParams.set("next", next);
    return NextResponse.redirect(target);
  } catch {
    return NextResponse.redirect(new URL("/login?sso_error=configuration", request.url));
  }
}
