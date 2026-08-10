import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";
import { sessionCookieIsSecure } from "@/lib/session";

export async function POST() {
  await adminMutation("/v1/auth/logout", "POST");
  const response = NextResponse.json({ ok: true });
  response.cookies.set("metrune_session", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: sessionCookieIsSecure(),
    path: "/",
    expires: new Date(0),
  });
  return response;
}
