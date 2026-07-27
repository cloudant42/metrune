import { adminMutation } from "@/lib/api";
import { NextResponse } from "next/server";

export async function POST() {
  await adminMutation("/v1/auth/logout", "POST");
  const response = NextResponse.json({ ok: true });
  response.cookies.set("metrune_session", "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: new Date(0),
  });
  return response;
}
