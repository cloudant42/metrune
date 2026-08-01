import { getOrgSessions, type PageParams, type Session } from "@/lib/api";
import { NextResponse } from "next/server";
import { cookies } from "next/headers";

function csv(value: unknown) {
  let text = String(value ?? "");
  // Spreadsheet applications interpret cells beginning with these characters
  // as formulas. Prefix only suspicious string values so ordinary numeric
  // columns remain numeric while project/client labels cannot execute a
  // formula when opened in Excel, Numbers, or Sheets.
  if (typeof value === "string" && /^[\t\r\n=+\-@]/.test(text)) text = `'${text}`;
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

const FILTERS = ["range", "team", "project", "category", "client", "status", "workflow"] as const;
const PAGE_SIZE = 200;
const MAX_EXPORT_ROWS = 10_000;

export async function GET(request: Request) {
  const store = await cookies();
  if (!store.get("metrune_session")?.value) {
    return NextResponse.json({ error: "Sign in to export sessions." }, { status: 401 });
  }
  const url = new URL(request.url);
  const params: PageParams = {};
  for (const key of FILTERS) {
    const value = url.searchParams.get(key)?.trim();
    if (value) params[key] = value.slice(0, 320);
  }
  const sessions: Session[] = [];
  for (let page = 0; sessions.length < MAX_EXPORT_ROWS; page += 1) {
    const result = await getOrgSessions(params, page, "ended", PAGE_SIZE);
    if (result.kind === "unauthorized") return NextResponse.json({ error: "Sign in to export sessions." }, { status: 401 });
    if (result.kind === "forbidden") return NextResponse.json({ error: "Analyst or admin access is required to export sessions." }, { status: 403 });
    if (result.kind !== "live") return NextResponse.json({ error: "Live session data is temporarily unavailable." }, { status: 503 });
    sessions.push(...result.sessions);
    if (!result.hasMore) break;
    if (sessions.length >= MAX_EXPORT_ROWS) {
      return NextResponse.json(
        { error: `This export exceeds ${MAX_EXPORT_ROWS.toLocaleString()} sessions; narrow the filters and try again.` },
        { status: 413 },
      );
    }
  }
  const header = ["session_key", "project", "client", "category", "semantic_status", "confidence", "tokens", "cost_usd", "ended_at"];
  const rows = sessions.map(session => [
    session.sessionKey,
    session.projectAlias || "Unassigned",
    session.clientId,
    session.categoryId,
    session.classificationStatus,
    session.categoryConfidence,
    session.totalTokens,
    session.totalCost,
    new Date(session.endedAtMs).toISOString(),
  ]);
  const body = [header, ...rows].map(row => row.map(csv).join(",")).join("\n");
  return new Response(body, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": "attachment; filename=metrune-sessions.csv",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
