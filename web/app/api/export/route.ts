import { getOrgSessions } from "@/lib/api";

function csv(value: unknown) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export async function GET() {
  const result = await getOrgSessions({}, 0, "ended", 200);
  const sessions = result.kind === "live" ? result.sessions : [];
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
    },
  });
}
