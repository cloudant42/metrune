import Link from "next/link";
import { FilterBar } from "@/components/filters";
import {
  getCurrentUser,
  getFacets,
  getMyInstallations,
  getMySessions,
  getMyUsage,
  getOrgSessions,
  type PageParams,
  type Session,
  type SessionsResult,
} from "@/lib/api";
import { formatCompact, formatMoney, formatTime, label } from "@/lib/format";
import { DemoBanner, toParams } from "../page";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

function buildHref(params: PageParams, patch: Record<string, string | undefined>): string {
  const merged = { ...params, ...patch };
  const query = new URLSearchParams(Object.entries(merged).filter((entry): entry is [string, string] => Boolean(entry[1])));
  const text = query.toString();
  return text ? `/sessions?${text}` : "/sessions";
}

const sortable = new Set(["ended", "cost", "tokens", "category"]);

export default async function SessionsPage({ searchParams }: PageProps) {
  const params = await toParams(await searchParams);
  const sort = sortable.has(params.sort ?? "") ? (params.sort as string) : "ended";
  const page = Math.max(0, Number.parseInt(params.page ?? "0", 10) || 0);
  const user = await getCurrentUser();

  if (user) {
    const [result, installations, usage] = await Promise.all([
      getMySessions(params, page, sort),
      getMyInstallations(),
      getMyUsage(),
    ]);
    const installationNames = new Map(installations.map(item => [item.id, item.name]));
    const selectedInstallation = params.installation ? installationNames.get(params.installation) : undefined;
    return (
      <>
        {result.kind === "unavailable" && <DemoBanner />}
        <form className="filter-bar" aria-label="Filter my sessions">
          <label>
            <span>Date range</span>
            <select name="range" defaultValue={params.range ?? "30"}>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </select>
          </label>
          <label>
            <span>Client machine</span>
            <select name="installation" defaultValue={params.installation ?? ""}>
              <option value="">All my machines</option>
              {installations.map(item => (
                <option key={item.id} value={item.id}>{item.name}{item.revoked ? " (revoked)" : ""}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Category</span>
            <select name="category" defaultValue={params.category ?? ""}>
              <option value="">All categories</option>
              {(usage?.categories ?? []).map(item => (
                <option key={item.dimension} value={item.dimension}>{label(item.dimension)}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Semantic status</span>
            <select name="status" defaultValue={params.status ?? ""}>
              <option value="">All semantic statuses</option>
              {(["classified", "failed", "unavailable", "not_configured", "no_input"] as const).map(status => (
                <option key={status} value={status}>{label(status)}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Coding agent</span>
            <select name="client" defaultValue={params.client ?? ""}>
              <option value="">All agents</option>
              {(usage?.clients ?? []).map(item => (
                <option key={item.dimension} value={item.dimension}>{item.dimension}</option>
              ))}
            </select>
          </label>
          <div className="filter-actions">
            <button type="submit" className="btn">Apply</button>
            <a className="btn ghost" href="/sessions">Reset</a>
          </div>
        </form>
        <SessionTable
          result={result}
          params={params}
          sort={sort}
          page={page}
          eyebrow="Sessions from your own enrolled clients"
          title={selectedInstallation ? `My sessions · ${selectedInstallation}` : "My sessions"}
          installationNames={installationNames}
        />
      </>
    );
  }

  const [result, facets] = await Promise.all([getOrgSessions(params, page, sort), getFacets(params)]);
  if (result.kind === "forbidden") {
    return (
      <section className="panel" aria-labelledby="sessions-unavailable-title">
        <div className="panel-header">
          <div><p className="eyebrow">Only analysts and admins can drill into sessions</p><h2 id="sessions-unavailable-title">Sessions are private</h2></div>
        </div>
        <div className="panel-body">
          <p className="onboarding-copy">
            Session-level drilldown is only available to analyst and admin service tokens.
            Signed-in members can review their own sessions after signing in — organization analytics stay aggregated
            and never expose another person&apos;s sessions.
          </p>
        </div>
      </section>
    );
  }
  return (
    <>
      {result.kind === "unavailable" && <DemoBanner />}
      <FilterBar params={params} facets={facets.data} />
      <SessionTable
        result={result}
        params={params}
        sort={sort}
        page={page}
        eyebrow="Pseudonymous identities, no prompt content"
        title="Classified sessions"
        showExport
      />
    </>
  );
}

function SessionTable({
  result,
  params,
  sort,
  page,
  eyebrow,
  title,
  installationNames,
  showExport = false,
}: {
  result: SessionsResult;
  params: PageParams;
  sort: string;
  page: number;
  eyebrow: string;
  title: string;
  installationNames?: Map<string, string>;
  showExport?: boolean;
}) {
  const sessions: Session[] = result.kind === "live" ? result.sessions : [];
  const hasMore = result.kind === "live" && result.hasMore;
  const sortHeader = (key: string, headerTitle: string) => (
    <Link href={buildHref(params, { sort: key, page: undefined })} className={sort === key ? "sorted" : ""} aria-label={`Sort by ${headerTitle}`}>
      {headerTitle}{sort === key ? " ↓" : ""}
    </Link>
  );
  return (
    <section className="panel" aria-label={title}>
      <div className="panel-header">
        <div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>
        {showExport && <a className="btn ghost" href="/api/export">Export CSV</a>}
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Session</th>
              {installationNames && <th>Machine</th>}
              <th>Project</th><th>Agent</th>
              <th>{sortHeader("category", "Category")}</th>
              <th>Semantic status</th>
              <th className="num">Confidence</th>
              <th className="num">{sortHeader("tokens", "Tokens")}</th>
              <th className="num">{sortHeader("cost", "Cost")}</th>
              <th>{sortHeader("ended", "Finished")}</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(session => (
              <tr key={`${session.sessionKey}-${session.endedAtMs}`}>
                <td><code>{session.sessionKey.slice(0, 8)}</code></td>
                {installationNames && <td>{installationNames.get(session.installationId) ?? "Unknown"}</td>}
                <td>{session.projectAlias || "Unassigned"}</td>
                <td><span className="client-badge">{session.clientId}</span></td>
                <td>{session.classificationStatus === "classified" ? label(session.categoryId) : "Unclassified"}</td>
                <td>{label(session.classificationStatus)}</td>
                <td className="num">{Math.round(session.categoryConfidence * 100)}%</td>
                <td className="num">{formatCompact(session.totalTokens)}</td>
                <td className="num">{formatMoney(session.totalCost)}</td>
                <td>{formatTime(session.endedAtMs)}</td>
              </tr>
            ))}
            {sessions.length === 0 && (
              <tr>
                <td colSpan={installationNames ? 10 : 9} className="empty">
                  {result.kind === "unavailable" ? "The API is unreachable — no live sessions to show." : "No sessions match this filter."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <nav className="pagination" aria-label="Session pages">
        {page > 0
          ? <Link className="btn ghost small" href={buildHref(params, { page: String(page - 1) })}>← Newer</Link>
          : <span className="btn ghost small disabled" aria-hidden="true">← Newer</span>}
        <span className="page-indicator">Page {page + 1}</span>
        {hasMore
          ? <Link className="btn ghost small" href={buildHref(params, { page: String(page + 1) })}>Older →</Link>
          : <span className="btn ghost small disabled" aria-hidden="true">Older →</span>}
      </nav>
    </section>
  );
}
