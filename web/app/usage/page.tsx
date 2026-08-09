import Link from "next/link";
import { CategoryGuide } from "@/components/category-guide";
import { FilterBar } from "@/components/filters";
import { getCurrentUser, getFacets, getUsageBreakdown, type PageParams } from "@/lib/api";
import { formatCompact, formatMoney, label, shortModel } from "@/lib/format";
import { toParams, UnavailablePanel } from "../page";
import { redirect } from "next/navigation";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const dimensions = ["category", "workflow", "status", "client", "model", "provider", "team", "project"] as const;

function buildHref(params: PageParams, patch: Record<string, string | undefined>): string {
  const merged = { ...params, ...patch };
  const query = new URLSearchParams(Object.entries(merged).filter((entry): entry is [string, string] => Boolean(entry[1])));
  const text = query.toString();
  return text ? `/usage?${text}` : "/usage";
}

export default async function UsagePage({ searchParams }: PageProps) {
  const params = await toParams(await searchParams);
  const dimension = dimensions.includes(params.dimension as never) ? (params.dimension as string) : "category";
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=%2Fusage");
  const [values, facets] = await Promise.all([getUsageBreakdown(params, dimension), getFacets(params)]);
  if (!values || !facets) return <UnavailablePanel />;
  const totalCost = values.reduce((sum, value) => sum + value.cost, 0);
  const format = dimension === "model" ? shortModel : label;
  return (
    <>
      <FilterBar params={params} facets={facets} />
      <nav className="tabs" aria-label="Breakdown dimension">
        {dimensions.map(entry => (
          <Link key={entry} href={buildHref(params, { dimension: entry })} className={entry === dimension ? "active" : ""} aria-current={entry === dimension ? "page" : undefined}>
            {label(entry)}
          </Link>
        ))}
      </nav>
      {dimension === "category" && <CategoryGuide />}
      <section className="panel" aria-label={`Usage by ${dimension}`}>
        {dimension === "workflow" && (
          <div className="panel-header">
            <div>
              <p className="muted">Token and cost values describe turns where each signal occurred. Do not sum rows into a usage total.</p>
              <p className="eyebrow">A turn can carry more than one workflow signal</p>
              <h2>Workflow context is non-additive</h2>
            </div>
          </div>
        )}
        <div className="table-scroll">
          <table>
            <thead>
              <tr><th>{label(dimension)}</th><th className="num">{dimension === "workflow" ? "Cost context" : "Cost"}</th><th className="num">{dimension === "workflow" ? "Token context" : "Tokens"}</th><th className="num">Sessions</th>{dimension !== "workflow" && <th className="share-col">Share of cost</th>}</tr>
            </thead>
            <tbody>
              {values.map(value => (
                <tr key={value.dimension}>
                  <td><strong>{format(value.dimension)}</strong></td>
                  <td className="num">{formatMoney(value.cost)}</td>
                  <td className="num">{formatCompact(value.tokens)}</td>
                  <td className="num">{value.sessions}</td>
                  {dimension !== "workflow" && (
                    <td className="share-col">
                      <div className="share-track" aria-label={`${format(value.dimension)}: ${totalCost > 0 ? Math.round(value.cost / totalCost * 100) : 0}% of cost`}>
                        <span style={{ width: `${totalCost > 0 ? Math.max(2, value.cost / totalCost * 100) : 0}%` }} />
                      </div>
                      <small>{totalCost > 0 ? `${Math.round(value.cost / totalCost * 100)}%` : "—"}</small>
                    </td>
                  )}
                </tr>
              ))}
              {values.length === 0 && <tr><td colSpan={dimension === "workflow" ? 4 : 5} className="empty">No usage in this range.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
