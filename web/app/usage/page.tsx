import Link from "next/link";
import { FilterBar } from "@/components/filters";
import { getFacets, getUsageBreakdown, type PageParams } from "@/lib/api";
import { formatCompact, formatMoney, label, shortModel } from "@/lib/format";
import { DemoBanner, toParams } from "../page";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const dimensions = ["category", "status", "client", "model", "provider", "team", "project"] as const;

function buildHref(params: PageParams, patch: Record<string, string | undefined>): string {
  const merged = { ...params, ...patch };
  const query = new URLSearchParams(Object.entries(merged).filter((entry): entry is [string, string] => Boolean(entry[1])));
  const text = query.toString();
  return text ? `/usage?${text}` : "/usage";
}

export default async function UsagePage({ searchParams }: PageProps) {
  const params = await toParams(await searchParams);
  const dimension = dimensions.includes(params.dimension as never) ? (params.dimension as string) : "category";
  const [{ data: values, source }, facets] = await Promise.all([getUsageBreakdown(params, dimension), getFacets(params)]);
  const totalCost = values.reduce((sum, value) => sum + value.cost, 0);
  const format = dimension === "model" ? shortModel : label;
  return (
    <>
      {source === "demo" && <DemoBanner />}
      <FilterBar params={params} facets={facets.data} />
      <nav className="tabs" aria-label="Breakdown dimension">
        {dimensions.map(entry => (
          <Link key={entry} href={buildHref(params, { dimension: entry })} className={entry === dimension ? "active" : ""} aria-current={entry === dimension ? "page" : undefined}>
            {label(entry)}
          </Link>
        ))}
      </nav>
      <section className="panel" aria-label={`Usage by ${dimension}`}>
        <div className="table-scroll">
          <table>
            <thead>
              <tr><th>{label(dimension)}</th><th className="num">Cost</th><th className="num">Tokens</th><th className="num">Sessions</th><th className="share-col">Share of cost</th></tr>
            </thead>
            <tbody>
              {values.map(value => (
                <tr key={value.dimension}>
                  <td><strong>{format(value.dimension)}</strong></td>
                  <td className="num">{formatMoney(value.cost)}</td>
                  <td className="num">{formatCompact(value.tokens)}</td>
                  <td className="num">{value.sessions}</td>
                  <td className="share-col">
                    <div className="share-track" aria-label={`${format(value.dimension)}: ${totalCost > 0 ? Math.round(value.cost / totalCost * 100) : 0}% of cost`}>
                      <span style={{ width: `${totalCost > 0 ? Math.max(2, value.cost / totalCost * 100) : 0}%` }} />
                    </div>
                    <small>{totalCost > 0 ? `${Math.round(value.cost / totalCost * 100)}%` : "—"}</small>
                  </td>
                </tr>
              ))}
              {values.length === 0 && <tr><td colSpan={5} className="empty">No usage in this range.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
