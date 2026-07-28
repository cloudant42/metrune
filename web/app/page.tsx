import { BreakdownBars, TrendChart } from "@/components/charts";
import { FilterBar } from "@/components/filters";
import { ArrowRightIcon } from "@/components/icons";
import { getFacets, getOverviewData, type PageParams } from "@/lib/api";
import { formatCompact, formatMoney, shortModel } from "@/lib/format";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export async function toParams(raw: Record<string, string | string[] | undefined>): Promise<PageParams> {
  return Object.fromEntries(Object.entries(raw).map(([key, value]) => [key, Array.isArray(value) ? value[0] : value]));
}

export function DemoBanner() {
  return (
    <div className="banner" role="status">
      <strong>Demo data</strong>
      <span>The API is unreachable or no dashboard token is configured. Connect it to see live organization usage.</span>
    </div>
  );
}

export default async function Home({ searchParams }: PageProps) {
  const params = await toParams(await searchParams);
  const [{ data, source }, facets] = await Promise.all([getOverviewData(params), getFacets(params)]);
  return (
    <>
      {source === "demo" && <DemoBanner />}
      <FilterBar params={params} facets={facets.data} />
      <section className="metric-grid" aria-label="Usage summary">
        <Metric label="Total spend" value={formatMoney(data.overview.totalCost)} detail="Sanitized usage metadata" />
        <Metric label="Tokens" value={formatCompact(data.overview.totalTokens)} detail="Input, output, cache and reasoning" />
        <Metric label="Sessions" value={formatCompact(data.overview.sessions)} detail="Across supported coding agents" />
        <Metric label="Active users" value={String(data.overview.activeUsers)} detail="Pseudonymous identities" />
      </section>
      <section className="panel" aria-labelledby="trend-title">
        <div className="panel-header">
          <div><p className="eyebrow">Daily cost across the selected range</p><h2 id="trend-title">Usage trend</h2></div>
        </div>
        <TrendChart points={data.timeseries} />
      </section>
      <div className="three-column">
        <section className="panel" aria-labelledby="top-categories">
          <div className="panel-header"><div><p className="eyebrow">Locally classified session purpose</p><h2 id="top-categories">What AI is used for</h2></div><a className="panel-link" href="/usage?dimension=category">Explore<ArrowRightIcon /></a></div>
          <BreakdownBars values={data.categories} />
        </section>
        <section className="panel" aria-labelledby="top-models">
          <div className="panel-header"><div><p className="eyebrow">Top models by cost</p><h2 id="top-models">Spend by model</h2></div><a className="panel-link" href="/models">Explore<ArrowRightIcon /></a></div>
          <BreakdownBars values={data.models} format={shortModel} />
        </section>
        <section className="panel" aria-labelledby="top-clients">
          <div className="panel-header"><div><p className="eyebrow">Coverage per coding agent</p><h2 id="top-clients">By coding agent</h2></div><a className="panel-link" href="/usage?dimension=client">Explore<ArrowRightIcon /></a></div>
          <BreakdownBars values={data.clients} />
        </section>
      </div>
    </>
  );
}

function Metric({ label: metricLabel, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="metric"><p>{metricLabel}</p><strong>{value}</strong><span>{detail}</span></article>;
}
