import { BreakdownBars, ModelHeatmap } from "@/components/charts";
import { CategoryGuide } from "@/components/category-guide";
import { FilterBar } from "@/components/filters";
import { getFacets, getModelsData } from "@/lib/api";
import { formatCompact, label, shortModel } from "@/lib/format";
import { DemoBanner, toParams, UnavailablePanel } from "../page";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function ModelsPage({ searchParams }: PageProps) {
  const params = await toParams(await searchParams);
  const [{ data, source }, facets] = await Promise.all([getModelsData(params), getFacets(params)]);
  if (source === "unavailable" || facets.source === "unavailable") return <UnavailablePanel />;
  return (
    <>
      {source === "demo" && <DemoBanner />}
      <FilterBar params={params} facets={facets.data} />
      <CategoryGuide />
      <section className="panel" aria-labelledby="heatmap-title">
        <div className="panel-header">
          <div><p className="eyebrow">Token share of each category, per model</p><h2 id="heatmap-title">Which models power each category?</h2></div>
        </div>
        <ModelHeatmap values={data.categoryModels} />
      </section>
      <section className="panel" aria-labelledby="providers-title">
        <div className="panel-header">
          <div><p className="eyebrow">Cost split across model providers</p><h2 id="providers-title">Spend by provider</h2></div>
        </div>
        <BreakdownBars values={data.providers} limit={10} />
      </section>
      <section className="panel" aria-labelledby="workflow-model-title">
        <div className="panel-header">
          <div>
            <p className="muted">Coverage varies by coding agent. Unsupported signals are unknown, not zero. Token and cost context is non-additive across signals.</p>
            <p className="eyebrow">Observed event counts attributed to model steps</p>
            <h2 id="workflow-model-title">Which models read, search, and edit?</h2>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Workflow</th><th>Model</th><th className="num">Events</th><th className="num">Token context</th><th className="num">Sessions</th></tr></thead>
            <tbody>
              {data.workflowModels.map(row => (
                <tr key={`${row.signal}-${row.model}`}>
                  <td><strong>{label(row.signal)}</strong></td>
                  <td>{row.model === "Unattributed" ? row.model : shortModel(row.model)}</td>
                  <td className="num">{formatCompact(row.count)}</td>
                  <td className="num">{formatCompact(row.tokens)}</td>
                  <td className="num">{row.sessions}</td>
                </tr>
              ))}
              {data.workflowModels.length === 0 && <tr><td colSpan={5} className="empty">No turn-level workflow data in this range.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel" aria-labelledby="classifier-overhead-title">
        <div className="panel-header">
          <div>
            <p className="muted">Rule, inherited, and cache-hit classifications use no classifier tokens.</p>
            <p className="eyebrow">Separate from coding-agent work tokens</p>
            <h2 id="classifier-overhead-title">Semantic classifier overhead</h2>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Classifier</th><th>Measurement</th><th className="num">Input</th><th className="num">Output</th><th className="num">Cache read</th><th className="num">Reasoning</th><th className="num">Requests</th></tr></thead>
            <tbody>
              {data.classificationOverhead.map(row => (
                <tr key={`${row.provider}-${row.model}-${row.measurement}`}>
                  <td><strong>{row.model || row.provider}</strong></td>
                  <td>{label(row.measurement)}</td>
                  <td className="num">{formatCompact(row.inputTokens)}</td>
                  <td className="num">{formatCompact(row.outputTokens)}</td>
                  <td className="num">{formatCompact(row.cacheReadTokens)}</td>
                  <td className="num">{formatCompact(row.reasoningTokens)}</td>
                  <td className="num">{formatCompact(row.requests)}</td>
                </tr>
              ))}
              {data.classificationOverhead.length === 0 && <tr><td colSpan={7} className="empty">No semantic-model requests in this range.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
