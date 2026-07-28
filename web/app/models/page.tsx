import { BreakdownBars, ModelHeatmap } from "@/components/charts";
import { FilterBar } from "@/components/filters";
import { getFacets, getModelsData } from "@/lib/api";
import { DemoBanner, toParams } from "../page";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function ModelsPage({ searchParams }: PageProps) {
  const params = await toParams(await searchParams);
  const [{ data, source }, facets] = await Promise.all([getModelsData(params), getFacets(params)]);
  return (
    <>
      {source === "demo" && <DemoBanner />}
      <FilterBar params={params} facets={facets.data} />
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
    </>
  );
}
