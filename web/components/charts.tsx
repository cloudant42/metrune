import type { Breakdown, CategoryModelBreakdown } from "@/lib/api";
import { formatCompact, formatMoney, label, shortModel } from "@/lib/format";

export { TrendChart } from "./trend-chart";

export function BreakdownBars({ values, limit = 6, format }: { values: Breakdown[]; limit?: number; format?: (value: string) => string }) {
  const shown = values.slice(0, limit);
  const max = Math.max(...shown.map(value => value.cost), 1);
  const show = format ?? label;
  if (shown.length === 0) return <p className="empty">No usage in this range.</p>;
  return (
    <div className="bars">
      {shown.map(value => (
        <div className="bar-row" key={value.dimension}>
          <div className="bar-label"><span>{show(value.dimension)}</span><strong>{formatMoney(value.cost)}</strong></div>
          <div className="bar-track" aria-label={`${show(value.dimension)}: ${formatMoney(value.cost)}`}>
            <span style={{ width: `${Math.max(2, value.cost / max * 100)}%` }} />
          </div>
          <small>{formatCompact(value.tokens)} tokens · {value.sessions} sessions</small>
        </div>
      ))}
    </div>
  );
}

/* Sequential blue ramp — the steps live in globals.css so each theme can run
   the ramp in the direction that reads as "more" on its own surface (darker on
   light, brighter on dark). Ink is paired per step to clear contrast. */
const ramp = Array.from({ length: 8 }, (_, index) => ({
  bg: `var(--hm-${index + 1})`,
  ink: `var(--hm-ink-${index + 1})`,
}));

const heatmapModelCap = 8;

export function ModelHeatmap({ values }: { values: CategoryModelBreakdown[] }) {
  const modelTotals = new Map<string, number>();
  const categoryTotals = new Map<string, number>();
  const cells = new Map<string, CategoryModelBreakdown>();
  for (const value of values) {
    modelTotals.set(value.model, (modelTotals.get(value.model) ?? 0) + value.tokens);
    categoryTotals.set(value.category, (categoryTotals.get(value.category) ?? 0) + value.tokens);
    cells.set(`${value.category}\0${value.model}`, value);
  }
  const allModels = [...modelTotals.keys()].sort((a, b) => (modelTotals.get(b) ?? 0) - (modelTotals.get(a) ?? 0));
  const models = allModels.slice(0, heatmapModelCap);
  const categories = [...categoryTotals.keys()].sort((a, b) => (categoryTotals.get(b) ?? 0) - (categoryTotals.get(a) ?? 0));
  if (values.length === 0) return <p className="empty">No model usage is available for this filter.</p>;
  return (
    <>
      <div className="table-scroll">
        <table className="heatmap-table">
          <caption className="sr-only">Token usage by category and model. Stronger cells mean a larger token share within the category row.</caption>
          <thead>
            <tr><th scope="col">Category</th>{models.map(model => <th scope="col" key={model}>{shortModel(model)}</th>)}</tr>
          </thead>
          <tbody>
            {categories.map(category => {
              const rowTotal = categoryTotals.get(category) ?? 0;
              return (
                <tr key={category}>
                  <th scope="row"><span>{label(category)}</span><small>{formatCompact(rowTotal)} tokens</small></th>
                  {models.map(model => {
                    const cell = cells.get(`${category}\0${model}`);
                    const share = cell && rowTotal > 0 ? cell.tokens / rowTotal : 0;
                    const step = ramp[Math.min(ramp.length - 1, Math.floor(share * ramp.length))];
                    return (
                      <td key={model} className={`hm-cell${cell ? "" : " empty"}`}
                        title={cell
                          ? `${label(category)} · ${model}: ${formatCompact(cell.tokens)} tokens, ${formatMoney(cell.cost)}, ${cell.sessions} sessions (${Math.round(share * 100)}% of the row)`
                          : `${label(category)} · ${model}: no usage`}>
                        {cell
                          ? <div style={{ background: step.bg, color: step.ink }}><strong>{formatCompact(cell.tokens)}</strong><small>{formatMoney(cell.cost)}</small></div>
                          : <span>—</span>}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {allModels.length > heatmapModelCap && <p className="panel-note">Showing the top {heatmapModelCap} of {allModels.length} models by tokens. Use the usage explorer for the full list.</p>}
      <p className="panel-note">
        <span className="hm-legend">
          <span>Less</span>
          {ramp.filter((_, index) => index % 2 === 0).map(step => <span key={step.bg} className="hm-swatch" style={{ background: step.bg }} />)}
          <span>More of the category row</span>
        </span>
      </p>
    </>
  );
}
