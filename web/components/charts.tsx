import type { Breakdown, CategoryModelBreakdown, TimeseriesPoint } from "@/lib/api";
import { formatCompact, formatMoney, label, shortModel } from "@/lib/format";

export function TrendChart({ points }: { points: TimeseriesPoint[] }) {
  const width = 800, height = 210, pad = 18;
  const max = Math.max(...points.map(point => point.cost), 1);
  const coordinates = points.map((point, index) => ({
    x: pad + index * ((width - pad * 2) / Math.max(points.length - 1, 1)),
    y: height - pad - (point.cost / max) * (height - pad * 2),
    ...point,
  }));
  const line = coordinates.map(point => `${point.x},${point.y}`).join(" ");
  return (
    <div className="chart-wrap">
      <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-labelledby="chart-title chart-description">
        <title id="chart-title">Daily AI cost</title>
        <desc id="chart-description">Daily cost rises from {formatMoney(points[0]?.cost ?? 0)} to {formatMoney(points.at(-1)?.cost ?? 0)} over the selected range.</desc>
        {[0.25, 0.5, 0.75, 1].map(levelPoint => <line key={levelPoint} x1={pad} x2={width - pad} y1={height - pad - levelPoint * (height - pad * 2)} y2={height - pad - levelPoint * (height - pad * 2)} className="grid-line" />)}
        <polygon points={`${pad},${height - pad} ${line} ${width - pad},${height - pad}`} className="area" />
        <polyline points={line} className="line" />
        {coordinates.map(point => <circle key={point.bucket} cx={point.x} cy={point.y} r="4" className="point" tabIndex={0} role="img" aria-label={`${point.bucket}: ${formatMoney(point.cost)}, ${formatCompact(point.tokens)} tokens`} />)}
      </svg>
      <div className="chart-axis" aria-hidden="true"><span>{points[0]?.bucket.slice(5)}</span><span>{points.at(-1)?.bucket.slice(5)}</span></div>
      <details className="data-fallback"><summary>View chart as table</summary><table><thead><tr><th>Date</th><th>Cost</th><th>Tokens</th><th>Sessions</th></tr></thead><tbody>{points.map(point => <tr key={point.bucket}><td>{point.bucket}</td><td>{formatMoney(point.cost)}</td><td>{formatCompact(point.tokens)}</td><td>{point.sessions}</td></tr>)}</tbody></table></details>
    </div>
  );
}

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
          <div className="bar-track" aria-label={`${show(value.dimension)}: ${formatMoney(value.cost)}`}><span style={{ width: `${Math.max(3, value.cost / max * 100)}%` }} /></div>
          <small>{formatCompact(value.tokens)} tokens · {value.sessions} sessions</small>
        </div>
      ))}
    </div>
  );
}

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
          <caption className="sr-only">Token usage by category and model. Darker cells mean a larger token share within the category row.</caption>
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
                    return (
                      <td key={model} className={`hm-cell${cell ? "" : " empty"}`}
                        style={cell ? { backgroundColor: `rgb(59 130 246 / ${(0.07 + share * 0.5).toFixed(3)})` } : undefined}
                        title={cell ? `${label(category)} · ${model}: ${formatCompact(cell.tokens)} tokens, ${formatMoney(cell.cost)}, ${cell.sessions} sessions` : `${label(category)} · ${model}: no usage`}>
                        {cell ? <><strong>{formatCompact(cell.tokens)}</strong><small>{formatMoney(cell.cost)}</small></> : <span>—</span>}
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
      <p className="panel-note"><span className="hm-swatch" />Darker cells represent a larger token share within that category row.</p>
    </>
  );
}
