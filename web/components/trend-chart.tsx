"use client";

import { useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import type { TimeseriesPoint } from "@/lib/api";
import { formatCompact, formatMoney } from "@/lib/format";

const view = { width: 1000, height: 250, left: 54, right: 16, top: 14, bottom: 30 };

/* Round an axis maximum up to the nearest 1 / 2 / 5 x 10^n so ticks land on
   readable numbers. */
function niceMax(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const scaled = value / magnitude;
  const step = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
  return step * magnitude;
}

function tickLabel(value: number): string {
  if (value >= 1000) return `$${formatCompact(value)}`;
  return `$${Number.isInteger(value) ? value : value.toFixed(2)}`;
}

export function TrendChart({ points }: { points: TimeseriesPoint[] }) {
  const wrap = useRef<HTMLDivElement>(null);
  const svg = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<{ index: number; left: number } | null>(null);
  if (points.length === 0) return <p className="empty">No usage in this range.</p>;

  const max = niceMax(Math.max(...points.map(point => point.cost), 0.01));
  const plotWidth = view.width - view.left - view.right;
  const plotHeight = view.height - view.top - view.bottom;
  const baseline = view.height - view.bottom;
  const stepX = plotWidth / Math.max(points.length - 1, 1);
  const coordinates = points.map((point, index) => ({
    x: view.left + index * stepX,
    y: baseline - (point.cost / max) * plotHeight,
    ...point,
  }));
  const line = coordinates.map(point => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");
  const ticks = [0, 0.25, 0.5, 0.75, 1];
  /* At most six date ticks, always including the first and last bucket. */
  const dateStep = Math.max(1, Math.ceil(points.length / 6));
  const dateTicks = coordinates.filter((_, index) => index % dateStep === 0 || index === points.length - 1);
  const last = coordinates[coordinates.length - 1];
  const active = hover ? coordinates[hover.index] : null;

  function track(event: ReactPointerEvent<SVGSVGElement>) {
    const svgRect = svg.current?.getBoundingClientRect();
    const wrapRect = wrap.current?.getBoundingClientRect();
    if (!svgRect || !wrapRect) return;
    const scale = svgRect.width / view.width;
    const plotStart = svgRect.left + view.left * scale;
    const ratio = (event.clientX - plotStart) / (plotWidth * scale);
    const index = Math.min(points.length - 1, Math.max(0, Math.round(ratio * (points.length - 1))));
    const left = plotStart + index * stepX * scale - wrapRect.left;
    setHover({ index, left });
  }

  return (
    <div className="chart-wrap" ref={wrap}>
      <svg
        className="trend-chart"
        ref={svg}
        viewBox={`0 0 ${view.width} ${view.height}`}
        role="img"
        aria-labelledby="chart-title chart-description"
        onPointerMove={track}
        onPointerLeave={() => setHover(null)}
      >
        <title id="chart-title">Daily AI cost</title>
        <desc id="chart-description">
          Daily cost moves from {formatMoney(points[0]?.cost ?? 0)} to {formatMoney(points.at(-1)?.cost ?? 0)} over the selected range.
        </desc>
        <defs>
          <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--series-1)" stopOpacity="0.18" />
            <stop offset="100%" stopColor="var(--series-1)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {ticks.map((tick, index) => {
          const y = baseline - tick * plotHeight;
          /* Quarter gridlines are dropped on narrow screens, where the plot is
             too short to carry five labelled steps. */
          return (
            <g key={tick} className={index % 2 === 1 ? "tick-dense" : undefined}>
              <line x1={view.left} x2={view.width - view.right} y1={y} y2={y} className={tick === 0 ? "axis-line" : "grid-line"} />
              <text x={view.left - 10} y={y + 3.5} textAnchor="end" className="chart-tick y-tick">{tickLabel(max * tick)}</text>
            </g>
          );
        })}
        {dateTicks.map((point, index) => (
          <text
            key={point.bucket}
            x={point.x}
            y={baseline + 18}
            textAnchor={index === 0 ? "start" : index === dateTicks.length - 1 ? "end" : "middle"}
            /* Narrow screens keep only the first, middle and last date. */
            className={`chart-tick${[0, Math.floor((dateTicks.length - 1) / 2), dateTicks.length - 1].includes(index) ? "" : " tick-dense"}`}
          >
            {point.bucket.slice(5)}
          </text>
        ))}
        <polygon points={`${view.left},${baseline} ${line} ${view.width - view.right},${baseline}`} className="area" />
        <polyline points={line} className="line" />
        {active && (
          <g>
            <line x1={active.x} x2={active.x} y1={view.top} y2={baseline} className="chart-cursor" />
            <circle cx={active.x} cy={active.y} r="5" className="point" />
          </g>
        )}
        {!active && <circle cx={last.x} cy={last.y} r="4.5" className="point" />}
        {coordinates.map((point, index) => (
          <circle
            key={point.bucket}
            cx={point.x}
            cy={point.y}
            r="10"
            className="chart-hit"
            tabIndex={0}
            role="img"
            aria-label={`${point.bucket}: ${formatMoney(point.cost)}, ${formatCompact(point.tokens)} tokens, ${point.sessions} sessions`}
            onFocus={() => setHover({ index, left: 0 })}
            onBlur={() => setHover(null)}
          />
        ))}
      </svg>
      {active && hover && hover.left > 0 && (
        <div className="chart-tooltip" style={{ left: `${hover.left}px`, top: "6px" }} role="status">
          <p>{active.bucket}</p>
          <dl>
            <dt>Cost</dt><dd>{formatMoney(active.cost)}</dd>
            <dt>Tokens</dt><dd>{formatCompact(active.tokens)}</dd>
            <dt>Sessions</dt><dd>{active.sessions}</dd>
          </dl>
        </div>
      )}
      <details className="data-fallback">
        <summary>View chart as table</summary>
        <table>
          <thead><tr><th>Date</th><th className="num">Cost</th><th className="num">Tokens</th><th className="num">Sessions</th></tr></thead>
          <tbody>
            {points.map(point => (
              <tr key={point.bucket}>
                <td>{point.bucket}</td>
                <td className="num">{formatMoney(point.cost)}</td>
                <td className="num">{formatCompact(point.tokens)}</td>
                <td className="num">{point.sessions}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}
