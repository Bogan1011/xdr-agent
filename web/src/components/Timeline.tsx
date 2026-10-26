import { useMemo, useState } from "react";
import { Category, Stats, categoryOf } from "../api";

const series: { key: Category; label: string }[] = [
  { key: "process", label: "Process" },
  { key: "file", label: "File" },
  { key: "network", label: "Network" },
];

interface HourBucket {
  t: number;
  process: number;
  file: number;
  network: number;
  total: number;
}

const W = 720;
const H = 180;
const PAD = { l: 40, r: 8, t: 8, b: 22 };

// Timeline shows event volume per hour over the last 24 hours, stacked by category.
export default function Timeline({ stats }: { stats: Stats }) {
  const [hover, setHover] = useState<number | null>(null);

  const buckets = useMemo(() => {
    const now = new Date();
    now.setMinutes(0, 0, 0);
    const start = now.getTime() - 23 * 3600_000;
    const out: HourBucket[] = Array.from({ length: 24 }, (_, i) => ({
      t: start + i * 3600_000, process: 0, file: 0, network: 0, total: 0,
    }));
    for (const b of stats.timeline) {
      const i = Math.round((new Date(b.ts).getTime() - start) / 3600_000);
      if (i < 0 || i >= 24) continue;
      out[i][categoryOf(b.type)] += b.count;
      out[i].total += b.count;
    }
    return out;
  }, [stats]);

  const max = Math.max(1, ...buckets.map((b) => b.total));
  const ticks = niceTicks(max);
  const top = ticks[ticks.length - 1];
  const plotW = W - PAD.l - PAD.r;
  const plotH = H - PAD.t - PAD.b;
  const slot = plotW / 24;
  const barW = Math.max(4, slot - 6);
  const y = (v: number) => PAD.t + plotH - (v / top) * plotH;

  return (
    <div className="viz">
      <div className="legend" role="list">
        {series.map((s) => (
          <span key={s.key} role="listitem">
            <i className={`swatch fill-${s.key}`} /> {s.label}
          </span>
        ))}
      </div>
      <div className="viz-plot">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Events per hour, last 24 hours, by category">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} className={t === 0 ? "axis" : "grid"} />
              <text x={PAD.l - 6} y={y(t) + 4} className="tick" textAnchor="end">
                {compact(t)}
              </text>
            </g>
          ))}
          {buckets.map((b, i) => {
            const x = PAD.l + i * slot + (slot - barW) / 2;
            let acc = 0;
            const segs = series
              .filter((s) => b[s.key] > 0)
              .map((s, j, arr) => {
                const y0 = y(acc);
                acc += b[s.key];
                const y1 = y(acc);
                // Leave a 2px surface gap below every segment except the bottom one.
                const h = Math.max(1, y0 - y1 - (j > 0 ? 2 : 0));
                const isTop = j === arr.length - 1;
                return (
                  <path
                    key={s.key}
                    className={`fill-${s.key}`}
                    d={barPath(x, y1, barW, h, isTop ? 3 : 0)}
                  />
                );
              });
            return (
              <g key={b.t}>
                {segs}
                {i % 4 === 0 && (
                  <text x={x + barW / 2} y={H - 6} className="tick" textAnchor="middle">
                    {new Date(b.t).getHours().toString().padStart(2, "0")}:00
                  </text>
                )}
                <rect
                  x={PAD.l + i * slot}
                  y={PAD.t}
                  width={slot}
                  height={plotH}
                  className="hit"
                  onMouseEnter={() => setHover(i)}
                  onMouseLeave={() => setHover(null)}
                />
              </g>
            );
          })}
        </svg>
        {hover !== null && (
          <div
            className="tooltip"
            style={{ left: `${((PAD.l + hover * slot + slot / 2) / W) * 100}%` }}
          >
            <div className="tooltip-title">
              {new Date(buckets[hover].t).toLocaleString([], { hour: "2-digit", minute: "2-digit", day: "numeric", month: "short" })}
            </div>
            {series.map((s) => (
              <div key={s.key} className="tooltip-row">
                <i className={`swatch fill-${s.key}`} /> {s.label}
                <b>{buckets[hover][s.key].toLocaleString()}</b>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// barPath draws a bar with rounded top corners and a square base.
function barPath(x: number, yTop: number, w: number, h: number, r: number): string {
  r = Math.min(r, w / 2, h);
  return `M${x},${yTop + h}V${yTop + r}Q${x},${yTop} ${x + r},${yTop}H${x + w - r}Q${x + w},${yTop} ${x + w},${yTop + r}V${yTop + h}Z`;
}

function niceTicks(max: number): number[] {
  const step0 = max / 4;
  const mag = 10 ** Math.floor(Math.log10(step0));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= step0) ?? mag * 10;
  const out = [];
  for (let v = 0; v <= max + step * 0.999; v += step) out.push(Math.round(v));
  return out.length < 2 ? [0, 1] : out;
}

function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10_000 ? 0 : 1)}k`;
  return String(n);
}
