import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Alert, Severity, StoryNode, Storyline, categoryOf } from "../api";
import { SeverityBadge } from "./Response";

// ProcessGraph draws a storyline like an EDR process explorer: user,
// endpoint and session on the left, the process tree to the right. The path
// to the alert and every alerting process stay expanded; quiet branches fold
// into "+N more" nodes. Wheel zooms around the pointer, drag pans.

const sevRank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const shells = new Set(["bash", "sh", "dash", "zsh", "ksh", "fish", "-bash", "-sh", "-zsh"]);
const COL = 190;
const ROW = 104;
const R = 24;
const MIN_K = 0.15;
const MAX_K = 2.5;
// The focus process's own children stay open up to this many.
const OPEN_CHILDREN = 12;

export function base(exe: string): string {
  return exe ? exe.split("/").pop() || exe : "unknown process";
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

type Kind = "user" | "host" | "session" | "shell" | "process" | "more";

interface GNode {
  id: string;
  kind: Kind;
  label: string;
  sub?: string;
  x: number;
  y: number;
  node?: StoryNode;
  // For "more" nodes: the parent whose hidden children they stand for.
  parent?: string;
}

interface Props {
  st: Storyline;
  host: string;
  ip: string;
  byProcess: Map<string, Alert[]>;
  selected: string;
  onSelect: (guid: string) => void;
  onShowActivity: () => void;
}

export default function ProcessGraph({ st, host, ip, byProcess, selected, onSelect, onShowActivity }: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const { g, edges, width, height, hidden, hot } = useMemo(
    () => layout(st, host, ip, byProcess, expanded),
    [st, host, ip, byProcess, expanded],
  );
  const pos = new Map(g.map((n) => [n.id, n]));

  const sel = st.nodes.find((n) => n.guid === selected) ?? (st.session?.guid === selected ? st.session : undefined);
  // The drawer covers the right of the canvas; fit and center use the rest.
  const drawerW = (el: HTMLDivElement) => (sel ? Math.min(340, el.clientWidth * 0.9) : 0);

  // --- pan and zoom ---
  const box = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [anim, setAnim] = useState(false);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);

  const animate = (v: { x: number; y: number; k: number }) => {
    setAnim(true);
    setView(v);
    window.setTimeout(() => setAnim(false), 320);
  };

  const fit = useCallback(() => {
    const el = box.current;
    if (!el) return;
    const w = el.clientWidth - drawerW(el);
    const h = el.clientHeight;
    const k = Math.max(MIN_K, Math.min(1.1, (w - 40) / width, (h - 40) / height));
    animate({ x: (w - width * k) / 2, y: (h - height * k) / 2, k });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [width, height, !!sel]);

  const zoomBy = (f: number, px?: number, py?: number) => {
    const el = box.current;
    if (!el) return;
    setView((v) => {
      const k = Math.min(MAX_K, Math.max(MIN_K, v.k * f));
      const cx = px ?? el.clientWidth / 2;
      const cy = py ?? el.clientHeight / 2;
      return { k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k };
    });
  };

  const center = (id: string) => {
    const el = box.current;
    const n = pos.get(id);
    if (!el || !n) return;
    const k = Math.max(view.k, 0.9);
    animate({ k, x: (el.clientWidth - drawerW(el)) / 2 - n.x * k, y: el.clientHeight / 2 - n.y * k });
  };

  // Fit when the graph first loads and when branches open or close.
  const shape = g.length;
  useEffect(() => {
    fit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape, !!sel]);

  // The wheel listener must not be passive, so the page does not scroll.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomBy(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  });

  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return;
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
  };
  const onPointerMove = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    if (!d.moved && Math.hypot(dx, dy) < 4) return;
    if (!d.moved) {
      d.moved = true;
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    }
    setView((v) => ({ ...v, x: d.vx + dx, y: d.vy + dy }));
  };
  const onPointerUp = () => {
    // Let the click that ends a drag through only when nothing moved.
    window.setTimeout(() => (drag.current = null), 0);
  };
  const clicked = (fn: () => void) => () => {
    if (!drag.current?.moved) fn();
  };

  const toggle = (parent: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(parent)) n.delete(parent);
      else n.add(parent);
      return n;
    });


  return (
    <div className="pg">
      <div
        ref={box}
        className={`pg-canvas${drag.current?.moved ? " dragging" : ""}`}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <svg width="100%" height="100%" role="img" aria-label="Process tree">
          <g
            transform={`translate(${view.x},${view.y}) scale(${view.k})`}
            style={{ transition: anim ? "transform 0.3s ease" : "none" }}
          >
            {edges.map(([a, b]) => {
              const p = pos.get(a);
              const q = pos.get(b);
              if (!p || !q) return null;
              const mx = (p.x + q.x) / 2;
              return (
                <path
                  key={a + ">" + b}
                  d={`M${p.x + R} ${p.y} C${mx} ${p.y} ${mx} ${q.y} ${q.x - R} ${q.y}`}
                  className={hot.has(a) && hot.has(b) ? "wb-edge hot" : "wb-edge"}
                />
              );
            })}
            {g.map((n) => (
              <GraphNode
                key={n.id}
                n={n}
                alerts={n.node ? byProcess.get(n.id) ?? [] : []}
                focus={n.id === st.focus}
                selected={n.id === selected}
                onClick={clicked(() => (n.kind === "more" ? toggle(n.parent!) : n.node && onSelect(n.id)))}
              />
            ))}
          </g>
        </svg>
      </div>

      <div className="pg-tools">
        <button title="Zoom in" onClick={() => zoomBy(1.25)}>+</button>
        <button title="Zoom out" onClick={() => zoomBy(0.8)}>−</button>
        <button title="Fit to screen" onClick={fit}>Fit</button>
        <button title="Center on the alert" onClick={() => center(st.focus)}>Alert</button>
        {expanded.size > 0 && (
          <button title="Fold the branches you opened" onClick={() => setExpanded(new Set())}>Collapse all</button>
        )}
      </div>
      <div className="pg-hint muted">Scroll to zoom · drag to move · click a process</div>
      {st.truncated && <div className="pg-note muted">Large tree: showing the first part.</div>}

      {sel && (
        <Drawer
          n={sel}
          alerts={byProcess.get(sel.guid) ?? []}
          hiddenKids={hidden.get(sel.guid) ?? 0}
          expanded={expanded.has(sel.guid)}
          onToggle={() => toggle(sel.guid)}
          onClose={() => onSelect("")}
          onCenter={() => center(sel.guid)}
          onShowActivity={onShowActivity}
        />
      )}
    </div>
  );
}

function GraphNode({ n, alerts, focus, selected, onClick }: {
  n: GNode; alerts: Alert[]; focus: boolean; selected: boolean; onClick: () => void;
}) {
  const worst = alerts.reduce<Alert | undefined>((w, a) => (!w || sevRank[a.severity] > sevRank[w.severity] ? a : w), undefined);
  const counts = { file: 0, network: 0 };
  for (const [t, c] of Object.entries(n.node?.counts ?? {})) {
    const cat = categoryOf(t);
    if (t !== "process_exit" && (cat === "file" || cat === "network")) counts[cat] += c;
  }
  const clickable = n.kind === "more" || (!!n.node && n.kind !== "session");
  const cls = [
    "wb-node",
    `wb-${n.kind}`,
    worst ? `alert sev-ring-${worst.severity}` : "",
    selected ? "selected" : "",
    focus ? "focus" : "",
    clickable ? "clickable" : "",
  ].join(" ");
  const activity = [counts.file ? `${counts.file} file` : "", counts.network ? `${counts.network} net` : ""].filter(Boolean).join(" · ");
  return (
    <g transform={`translate(${n.x},${n.y})`} className={cls} onClick={clickable ? onClick : undefined}>
      <title>{n.node ? `${n.node.args || n.node.exe}\npid ${n.node.pid} · ${n.node.user}` : n.label}</title>
      {n.kind === "more" ? (
        <>
          <rect x={-R - 6} y={-14} width={2 * R + 12} height={28} rx={14} className="wb-disc" />
          <text y={4} textAnchor="middle" className="wb-label">{n.label}</text>
        </>
      ) : (
        <>
          {focus && <circle r={R + 7} className="wb-halo" />}
          <circle r={R} className="wb-disc" />
          <Icon kind={n.kind} />
          {worst && <circle cx={R * 0.72} cy={-R * 0.72} r={6.5} className={`wb-badge sev-fill-${worst.severity}`} />}
          <text y={R + 16} textAnchor="middle" className="wb-label">{clip(n.label, 22)}</text>
          {n.sub && <text y={R + 30} textAnchor="middle" className="wb-sub">{clip(n.sub, 28)}</text>}
          {activity && <text y={R + (n.sub ? 44 : 30)} textAnchor="middle" className="wb-sub wb-counts">{activity}</text>}
        </>
      )}
    </g>
  );
}

function Drawer({ n, alerts, hiddenKids, expanded, onToggle, onClose, onCenter, onShowActivity }: {
  n: StoryNode; alerts: Alert[]; hiddenKids: number; expanded: boolean;
  onToggle: () => void; onClose: () => void; onCenter: () => void; onShowActivity: () => void;
}) {
  const counts = Object.entries(n.counts).filter(([t]) => t !== "process_exit");
  return (
    <aside className="pg-drawer">
      <div className="card-head">
        <h3 className="mono">{base(n.exe)}</h3>
        <button className="link" onClick={onClose} aria-label="Close">✕</button>
      </div>
      {alerts.map((a) => (
        <div key={a.id} className="story-alert">
          <SeverityBadge severity={a.severity} /> <Link to={`/alerts?id=${a.id}`}>{a.rule_name}</Link>
        </div>
      ))}
      <dl className="pg-facts">
        <dt>Command line</dt>
        <dd className="mono">{n.args || n.exe || "unknown"}</dd>
        <dt>Executable</dt>
        <dd className="mono">{n.exe || "unknown"}</dd>
        {n.images && n.images.length > 0 && (
          <>
            <dt>Earlier images</dt>
            <dd className="mono">{n.images.join(" → ")}</dd>
          </>
        )}
        <dt>PID / user</dt>
        <dd>{n.pid || "?"} · {n.user || "?"}</dd>
        {n.known && (
          <>
            <dt>Started</dt>
            <dd>{new Date(n.started).toLocaleString()}</dd>
          </>
        )}
        {n.exited && (
          <>
            <dt>Exit code</dt>
            <dd>{n.exit_code}</dd>
          </>
        )}
        {n.sha256 && (
          <>
            <dt>SHA-256</dt>
            <dd className="mono">{n.sha256}</dd>
          </>
        )}
        {counts.length > 0 && (
          <>
            <dt>Activity</dt>
            <dd>{counts.map(([t, c]) => `${c} ${t.replace("_", " ")}`).join(", ")}</dd>
          </>
        )}
        <dt>Process GUID</dt>
        <dd className="mono">{n.guid}</dd>
      </dl>
      <div className="pg-actions">
        <button onClick={onCenter}>Center</button>
        {(hiddenKids > 0 || expanded) && (
          <button onClick={onToggle}>{expanded ? "Fold children" : `Show ${hiddenKids} more children`}</button>
        )}
        <button onClick={onShowActivity}>Activity ↓</button>
      </div>
    </aside>
  );
}

function Icon({ kind }: { kind: Kind }) {
  const p = { fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (kind) {
    case "user":
      return (
        <g {...p}>
          <circle cx={0} cy={-5} r={5} />
          <path d="M-9 10c1-6 5-8 9-8s8 2 9 8" />
        </g>
      );
    case "host":
      return (
        <g {...p}>
          <rect x={-9} y={-10} width={18} height={8} rx={1.5} />
          <rect x={-9} y={2} width={18} height={8} rx={1.5} />
          <path d="M-5 -6h4M-5 6h4" />
        </g>
      );
    case "session":
      return (
        <g {...p}>
          <circle r={4} />
          <path d="M0 -10v3M0 7v3M-10 0h3M7 0h3M-7 -7l2 2M5 5l2 2M-7 7l2 -2M5 -5l2 -2" />
        </g>
      );
    case "shell":
      return (
        <g {...p}>
          <rect x={-10} y={-8} width={20} height={16} rx={2} />
          <path d="M-6 -3l4 3-4 3M1 4h5" />
        </g>
      );
    default:
      return (
        <g {...p}>
          <rect x={-8} y={-8} width={16} height={16} rx={3} />
          <path d="M-4 -2h8M-4 2h5" />
        </g>
      );
  }
}

// layout decides what is shown and places it: a tidy tree, left to right.
function layout(st: Storyline, host: string, ip: string, byProcess: Map<string, Alert[]>, expanded: Set<string>) {
  const byId = new Map(st.nodes.map((n) => [n.guid, n]));
  const kids = new Map<string, StoryNode[]>();
  const TOP = "#tops";
  for (const n of st.nodes) {
    const parent = n.guid !== st.root && byId.has(n.parent_guid) ? n.parent_guid : TOP;
    if (n.guid === st.root && parent === TOP) {
      kids.set(TOP, [n, ...(kids.get(TOP) ?? [])]);
      continue;
    }
    kids.set(parent, [...(kids.get(parent) ?? []), n]);
  }

  // Always shown: the path to the focus, every alerting process and its
  // ancestors, the root, and the focus's own children.
  const keep = new Set<string>([st.root]);
  const up = (g: string | undefined) => {
    for (let cur = g; cur && byId.has(cur) && !keep.has(cur); cur = byId.get(cur)?.parent_guid) keep.add(cur);
  };
  up(st.focus);
  for (const n of st.nodes) if (byProcess.has(n.guid)) up(n.guid);
  const focusKids = kids.get(st.focus) ?? [];
  if (focusKids.length <= OPEN_CHILDREN) for (const c of focusKids) keep.add(c.guid);

  const g: GNode[] = [];
  const edges: [string, string][] = [];
  const hidden = new Map<string, number>();
  const hot = new Set<string>(["#user", "#host", "#session"]);
  for (let cur: string | undefined = st.focus; cur && byId.has(cur) && !hot.has(cur); cur = byId.get(cur)?.parent_guid) hot.add(cur);

  const offset = st.session ? 3 : 2;
  let slot = 0;
  // place lays out the visible children of parent and returns their y slots.
  const placeChildren = (parent: string, depth: number): number[] => {
    const all = kids.get(parent) ?? [];
    const shown = all.filter((c) => keep.has(c.guid) || expanded.has(parent));
    const ys = shown.map((c) => place(c, depth));
    const rest = all.length - shown.length;
    if (rest > 0) {
      hidden.set(parent, rest);
      const id = `#more:${parent}`;
      g.push({ id, kind: "more", label: `+${rest} more`, x: (offset + depth) * COL, y: slot, parent });
      ys.push(slot++);
      if (parent !== TOP) edges.push([parent, id]);
    }
    return ys;
  };
  const place = (n: StoryNode, depth: number): number => {
    const ys = placeChildren(n.guid, depth + 1);
    for (const c of kids.get(n.guid) ?? []) if (keep.has(c.guid) || expanded.has(n.guid)) edges.push([n.guid, c.guid]);
    const y = ys.length ? (ys[0] + ys[ys.length - 1]) / 2 : slot++;
    const name = base(n.exe);
    g.push({
      id: n.guid, kind: shells.has(name) ? "shell" : "process", label: name,
      sub: n.args && n.args !== n.exe && n.args !== name ? n.args : "", x: (offset + depth) * COL, y, node: n,
    });
    return y;
  };
  const topYs = placeChildren(TOP, 0);
  const mid = topYs.length ? (topYs[0] + topYs[topYs.length - 1]) / 2 : 0;

  const rootNode = byId.get(st.root) ?? st.nodes[0];
  g.push({ id: "#user", kind: "user", label: rootNode?.user || "unknown user", x: 0, y: mid });
  g.push({ id: "#host", kind: "host", label: host, sub: ip, x: COL, y: mid });
  edges.push(["#user", "#host"]);
  const from = st.session ? "#session" : "#host";
  if (st.session) {
    g.push({ id: "#session", kind: "session", label: base(st.session.exe), x: 2 * COL, y: mid, node: st.session });
    edges.push(["#host", "#session"]);
  }
  for (const n of g) if (n.x === offset * COL && n.id !== "#session") edges.push([from, n.id]);

  for (const n of g) {
    n.x += 60;
    n.y = 60 + n.y * ROW;
  }
  const width = Math.max(...g.map((n) => n.x)) + 120;
  const height = Math.max(...g.map((n) => n.y)) + 80;
  return { g, edges, width, height, hidden, hot };
}
