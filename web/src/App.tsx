import { Suspense, lazy, memo, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { Agent, Me, api, can } from "./api";
import { MeContext } from "./me";
import Login from "./pages/Login";
import { usePoll } from "./hooks";
import { icons } from "./icons";

// Pages load on first visit so the console starts fast; xterm and the graph
// code only download when a page that needs them is opened.
const Overview = lazy(() => import("./pages/Overview"));
const Endpoints = lazy(() => import("./pages/Endpoints"));
const EndpointDetail = lazy(() => import("./pages/EndpointDetail"));
const Events = lazy(() => import("./pages/Events"));
const Deploy = lazy(() => import("./pages/Deploy"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Storyline = lazy(() => import("./pages/Storyline"));
const Rules = lazy(() => import("./pages/Rules"));
const IOCs = lazy(() => import("./pages/IOCs"));
const PAM = lazy(() => import("./pages/PAM"));
const Policies = lazy(() => import("./pages/Policies"));
const PolicyEditor = lazy(() => import("./pages/Policies").then((m) => ({ default: m.PolicyEditor })));
const RemoteAccess = lazy(() => import("./pages/RemoteAccess"));
const RemoteShell = lazy(() => import("./pages/RemoteAccess").then((m) => ({ default: m.RemoteShell })));
const WatchShell = lazy(() => import("./pages/RemoteAccess").then((m) => ({ default: m.WatchShell })));
const SessionDetail = lazy(() => import("./pages/SessionDetail"));
const Audit = lazy(() => import("./pages/Audit"));
const Admin = lazy(() => import("./pages/Admin"));
const AccessPolicies = lazy(() => import("./pages/AccessPolicies"));
const Profile = lazy(() => import("./pages/Profile"));

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const load = () => api.me().then(setMe).catch(() => setMe(null));

  useEffect(() => {
    load();
    const onUnauthorized = () => setMe(null);
    window.addEventListener("xdr:unauthorized", onUnauthorized);
    return () => window.removeEventListener("xdr:unauthorized", onUnauthorized);
  }, []);

  if (me === undefined) return null;
  if (me === null) return <Login onLogin={load} />;
  return (
    <MeContext.Provider value={me}>
      <Shell me={me} onSignOut={() => setMe(null)} />
    </MeContext.Provider>
  );
}

type IconName = keyof typeof icons;
type NavItem = { to: string; label: string; icon: IconName; end?: boolean; badge?: number; perm?: string; hint?: string };
type NavGroup = { title: string; items: NavItem[] };

const navGroups = (pending: number): NavGroup[] => [
  { title: "Dashboard", items: [{ to: "/", label: "Security overview", icon: "dashboard", end: true, hint: "home stats" }] },
  {
    title: "XDR",
    items: [
      { to: "/alerts", label: "Workbench alerts", icon: "bell", hint: "detections incidents" },
      { to: "/events", label: "Threat hunting", icon: "search", hint: "events telemetry search" },
      { to: "/rules", label: "Detection rules", icon: "rules", hint: "sigma yara" },
      { to: "/iocs", label: "Threat intel", icon: "globe", hint: "ioc feeds hashes" },
    ],
  },
  {
    title: "Endpoints",
    items: [
      { to: "/endpoints", label: "Endpoint inventory", icon: "endpoint", hint: "agents hosts machines" },
      { to: "/deploy", label: "Install & uninstall", icon: "download", hint: "deploy agent ssh" },
      { to: "/policies", label: "Policies", icon: "shield", hint: "prevention modules" },
    ],
  },
  {
    title: "Identity & access",
    items: [
      { to: "/remote", label: "Remote access", icon: "terminal", perm: "access.request", hint: "shell ssh" },
      { to: "/pam", label: "Privileged access", icon: "lock", badge: pending || undefined, hint: "pam elevation sudo" },
      { to: "/audit", label: "Audit log", icon: "scroll", perm: "audit.view", hint: "history" },
    ],
  },
  {
    title: "Administration",
    items: [
      { to: "/admin/users", label: "Users & roles", icon: "users", perm: "iam.manage", hint: "rbac accounts" },
      { to: "/admin/access", label: "Access policies", icon: "sliders", hint: "asset groups" },
    ],
  },
];

const COLLAPSE_KEY = "xdr.sidebar.collapsed";

function readCollapsed() {
  try {
    const v = localStorage.getItem(COLLAPSE_KEY);
    if (v !== null) return v === "1";
  } catch {
    /* storage unavailable */
  }
  return window.innerWidth < 900;
}

function Shell({ me, onSignOut }: { me: Me; onSignOut: () => void }) {
  const user = me.display_name || me.username;
  const pam = usePoll(api.pamSummary, 15000);
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [palette, setPalette] = useState(false);
  const pending = pam.data?.pending ?? 0;

  const groups = useMemo(
    () =>
      navGroups(pending)
        .map((g) => ({ ...g, items: g.items.filter((it) => !it.perm || can(me, it.perm)) }))
        .filter((g) => g.items.length > 0),
    [me, pending],
  );

  const toggle = () =>
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      } catch {
        /* storage unavailable */
      }
      return !c;
    });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement && e.target.closest("input, textarea, select, [contenteditable], .xterm");
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        setPalette(true);
      } else if ((e.ctrlKey || e.metaKey) && e.key === "\\") {
        e.preventDefault();
        toggle();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const isActive = (it: NavItem) =>
    it.end ? location.pathname === it.to : location.pathname === it.to || location.pathname.startsWith(it.to + "/");
  const current = groups.flatMap((g) => g.items.map((it) => ({ g, it }))).find(({ it }) => isActive(it));

  return (
    <div className={"shell" + (collapsed ? " collapsed" : "")}>
      <aside className="side" aria-label="Main navigation">
        <div className="brand">
          <span className="brand-mark" aria-hidden>{icons.logo}</span>
          <span className="brand-text side-label">XDR<span>Console</span></span>
        </div>
        <button className="side-search" onClick={() => setPalette(true)} title="Search or jump to (Ctrl+K)">
          {icons.search}
          <span className="side-label">Jump to…</span>
          <kbd className="side-label">Ctrl K</kbd>
        </button>
        <nav className="side-nav">
          {groups.map((g) => (
            <div key={g.title} className="side-group">
              <div className="side-title side-label">{g.title}</div>
              {g.items.map((it) => (
                <NavLink key={it.to} to={it.to} end={it.end} className="side-link" title={collapsed ? it.label : undefined}>
                  <span className="side-icon" aria-hidden>{icons[it.icon]}</span>
                  <span className="side-label">{it.label}</span>
                  {it.badge ? <span className="nav-count">{it.badge}</span> : null}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="side-foot">
          <NavLink to="/profile" className="side-link" title={collapsed ? user : undefined}>
            <span className="side-icon avatar" aria-hidden>{user.slice(0, 1).toUpperCase()}</span>
            <span className="side-label">{user}</span>
          </NavLink>
          <button className="side-toggle" onClick={toggle} title={(collapsed ? "Expand" : "Collapse") + " sidebar (Ctrl+\\)"}>
            {collapsed ? icons.expand : icons.collapse}
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="crumbs">
            {current ? (
              <>
                <span className="muted">{current.g.title}</span>
                <span className="crumb-sep">/</span>
                <span>{current.it.label}</span>
              </>
            ) : null}
          </div>
          <div className="topbar-right">
            <span className="live"><span className="pulse" aria-hidden /> Live</span>
            <NavLink to="/profile" className="muted">{user} · {me.role_id}</NavLink>
            <button className="ghost" onClick={() => api.logout().finally(onSignOut)}>Sign out</button>
          </div>
        </header>
        <Content />
      </div>
      {palette ? <Palette groups={groups} onClose={() => setPalette(false)} /> : null}
    </div>
  );
}

// Content is memoised so the sidebar's badge poll never re-renders the page.
const Content = memo(function Content() {
  const { pathname } = useLocation();
  return (
    <main className="content">
      <div key={pathname} className="page-enter">
        <Suspense fallback={<div className="page-loading" aria-label="Loading" />}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/endpoints/:id" element={<EndpointDetail />} />
            <Route path="/events" element={<Events />} />
            <Route path="/deploy" element={<Deploy />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/storyline/:agentId/:guid" element={<Storyline />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/iocs" element={<IOCs />} />
            <Route path="/pam" element={<PAM />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/:id" element={<PolicyEditor />} />
            <Route path="/prevention" element={<Navigate to="/policies" replace />} />
            <Route path="/remote" element={<RemoteAccess />} />
            <Route path="/remote/:id" element={<RemoteShell />} />
            <Route path="/remote/watch/:sid" element={<WatchShell />} />
            <Route path="/pam/sessions/:id" element={<SessionDetail />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/admin/users" element={<Admin />} />
            <Route path="/admin/access" element={<AccessPolicies />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </div>
    </main>
  );
});

type Hit = { key: string; label: string; sub: string; icon: IconName; to: string };

// Palette is the Ctrl+K / "/" jump box: every page plus every endpoint by name or IP.
function Palette({ groups, onClose }: { groups: NavGroup[]; onClose: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [agents, setAgents] = useState<Agent[]>([]);
  const listRef = useRef<HTMLUListElement>(null);

  useEffect(() => {
    api.agents().then(setAgents).catch(() => undefined);
  }, []);

  const hits = useMemo(() => {
    const all: (Hit & { text: string })[] = [
      ...groups.flatMap((g) =>
        g.items.map((it) => ({
          key: it.to, label: it.label, sub: g.title, icon: it.icon, to: it.to,
          text: `${it.label} ${g.title} ${it.hint ?? ""}`.toLowerCase(),
        })),
      ),
      ...agents.map((a) => ({
        key: "agent:" + a.id, label: a.hostname, sub: "Endpoint · " + (a.ip_addresses?.[0] ?? a.os), icon: "endpoint" as IconName,
        to: "/endpoints/" + a.id, text: `${a.hostname} ${a.ip_addresses?.join(" ") ?? ""} ${a.os} endpoint`.toLowerCase(),
      })),
    ];
    const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    return all.filter((h) => terms.every((t) => h.text.includes(t))).slice(0, 30);
  }, [groups, agents, q]);

  useEffect(() => setSel(0), [q]);
  useEffect(() => {
    listRef.current?.children[sel]?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const go = (h?: Hit) => {
    if (!h) return;
    onClose();
    navigate(h.to);
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => Math.min(s + 1, hits.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => Math.max(s - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(hits[sel]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-label="Jump to" onMouseDown={(e) => e.stopPropagation()} onKeyDown={onKey}>
        <div className="palette-input">
          {icons.search}
          <input autoFocus placeholder="Jump to a page or endpoint…" value={q} onChange={(e) => setQ(e.target.value)} />
          <kbd>Esc</kbd>
        </div>
        <ul ref={listRef} className="palette-list">
          {hits.map((h, i) => (
            <li
              key={h.key}
              className={i === sel ? "sel" : ""}
              onMouseMove={() => i !== sel && setSel(i)}
              onClick={() => go(h)}
            >
              <span className="side-icon" aria-hidden>{icons[h.icon]}</span>
              <span className="palette-label">{h.label}</span>
              <span className="muted small">{h.sub}</span>
            </li>
          ))}
          {hits.length === 0 ? <li className="empty">No matches</li> : null}
        </ul>
      </div>
    </div>
  );
}
