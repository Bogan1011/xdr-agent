import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api } from "./api";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import Events from "./pages/Events";
import Deploy from "./pages/Deploy";
import Alerts from "./pages/Alerts";
import Rules from "./pages/Rules";
import IOCs from "./pages/IOCs";
import PAM from "./pages/PAM";
import Policies, { PolicyEditor } from "./pages/Policies";
import RemoteAccess, { RemoteShell, WatchShell } from "./pages/RemoteAccess";
import { usePoll } from "./hooks";
import { icons } from "./icons";

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    api.me().then((m) => setUser(m.username)).catch(() => setUser(null));
    const onUnauthorized = () => setUser(null);
    window.addEventListener("xdr:unauthorized", onUnauthorized);
    return () => window.removeEventListener("xdr:unauthorized", onUnauthorized);
  }, []);

  if (user === undefined) return null;
  if (user === null) return <Login onLogin={setUser} />;
  return <Shell user={user} onSignOut={() => setUser(null)} />;
}

type NavItem = { to: string; label: string; end?: boolean; badge?: number };
type NavGroup = { title: string; icon: keyof typeof icons; items: NavItem[] };

function Shell({ user, onSignOut }: { user: string; onSignOut: () => void }) {
  const pam = usePoll(api.pamSummary, 15000);
  const location = useLocation();

  const groups: NavGroup[] = [
    { title: "Dashboard", icon: "dashboard", items: [{ to: "/", label: "Security overview", end: true }] },
    {
      title: "XDR",
      icon: "xdr",
      items: [
        { to: "/alerts", label: "Workbench alerts" },
        { to: "/events", label: "Threat hunting" },
        { to: "/rules", label: "Detection rules" },
        { to: "/iocs", label: "Threat intel" },
      ],
    },
    {
      title: "Endpoints",
      icon: "endpoint",
      items: [
        { to: "/endpoints", label: "Endpoint inventory" },
        { to: "/deploy", label: "Install & uninstall" },
        { to: "/policies", label: "Policies" },
      ],
    },
    {
      title: "Identity & access",
      icon: "key",
      items: [
        { to: "/remote", label: "Remote access" },
        { to: "/pam", label: "Privileged access", badge: pam.data?.pending || undefined },
      ],
    },
  ];

  const isActive = (it: NavItem) =>
    it.end ? location.pathname === it.to : location.pathname === it.to || location.pathname.startsWith(it.to + "/");
  const current = groups.flatMap((g) => g.items.map((it) => ({ g, it }))).find(({ it }) => isActive(it));

  return (
    <div className="shell">
      <aside className="rail" aria-label="Main navigation">
        <div className="brand">
          <span className="brand-mark" aria-hidden>{icons.logo}</span>
          <span className="rail-label brand-text">XDR<span>Console</span></span>
        </div>
        <nav>
          {groups.map((g) => {
            const groupActive = g.items.some(isActive);
            const badge = g.items.reduce((n, it) => n + (it.badge ?? 0), 0);
            return (
              <div key={g.title} className={"rail-group" + (groupActive ? " active" : "")}>
                <div className="rail-head">
                  <span className="rail-icon" aria-hidden>{icons[g.icon]}</span>
                  <span className="rail-label">{g.title}</span>
                  {badge ? <span className="nav-count rail-dot">{badge}</span> : null}
                </div>
                <div className="rail-items">
                  {g.items.map((it) => (
                    <NavLink key={it.to} to={it.to} end={it.end}>
                      {it.label}
                      {it.badge ? <span className="nav-count">{it.badge}</span> : null}
                    </NavLink>
                  ))}
                </div>
              </div>
            );
          })}
        </nav>
        <div className="rail-foot">
          <span className="rail-icon avatar" aria-hidden>{user.slice(0, 1).toUpperCase()}</span>
          <span className="rail-label">{user}</span>
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
            <span className="muted">{user}</span>
            <button className="ghost" onClick={() => api.logout().finally(onSignOut)}>Sign out</button>
          </div>
        </header>
        <main className="content">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/endpoints/:id" element={<EndpointDetail />} />
            <Route path="/events" element={<Events />} />
            <Route path="/deploy" element={<Deploy />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/iocs" element={<IOCs />} />
            <Route path="/pam" element={<PAM />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/policies/:id" element={<PolicyEditor />} />
            <Route path="/prevention" element={<Navigate to="/policies" replace />} />
            <Route path="/remote" element={<RemoteAccess />} />
            <Route path="/remote/:id" element={<RemoteShell />} />
            <Route path="/remote/watch/:sid" element={<WatchShell />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
