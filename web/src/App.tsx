import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Me, api, can } from "./api";
import { MeContext } from "./me";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import Events from "./pages/Events";
import Deploy from "./pages/Deploy";
import Alerts from "./pages/Alerts";
import Storyline from "./pages/Storyline";
import Rules from "./pages/Rules";
import IOCs from "./pages/IOCs";
import PAM from "./pages/PAM";
import Policies, { PolicyEditor } from "./pages/Policies";
import RemoteAccess, { RemoteShell, WatchShell } from "./pages/RemoteAccess";
import SessionDetail from "./pages/SessionDetail";
import Audit from "./pages/Audit";
import Admin from "./pages/Admin";
import AccessPolicies from "./pages/AccessPolicies";
import Profile from "./pages/Profile";
import { usePoll } from "./hooks";
import { icons } from "./icons";

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

type NavItem = { to: string; label: string; end?: boolean; badge?: number; perm?: string };
type NavGroup = { title: string; icon: keyof typeof icons; items: NavItem[] };

function Shell({ me, onSignOut }: { me: Me; onSignOut: () => void }) {
  const user = me.display_name || me.username;
  const pam = usePoll(api.pamSummary, 15000);
  const location = useLocation();

  const groups = ([
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
        { to: "/remote", label: "Remote access", perm: "access.request" },
        { to: "/pam", label: "Privileged access", badge: pam.data?.pending || undefined },
        { to: "/audit", label: "Audit log", perm: "audit.view" },
      ],
    },
    {
      title: "Administration",
      icon: "admin",
      items: [
        { to: "/admin/users", label: "Users & roles", perm: "iam.manage" },
        { to: "/admin/access", label: "Access policies" },
      ],
    },
  ] as NavGroup[])
    .map((g) => ({ ...g, items: g.items.filter((it) => !it.perm || can(me, it.perm)) }))
    .filter((g) => g.items.length > 0);

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
          <NavLink to="/profile" className="rail-label">{user}</NavLink>
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
        <main className="content">
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
        </main>
      </div>
    </div>
  );
}
