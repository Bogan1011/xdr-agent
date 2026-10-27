import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
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
import Prevention from "./pages/Prevention";
import { usePoll } from "./hooks";

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

function Shell({ user, onSignOut }: { user: string; onSignOut: () => void }) {
  const pam = usePoll(api.pamSummary, 15000);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden>◆</span> XDR Console
        </div>
        <nav>
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/endpoints">Endpoints</NavLink>
          <NavLink to="/events">Event search</NavLink>
          <NavLink to="/rules">Detection rules</NavLink>
          <NavLink to="/iocs">Threat intel</NavLink>
          <NavLink to="/prevention">Prevention</NavLink>
          <NavLink to="/pam">
            Privileged access{pam.data?.pending ? <span className="nav-count">{pam.data.pending}</span> : null}
          </NavLink>
          <NavLink to="/deploy">Deploy agents</NavLink>
        </nav>
        <div className="sidebar-foot">
          <span>{user}</span>
          <button
            className="link"
            onClick={() => api.logout().finally(onSignOut)}
          >
            Sign out
          </button>
        </div>
      </aside>
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
          <Route path="/prevention" element={<Prevention />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
