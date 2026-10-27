import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ModuleKey, PreventionPolicy, api, policyModules, timeAgo } from "../api";
import { usePoll } from "../hooks";
import { ModuleForm, moduleOn } from "../components/PolicyModules";

export function ModuleDots({ on }: { on: string[] }) {
  return (
    <span className="module-dots">
      {policyModules.map((m) => (
        <span key={m.key} className={on.includes(m.key) ? "dot on" : "dot"} title={`${m.label}: ${on.includes(m.key) ? "on" : "off"}`} />
      ))}
    </span>
  );
}

export default function Policies() {
  const list = usePoll(api.policies, 15000);
  const nav = useNavigate();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [copy, setCopy] = useState(0);
  const [err, setErr] = useState("");

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      const { id } = await api.createPolicy(name, "", copy);
      nav(`/policies/${id}`);
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Policies</h1>
          <div className="muted">Each endpoint follows one policy. Endpoints without one follow the Default policy.</div>
        </div>
        <button className="primary" onClick={() => setCreating(!creating)}>New policy</button>
      </header>
      {(list.error || err) && <div className="error">{list.error || err}</div>}
      {creating && (
        <form className="card filters" onSubmit={create}>
          <input className="grow" placeholder="Policy name, e.g. Web servers" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          <label>
            Start from
            <select value={copy} onChange={(e) => setCopy(Number(e.target.value))}>
              <option value={0}>Recommended settings</option>
              {list.data?.map((p) => <option key={p.id} value={p.id}>Copy of {p.name}</option>)}
            </select>
          </label>
          <button className="primary" disabled={!name.trim()}>Create</button>
        </form>
      )}
      <section className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Policy</th>
                <th>Modules on</th>
                <th>Endpoints</th>
                <th>Changed</th>
              </tr>
            </thead>
            <tbody>
              {list.data?.map((p) => (
                <tr key={p.id}>
                  <td>
                    <Link to={`/policies/${p.id}`}>{p.name}</Link>
                    {p.is_default && <span className="muted small"> · default</span>}
                    {p.description && <div className="muted small">{p.description}</div>}
                  </td>
                  <td><ModuleDots on={p.modules} /> <span className="muted small">{p.modules.length} of 8</span></td>
                  <td>{p.endpoints}</td>
                  <td>{timeAgo(p.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

type Tab = "overview" | ModuleKey;

export function PolicyEditor() {
  const id = Number(useParams().id);
  const nav = useNavigate();
  const detail = usePoll(() => api.policy(id), 0, [id]);
  const agents = usePoll(api.agents, 0);
  const [tab, setTab] = useState<Tab>("overview");
  const [p, setP] = useState<PreventionPolicy | null>(null);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [dirty, setDirty] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [assign, setAssign] = useState<string[]>([]);

  const d = detail.data;
  useEffect(() => {
    if (!d) return;
    setP(d.policy.policy);
    setName(d.policy.name);
    setDesc(d.policy.description);
    setDirty(false);
  }, [d]);

  if (detail.error) return <div className="error">{detail.error}</div>;
  if (!d || !p) return null;

  const edit = (np: PreventionPolicy) => {
    setP(np);
    setDirty(true);
    setMsg("");
  };

  async function save() {
    setErr("");
    setMsg("");
    const fw = p!.firewall;
    if (fw.enabled && fw.default_deny_inbound &&
      !fw.rules.some((r) => r.direction === "in" && r.action === "allow" && r.ports.split(",").map((x) => x.trim()).includes("22")) &&
      !confirm("Inbound traffic will be denied by default and no rule allows SSH (port 22). Only the console and established connections stay reachable. Save anyway?"))
      return;
    try {
      await api.updatePolicy(id, name, desc, p!);
      setDirty(false);
      setMsg("Saved. Endpoints apply it at their next check-in (within 15 seconds).");
      detail.refresh();
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  async function remove() {
    if (!confirm(`Delete the policy ${d!.policy.name}? Its ${d!.policy.endpoints} endpoints move to the Default policy.`)) return;
    try {
      await api.deletePolicy(id);
      nav("/policies");
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  async function doAssign() {
    setErr("");
    try {
      await api.assignPolicy(id, assign);
      setAssign([]);
      detail.refresh();
      agents.refresh();
    } catch (x) {
      setErr((x as Error).message);
    }
  }

  const others = (agents.data ?? []).filter((a) => !a.revoked && !d.endpoint_list.some((e) => e.id === a.id));

  return (
    <>
      <header className="page-head">
        <div>
          <div className="muted small"><Link to="/policies">Policies</Link> /</div>
          <h1>{d.policy.name}{d.policy.is_default && <span className="muted small"> · default</span>}</h1>
        </div>
        <div className="actions">
          {!d.policy.is_default && <button className="danger" onClick={remove}>Delete</button>}
          <button className="primary" onClick={save} disabled={!dirty}>Save policy</button>
        </div>
      </header>
      {err && <div className="error">{err}</div>}
      {msg && <div className="notice">{msg}</div>}

      <div className="policy-layout">
        <nav className="module-nav card" aria-label="Policy sections">
          <button className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}>
            Overview <span className="muted small">{d.policy.endpoints}</span>
          </button>
          {policyModules.map((m) => (
            <button key={m.key} className={tab === m.key ? "active" : ""} onClick={() => setTab(m.key)}>
              {m.label}
              <span className={moduleOn(p, m.key) ? "pill on" : "pill"}>{moduleOn(p, m.key) ? "On" : "Off"}</span>
            </button>
          ))}
        </nav>

        <section className="card" key={`${id}-${tab}-${d.policy.updated_at}`}>
          {tab === "overview" ? (
            <div className="stack">
              <label className="stack">
                Name
                <input value={name} onChange={(e) => { setName(e.target.value); setDirty(true); }} />
              </label>
              <label className="stack">
                Description
                <input value={desc} placeholder="What this policy is for" onChange={(e) => { setDesc(e.target.value); setDirty(true); }} />
              </label>
              <h3>Modules</h3>
              <div className="module-grid">
                {policyModules.map((m) => (
                  <button key={m.key} type="button" className="tile tile-link" onClick={() => setTab(m.key)}>
                    <div className="tile-label">{m.label}</div>
                    <div className={moduleOn(p, m.key) ? "status status-good" : "muted"}>{moduleOn(p, m.key) ? "● On" : "Off"}</div>
                  </button>
                ))}
              </div>
              <h3>Endpoints on this policy ({d.endpoint_list.length})</h3>
              {d.endpoint_list.length === 0 ? (
                <div className="muted">None yet.</div>
              ) : (
                <div className="filters">
                  {d.endpoint_list.map((e) => (
                    <Link key={e.id} className="button" to={`/endpoints/${e.id}`}>
                      <span className={e.online ? "status status-good" : "muted"}>●</span> {e.hostname}
                    </Link>
                  ))}
                </div>
              )}
              {others.length > 0 && (
                <>
                  <h3>Move endpoints to this policy</h3>
                  <div className="filters">
                    {others.map((a) => (
                      <label key={a.id} className="toggle">
                        <input
                          type="checkbox"
                          checked={assign.includes(a.id)}
                          onChange={(e) => setAssign(e.target.checked ? [...assign, a.id] : assign.filter((x) => x !== a.id))}
                        />
                        {a.hostname} <span className="muted small">({a.policy_name})</span>
                      </label>
                    ))}
                  </div>
                  <div><button onClick={doAssign} disabled={assign.length === 0}>Assign {assign.length || ""} selected</button></div>
                </>
              )}
            </div>
          ) : (
            <>
              <h2>{policyModules.find((m) => m.key === tab)!.label}</h2>
              <ModuleForm m={tab} p={p} set={edit} intel={d.intel} />
            </>
          )}
        </section>
      </div>
      {dirty && <div className="notice">Unsaved changes. Press <b>Save policy</b> to apply them to {d.policy.endpoints} endpoints.</div>}
    </>
  );
}
