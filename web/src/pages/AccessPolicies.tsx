import { FormEvent, useState } from "react";
import { AccessKind, AccessPolicy, AssetGroup, api, can } from "../api";
import { usePoll } from "../hooks";
import { useMe } from "../me";

const blankPolicy: AccessPolicy = {
  id: 0, name: "", description: "", enabled: true, priority: 50, effect: "allow", subject_roles: [], subject_users: [],
  asset_groups: [], access_types: ["shell"], accounts: [], require_approval: true, approvals: 1, require_mfa: false,
  require_ticket: false, max_minutes: 60, hours_from: 0, hours_to: 24, incident_mode: "none",
};

const blankGroup: AssetGroup = { id: 0, name: "", description: "", criticality: "medium", environment: "production", all_assets: false, agent_ids: [] };

const csv = (v: string[]) => v.join(", ");
const list = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

// AccessPolicies is where server access is decided: policies say who may
// open a shell or get sudo on which asset group, and under which conditions.
export default function AccessPolicies() {
  const me = useMe();
  const editable = can(me, "iam.manage");
  const policies = usePoll(api.accessPolicies, 0);
  const groups = usePoll(api.assetGroups, 0);
  const roles = usePoll(api.roles, 0);
  const agents = usePoll(api.agents, 0);
  const [policy, setPolicy] = useState<AccessPolicy | null>(null);
  const [group, setGroup] = useState<AssetGroup | null>(null);
  const [error, setError] = useState("");
  const groupName = (id: number) => groups.data?.find((g) => g.id === id)?.name ?? `#${id}`;

  async function act(f: () => Promise<unknown>, done: () => void) {
    setError("");
    try {
      await f();
      done();
      policies.refresh();
      groups.refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Access policies</h1>
          <p className="muted small">
            Checked top to bottom; the first that matches decides. Nothing matching means no access. The pseudo-role <code>host</code> stands
            for users asking for sudo on the server with <code>xdr-agent elevate</code>.
          </p>
        </div>
        {editable && <button className="primary" onClick={() => setPolicy({ ...blankPolicy })}>New policy</button>}
      </header>
      {error && <div className="error">{error}</div>}
      {policy && (
        <PolicyEditor
          policy={policy}
          groups={groups.data ?? []}
          roles={(roles.data?.roles ?? []).map((r) => r.id).concat("host")}
          onCancel={() => setPolicy(null)}
          onSave={(p) => act(() => api.saveAccessPolicy(p), () => setPolicy(null))}
        />
      )}
      <section className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>Policy</th><th>Who</th><th>Where</th><th>What</th><th>Conditions</th><th /></tr>
            </thead>
            <tbody>
              {(policies.data ?? []).map((p) => (
                <tr key={p.id} className={p.enabled ? "" : "muted"}>
                  <td>{p.priority}</td>
                  <td>
                    {p.effect === "deny" && <span className="status status-critical">deny </span>}
                    {p.name}
                    <div className="muted small">{p.description}</div>
                  </td>
                  <td className="small">{csv([...p.subject_roles.map((r) => `role:${r}`), ...p.subject_users])}</td>
                  <td className="small">{csv(p.asset_groups.map(groupName))}</td>
                  <td className="small">
                    {csv(p.access_types.map((t) => (t === "shell" ? "shell" : "sudo")))}
                    {p.accounts.length > 0 && <div className="muted mono">as {csv(p.accounts)}</div>}
                  </td>
                  <td className="small">
                    {[
                      p.require_approval && `${p.approvals} approval${p.approvals > 1 ? "s" : ""}`,
                      p.require_mfa && "MFA",
                      p.require_ticket && "ticket",
                      `≤ ${p.max_minutes} min`,
                      !(p.hours_from === 0 && p.hours_to === 24) && `${p.hours_from}:00–${p.hours_to}:00 UTC`,
                      p.incident_mode === "deny" ? "blocked during incidents" : p.incident_mode === "require_approval" ? "approval during incidents" : "",
                    ].filter(Boolean).join(" · ")}
                  </td>
                  <td className="nowrap actions">
                    {editable && (
                      <>
                        <button onClick={() => setPolicy(p)}>Edit</button>
                        <button className="danger" onClick={() => confirm(`Delete policy ${p.name}?`) && act(() => api.deleteAccessPolicy(p.id), () => undefined)}>Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <header className="page-head section-title">
        <div>
          <h2>Asset groups</h2>
          <p className="muted small">Servers grouped by what they are; policies grant access per group.</p>
        </div>
        {editable && <button onClick={() => setGroup({ ...blankGroup })}>New group</button>}
      </header>
      {group && (
        <GroupEditor
          group={group}
          agents={(agents.data ?? []).filter((a) => !a.revoked).map((a) => ({ id: a.id, hostname: a.hostname }))}
          onCancel={() => setGroup(null)}
          onSave={(g) => act(() => api.saveAssetGroup(g), () => setGroup(null))}
        />
      )}
      <section className="card">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Group</th><th>Criticality</th><th>Environment</th><th>Servers</th><th /></tr></thead>
            <tbody>
              {(groups.data ?? []).map((g) => (
                <tr key={g.id}>
                  <td>{g.name}<div className="muted small">{g.description}</div></td>
                  <td><span className={`sev sev-${g.criticality}`}>{g.criticality}</span></td>
                  <td>{g.environment}</td>
                  <td className="small">
                    {g.all_assets ? "every endpoint" : csv(g.agent_ids.map((id) => agents.data?.find((a) => a.id === id)?.hostname ?? id))}
                  </td>
                  <td className="nowrap actions">
                    {editable && (
                      <>
                        <button onClick={() => setGroup(g)}>Edit</button>
                        {!g.all_assets && (
                          <button className="danger" onClick={() => confirm(`Delete group ${g.name}?`) && act(() => api.deleteAssetGroup(g.id), () => undefined)}>Delete</button>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function PolicyEditor({ policy, groups, roles, onSave, onCancel }: {
  policy: AccessPolicy; groups: AssetGroup[]; roles: string[]; onSave: (p: AccessPolicy) => void; onCancel: () => void;
}) {
  const [p, setP] = useState(policy);
  const [users, setUsers] = useState(csv(policy.subject_users));
  const [accounts, setAccounts] = useState(csv(policy.accounts));
  const toggle = <T,>(arr: T[], v: T, on: boolean) => (on ? [...arr, v] : arr.filter((x) => x !== v));

  function submit(e: FormEvent) {
    e.preventDefault();
    onSave({ ...p, subject_users: list(users), accounts: list(accounts) });
  }

  return (
    <section className="card">
      <h2>{p.id ? `Edit ${policy.name}` : "New access policy"}</h2>
      <form className="stack" onSubmit={submit}>
        <div className="filters">
          <input placeholder="Name" value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} required />
          <input className="grow" placeholder="Description" value={p.description} onChange={(e) => setP({ ...p, description: e.target.value })} />
          <label>Order <input className="narrow" type="number" value={p.priority} onChange={(e) => setP({ ...p, priority: Number(e.target.value) })} /></label>
          <select value={p.effect} onChange={(e) => setP({ ...p, effect: e.target.value as AccessPolicy["effect"] })}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
          <label className="toggle"><input type="checkbox" checked={p.enabled} onChange={(e) => setP({ ...p, enabled: e.target.checked })} /> Enabled</label>
        </div>
        <div className="filters">
          <span className="muted small">Who:</span>
          {roles.map((r) => (
            <label key={r} className="toggle">
              <input type="checkbox" checked={p.subject_roles.includes(r)} onChange={(e) => setP({ ...p, subject_roles: toggle(p.subject_roles, r, e.target.checked) })} /> {r}
            </label>
          ))}
          <input className="grow" placeholder="and/or usernames, comma separated" value={users} onChange={(e) => setUsers(e.target.value)} />
        </div>
        <div className="filters">
          <span className="muted small">Where:</span>
          {groups.map((g) => (
            <label key={g.id} className="toggle">
              <input type="checkbox" checked={p.asset_groups.includes(g.id)} onChange={(e) => setP({ ...p, asset_groups: toggle(p.asset_groups, g.id, e.target.checked) })} /> {g.name}
            </label>
          ))}
        </div>
        <div className="filters">
          <span className="muted small">What:</span>
          {(["shell", "jit_sudo"] as AccessKind[]).map((t) => (
            <label key={t} className="toggle">
              <input type="checkbox" checked={p.access_types.includes(t)} onChange={(e) => setP({ ...p, access_types: toggle(p.access_types, t, e.target.checked) })} />{" "}
              {t === "shell" ? "Browser shell" : "JIT sudo"}
            </label>
          ))}
          <input className="grow mono" placeholder="local accounts, empty = any" value={accounts} onChange={(e) => setAccounts(e.target.value)} />
        </div>
        {p.effect === "allow" && (
          <div className="filters">
            <span className="muted small">Conditions:</span>
            <label className="toggle"><input type="checkbox" checked={p.require_approval} onChange={(e) => setP({ ...p, require_approval: e.target.checked })} /> Approval</label>
            {p.require_approval && (
              <select value={p.approvals} onChange={(e) => setP({ ...p, approvals: Number(e.target.value) })}>
                {[1, 2, 3].map((n) => <option key={n} value={n}>{n} approver{n > 1 ? "s" : ""}</option>)}
              </select>
            )}
            <label className="toggle"><input type="checkbox" checked={p.require_mfa} onChange={(e) => setP({ ...p, require_mfa: e.target.checked })} /> MFA</label>
            <label className="toggle"><input type="checkbox" checked={p.require_ticket} onChange={(e) => setP({ ...p, require_ticket: e.target.checked })} /> Ticket</label>
            <label>Max <input className="narrow" type="number" min={5} max={480} value={p.max_minutes} onChange={(e) => setP({ ...p, max_minutes: Number(e.target.value) })} /> min</label>
            <label>Hours (UTC) <input className="narrow" type="number" min={0} max={24} value={p.hours_from} onChange={(e) => setP({ ...p, hours_from: Number(e.target.value) })} />
              – <input className="narrow" type="number" min={0} max={24} value={p.hours_to} onChange={(e) => setP({ ...p, hours_to: Number(e.target.value) })} /></label>
            <select value={p.incident_mode} onChange={(e) => setP({ ...p, incident_mode: e.target.value as AccessPolicy["incident_mode"] })} aria-label="During incidents">
              <option value="none">Open high/critical alert: no change</option>
              <option value="require_approval">Open high/critical alert: needs approval</option>
              <option value="deny">Open high/critical alert: blocked</option>
            </select>
          </div>
        )}
        <div className="actions">
          <button className="primary">Save policy</button>
          <button type="button" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </section>
  );
}

function GroupEditor({ group, agents, onSave, onCancel }: {
  group: AssetGroup; agents: { id: string; hostname: string }[]; onSave: (g: AssetGroup) => void; onCancel: () => void;
}) {
  const [g, setG] = useState(group);
  function submit(e: FormEvent) {
    e.preventDefault();
    onSave(g);
  }
  return (
    <section className="card">
      <form className="stack" onSubmit={submit}>
        <div className="filters">
          <input placeholder="Name, e.g. Production Linux" value={g.name} onChange={(e) => setG({ ...g, name: e.target.value })} required />
          <input className="grow" placeholder="Description" value={g.description} onChange={(e) => setG({ ...g, description: e.target.value })} />
          <select value={g.criticality} onChange={(e) => setG({ ...g, criticality: e.target.value as AssetGroup["criticality"] })}>
            {["low", "medium", "high", "critical"].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select value={g.environment} onChange={(e) => setG({ ...g, environment: e.target.value as AssetGroup["environment"] })}>
            {["production", "staging", "development", "other"].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        {!g.all_assets && (
          <div className="filters">
            <span className="muted small">Servers:</span>
            {agents.map((a) => (
              <label key={a.id} className="toggle">
                <input
                  type="checkbox"
                  checked={g.agent_ids.includes(a.id)}
                  onChange={(e) => setG({ ...g, agent_ids: e.target.checked ? [...g.agent_ids, a.id] : g.agent_ids.filter((x) => x !== a.id) })}
                />{" "}
                {a.hostname}
              </label>
            ))}
          </div>
        )}
        <div className="actions">
          <button className="primary">Save group</button>
          <button type="button" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </section>
  );
}
