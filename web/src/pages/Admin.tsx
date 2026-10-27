import { FormEvent, useState } from "react";
import { ConsoleUser, Role, api, timeAgo } from "../api";
import { usePoll } from "../hooks";
import { useMe } from "../me";

// Admin manages console users and roles.
export default function Admin() {
  const users = usePoll(api.users, 30000);
  const roles = usePoll(api.roles, 0);
  const me = useMe();
  const [error, setError] = useState("");
  const roleList = roles.data?.roles ?? [];

  async function act(f: () => Promise<unknown>) {
    setError("");
    try {
      await f();
      users.refresh();
      roles.refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function edit(u: ConsoleUser, change: Partial<ConsoleUser> & { password?: string }) {
    const v = { ...u, ...change };
    act(() => api.updateUser(u.id, { display_name: v.display_name, email: v.email, role_id: v.role_id, disabled: v.disabled, password: change.password }));
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Users & roles</h1>
          <p className="muted small">Who can sign in to the console and what their role lets them do. Server access itself is decided by access policies.</p>
        </div>
      </header>
      {error && <div className="error">{error}</div>}
      <section className="card">
        <h2>Users</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>User</th><th>Role</th><th>MFA</th><th>Last sign-in</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {(users.data ?? []).map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.display_name || u.username} <span className="muted mono small">{u.username}</span>
                    {u.builtin && <div className="muted small">built-in administrator (deploy/.env)</div>}
                    {u.email && <div className="muted small">{u.email}</div>}
                  </td>
                  <td>
                    <select value={u.role_id} disabled={u.builtin || u.id === me?.id} onChange={(e) => edit(u, { role_id: e.target.value })}>
                      {roleList.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                    </select>
                  </td>
                  <td>
                    {u.mfa_enabled ? "On" : <span className="muted">Off</span>}
                    {u.mfa_enabled && u.id !== me?.id && (
                      <button className="ghost small" onClick={() => confirm(`Reset MFA for ${u.username}?`) && act(() => api.resetUserMFA(u.id))}>Reset</button>
                    )}
                  </td>
                  <td className="nowrap">{new Date(u.last_login).getTime() > 0 ? timeAgo(u.last_login) : <span className="muted">never</span>}</td>
                  <td>{u.disabled ? <span className="muted">Disabled</span> : <span className="status status-good">Active</span>}</td>
                  <td className="nowrap actions">
                    {!u.builtin && u.id !== me?.id && (
                      <>
                        <button onClick={() => { const p = prompt(`New password for ${u.username} (12+ characters):`); if (p) edit(u, { password: p }); }}>Set password</button>
                        <button onClick={() => edit(u, { disabled: !u.disabled })}>{u.disabled ? "Enable" : "Disable"}</button>
                        <button className="danger" onClick={() => confirm(`Delete ${u.username}?`) && act(() => api.deleteUser(u.id))}>Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <NewUser roles={roleList} onSave={(u) => act(() => api.createUser(u))} />
      </section>
      <section className="card">
        <h2>Roles</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Role</th><th>Permissions</th><th /></tr></thead>
            <tbody>
              {roleList.map((r) => (
                <tr key={r.id}>
                  <td>{r.name} <span className="muted mono small">{r.id}</span><div className="muted small">{r.description}</div></td>
                  <td className="small">{r.permissions.includes("*") ? "everything" : r.permissions.join(", ")}</td>
                  <td>{!r.builtin && <button className="danger" onClick={() => act(() => api.deleteRole(r.id))}>Delete</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {roles.data && <NewRole permissions={roles.data.permissions} onSave={(r) => act(() => api.saveRole(r, true))} />}
      </section>
    </>
  );
}

function NewUser({ roles, onSave }: { roles: Role[]; onSave: (u: { username: string; display_name: string; email: string; role_id: string; password: string }) => void }) {
  const [u, setU] = useState({ username: "", display_name: "", email: "", role_id: "operator", password: "" });
  function submit(e: FormEvent) {
    e.preventDefault();
    onSave(u);
    setU({ ...u, username: "", display_name: "", email: "", password: "" });
  }
  return (
    <form className="filters" onSubmit={submit}>
      <input placeholder="Username" value={u.username} onChange={(e) => setU({ ...u, username: e.target.value })} required />
      <input placeholder="Full name" value={u.display_name} onChange={(e) => setU({ ...u, display_name: e.target.value })} />
      <input placeholder="Email" value={u.email} onChange={(e) => setU({ ...u, email: e.target.value })} />
      <select value={u.role_id} onChange={(e) => setU({ ...u, role_id: e.target.value })}>
        {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
      </select>
      <input type="password" placeholder="Password (12+)" value={u.password} onChange={(e) => setU({ ...u, password: e.target.value })} autoComplete="new-password" required />
      <button className="primary">Add user</button>
    </form>
  );
}

function NewRole({ permissions, onSave }: { permissions: { id: string; label: string }[]; onSave: (r: Omit<Role, "builtin">) => void }) {
  const [open, setOpen] = useState(false);
  const [r, setR] = useState({ id: "", name: "", description: "", permissions: ["view"] as string[] });
  if (!open) return <button onClick={() => setOpen(true)}>New custom role</button>;
  function submit(e: FormEvent) {
    e.preventDefault();
    onSave(r);
    setOpen(false);
  }
  return (
    <form className="stack" onSubmit={submit}>
      <div className="filters">
        <input className="mono" placeholder="id, e.g. dba" value={r.id} onChange={(e) => setR({ ...r, id: e.target.value })} required />
        <input placeholder="Name" value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} required />
        <input className="grow" placeholder="Description" value={r.description} onChange={(e) => setR({ ...r, description: e.target.value })} />
      </div>
      <div className="response-grid">
        {permissions.map((p) => (
          <label key={p.id} className="toggle">
            <input
              type="checkbox"
              checked={r.permissions.includes(p.id)}
              onChange={(e) => setR({ ...r, permissions: e.target.checked ? [...r.permissions, p.id] : r.permissions.filter((x) => x !== p.id) })}
            />{" "}
            {p.label}
          </label>
        ))}
      </div>
      <div className="actions">
        <button className="primary">Create role</button>
        <button type="button" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </form>
  );
}
