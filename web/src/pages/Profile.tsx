import { FormEvent, useState } from "react";
import { api } from "../api";
import { useMe } from "../me";

// Profile is the signed-in user's password and MFA.
export default function Profile() {
  const me = useMe();
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  async function run(f: () => Promise<void>, ok: string) {
    setError("");
    setMsg("");
    try {
      await f();
      setMsg(ok);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function password(e: FormEvent) {
    e.preventDefault();
    run(() => api.changePassword(cur, next), "Password changed.").then(() => { setCur(""); setNext(""); });
  }

  function mfa(e: FormEvent) {
    e.preventDefault();
    if (me?.mfa_enabled) run(() => api.mfaDisable(code), "MFA is off. Reload to refresh.");
    else run(() => api.mfaEnable(code), "MFA is on. You will be asked for a code at sign-in.").then(() => setSetup(null));
    setCode("");
  }

  if (!me) return null;
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{me.display_name || me.username}</h1>
          <p className="muted small">Role {me.role_id} · {me.permissions.includes("*") ? "all permissions" : me.permissions.join(", ")}</p>
        </div>
      </header>
      {error && <div className="error">{error}</div>}
      {msg && <div className="notice">{msg}</div>}
      <section className="card">
        <h2>Multi-factor authentication</h2>
        <p className="muted small">
          {me.mfa_enabled ? "On: sign-in and MFA-protected access ask for a code." : "Off. Access policies can require MFA for shells or sudo."}
        </p>
        {!me.mfa_enabled && !setup && (
          <button className="primary" onClick={() => api.mfaSetup().then(setSetup).catch((e) => setError(e.message))}>Set up an authenticator app</button>
        )}
        {setup && (
          <div className="stack">
            <div>Add this key to Google Authenticator, Microsoft Authenticator, 1Password or similar (manual entry, time-based):</div>
            <code className="mono">{setup.secret}</code>
            <div className="muted small mono">{setup.uri}</div>
          </div>
        )}
        {(setup || me.mfa_enabled) && (
          <form className="filters" onSubmit={mfa}>
            <input className="mono" inputMode="numeric" placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} required />
            <button className={me.mfa_enabled ? "danger" : "primary"}>{me.mfa_enabled ? "Turn MFA off" : "Confirm and turn on"}</button>
          </form>
        )}
      </section>
      <section className="card">
        <h2>Password</h2>
        {me.builtin ? (
          <p className="muted small">This is the built-in administrator; its password is XDR_ADMIN_PASSWORD in deploy/.env.</p>
        ) : (
          <form className="filters" onSubmit={password}>
            <input type="password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" required />
            <input type="password" placeholder="New password (12+ characters)" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required />
            <button className="primary">Change</button>
          </form>
        )}
      </section>
    </>
  );
}
