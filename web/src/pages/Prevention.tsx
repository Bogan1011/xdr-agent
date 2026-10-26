import { api } from "../api";
import { usePoll } from "../hooks";
import PreventionForm from "../components/PreventionForm";

export default function Prevention() {
  const pol = usePoll(api.globalPrevention, 0);
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Prevention</h1>
          <div className="muted">Fleet-wide policy. An endpoint can override it on its own page.</div>
        </div>
      </header>
      {pol.error && <div className="error">{pol.error}</div>}
      {pol.data && (
        <section className="card">
          <PreventionForm
            policy={pol.data.policy}
            blockedHashes={pol.data.blocked_hashes}
            onSave={async (p) => {
              await api.setGlobalPrevention(p);
              pol.refresh();
            }}
          />
        </section>
      )}
    </>
  );
}
