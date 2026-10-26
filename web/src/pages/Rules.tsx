import { useState } from "react";
import { Rule, api, timeAgo } from "../api";
import { usePoll } from "../hooks";
import { SeverityBadge } from "../components/Response";

const sigmaTemplate = `id: custom-curl-to-ip
title: curl downloading from a bare IP address
description: Example custom rule. Fields, modifiers and conditions follow Sigma.
level: medium
tags: [attack.command_and_control, attack.t1105]
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    exe|endswith: [/curl, /wget]
    cmdline|re: 'https?://\\d+\\.\\d+\\.\\d+\\.\\d+'
  condition: selection
# Optional automatic response: kill_process, quarantine_file, isolate_host
# response: [kill_process]
`;

const yaraTemplate = `rule Custom_Example {
  meta:
    description = "Example custom YARA rule"
    severity = "high"
  strings:
    $a = "malicious-marker" nocase
    $b = { 7F 45 4C 46 }
  condition:
    $b at 0 and $a
}
`;

export default function Rules() {
  const rules = usePoll(api.rules, 0);
  const [kind, setKind] = useState<Rule["kind"]>("sigma");
  const [editing, setEditing] = useState<{ id: string; source: string } | null>(null);
  const [q, setQ] = useState("");
  const [err, setErr] = useState("");

  const list = (rules.data?.rules ?? []).filter(
    (r) => r.kind === kind && (!q || `${r.name} ${r.description} ${r.id}`.toLowerCase().includes(q.toLowerCase())),
  );

  async function toggle(r: Rule) {
    setErr("");
    try {
      await api.setRuleEnabled(r.id, !r.enabled);
      rules.refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }
  async function remove(r: Rule) {
    if (!confirm(`Delete rule "${r.name}"?`)) return;
    await api.deleteRule(r.id);
    rules.refresh();
  }

  return (
    <>
      <header className="page-head">
        <h1>Detection rules</h1>
        <div className="actions">
          <button className="primary" onClick={() => setEditing({ id: "", source: kind === "sigma" ? sigmaTemplate : yaraTemplate })}>
            New {kind === "sigma" ? "Sigma" : "YARA"} rule
          </button>
        </div>
      </header>
      <p className="muted">
        Sigma rules run on the console against every event. YARA rules are sent to agents, which scan new and changed files and
        the programs that start.
      </p>
      <div className="filters">
        <div className="tabs">
          <button className={kind === "sigma" ? "active" : ""} onClick={() => setKind("sigma")}>Sigma (behaviour)</button>
          <button className={kind === "yara" ? "active" : ""} onClick={() => setKind("yara")}>YARA (files)</button>
        </div>
        <input className="grow" placeholder="Filter rules" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {(rules.error || err) && <div className="error">{rules.error || err}</div>}
      {editing && (
        <RuleEditor
          kind={kind}
          initial={editing}
          fields={rules.data?.fields ?? []}
          onDone={() => {
            setEditing(null);
            rules.refresh();
          }}
        />
      )}
      <section className="card">
        {list.length === 0 ? (
          <div className="empty">No rules.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Enabled</th>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Source</th>
                  <th>Updated</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {list.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <input type="checkbox" checked={r.enabled} onChange={() => toggle(r)} aria-label={`Enable ${r.name}`} />
                    </td>
                    <td><SeverityBadge severity={r.severity} /></td>
                    <td>
                      <div>{r.name}</div>
                      <div className="muted small">{r.description}</div>
                    </td>
                    <td>{r.builtin ? "Built-in" : "Custom"}</td>
                    <td className="nowrap">{timeAgo(r.updated_at)}</td>
                    <td className="nowrap">
                      <button className="link" onClick={() => setEditing({ id: r.builtin ? "view:" + r.id : r.id, source: r.source })}>
                        {r.builtin ? "View" : "Edit"}
                      </button>
                      {!r.builtin && (
                        <>
                          {" · "}
                          <button className="link" onClick={() => remove(r)}>Delete</button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function RuleEditor({
  kind,
  initial,
  fields,
  onDone,
}: {
  kind: Rule["kind"];
  initial: { id: string; source: string };
  fields: string[];
  onDone: () => void;
}) {
  const readOnly = initial.id.startsWith("view:");
  const [source, setSource] = useState(initial.source);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    setErr("");
    try {
      await api.saveRule(kind, source, "", initial.id);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card highlight">
      <div className="card-head">
        <h2>{readOnly ? "Built-in rule" : initial.id ? "Edit rule" : "New rule"}</h2>
        <button className="link" onClick={onDone}>Close</button>
      </div>
      {err && <div className="error">{err}</div>}
      <textarea
        className="code-editor"
        value={source}
        onChange={(e) => setSource(e.target.value)}
        rows={Math.min(28, source.split("\n").length + 2)}
        readOnly={readOnly}
        spellCheck={false}
      />
      {kind === "sigma" && (
        <p className="muted small">
          Fields: {fields.join(", ")}. Modifiers: contains, startswith, endswith, re, cidr, all. Categories: process_creation,
          process_termination, file_event, file_change, file_rename, file_delete, network_connection, network_listen, yara.
        </p>
      )}
      {kind === "yara" && (
        <p className="muted small">
          Supported: text, hex and regex strings (nocase, wide, ascii, fullword), conditions with and/or/not, counts, at/in,
          "N of", filesize and uint8/16/32. Modules (import) and for-loops are not supported. Set meta severity to low, medium,
          high or critical.
        </p>
      )}
      {!readOnly && (
        <div className="actions">
          <button className="primary" disabled={busy} onClick={save}>Save and deploy</button>
        </div>
      )}
    </section>
  );
}
