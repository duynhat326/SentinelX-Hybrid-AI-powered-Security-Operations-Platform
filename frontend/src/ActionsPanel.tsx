import { useRef, useState, type FormEvent } from "react";
import { api } from "./api";
import { useAuth } from "./auth";
import { useAction } from "./hooks";
import type { IncidentDetail, ResponseAction, Suggestion } from "./types";
import { Err, fmt, newKey, Status } from "./ui";

const LABEL: Record<string, string> = {
  add_blocklist_entry: "Add to blocklist", request_ip_block: "Block address at the firewall (simulation only)",
  request_host_isolation: "Isolate host (simulation only)", generate_report: "Generate report",
};

export function ActionRow({ a, onChange }: { a: ResponseAction; onChange: () => void }) {
  const { can } = useAuth();
  const [real, setReal] = useState(false);
  const [reason, setReason] = useState("");
  const [detail, setDetail] = useState<ResponseAction | null>(null);
  const act = useAction();
  const target = typeof a.params.ip === "string" ? a.params.ip : typeof a.params.host === "string" ? a.params.host : "";
  const done = () => { setDetail(null); onChange(); };
  const result = detail?.result;
  return (
    <li className="action">
      <div className="row"><strong>{LABEL[a.type] ?? a.type}</strong>{target && <code>{target}</code>}<Status s={a.status} />{a.dry_run === true && <span className="tag">dry run</span>}</div>
      <p className="muted">
        Requested by {a.requested_by}{a.triggered_by !== a.requested_by && ` (asked for by ${a.triggered_by})`} · {fmt(a.requested_at)}
        {a.decided_by && ` · decided by ${a.decided_by}`}
      </p>
      {typeof a.params.reason === "string" && <p>Reason: {a.params.reason}</p>}
      {a.decision_reason && <p>Decision: {a.decision_reason}</p>}

      {a.status === "proposed" && can("approve") && (
        <div className="controls">
          <label className="check"><input type="checkbox" checked={real} onChange={(e) => setReal(e.target.checked)} /> Run for real (the server must allow it; firewall and isolation are only ever simulated)</label>
          <button disabled={act.pending} onClick={() => act.run(() => api.approve(a.id, real), done)}>{real ? "Approve and run" : "Approve (dry run)"}</button>
          <label>Reason to reject<input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} /></label>
          <button className="secondary" disabled={act.pending || !reason.trim()} onClick={() => act.run(() => api.reject(a.id, reason.trim()), done)}>Reject</button>
        </div>
      )}
      {a.status === "executed" && a.type === "add_blocklist_entry" && can("approve") && (
        <button className="secondary" disabled={act.pending} onClick={() => act.run(() => api.rollback(a.id), done)}>Roll back (remove from blocklist)</button>
      )}
      {(a.status === "simulated" || a.status === "executed") && !detail && <button className="link" onClick={() => act.run(() => api.action(a.id), setDetail)}>Show what happened</button>}
      {detail && (
        <div>
          {typeof result?.would === "string" && <p>Would: {result.would}</p>}
          {typeof result?.report_markdown === "string" && <pre className="report">{result.report_markdown}</pre>}
          {detail.rollback_guidance && <p className="muted">Rollback: {detail.rollback_guidance}</p>}
        </div>
      )}
      <Err msg={act.error} />
    </li>
  );
}

export function ProposePanel({ incident, onChange }: { incident: IncidentDetail; onChange: () => void }) {
  const { can } = useAuth();
  const [type, setType] = useState("add_blocklist_entry");
  const [target, setTarget] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [reason, setReason] = useState("");
  const [sug, setSug] = useState<Suggestion | null>(null);
  const key = useRef(newKey());
  const act = useAction();
  if (!can("propose")) return null;
  const ips = incident.entities.ip ?? [];
  const hosts = incident.entities.host ?? [];
  function body(): Record<string, unknown> {
    if (type === "generate_report") return { type };
    if (type === "request_host_isolation") return { type, host: target || hosts[0], reason };
    return { type, ip: target || ips[0], reason, ...(type === "request_ip_block" ? { duration_minutes: minutes } : {}) };
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    act.run(() => api.propose(incident.id, body(), key.current), () => { key.current = newKey(); setReason(""); onChange(); });
  }
  return (
    <div className="propose">
      <h3>Propose an action</h3>
      <p className="muted">A different person must approve it. Approving is a dry run unless they choose to run it for real.</p>
      <form onSubmit={submit}>
        <label>Action<select value={type} onChange={(e) => { setType(e.target.value); setTarget(""); }}>{Object.entries(LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        {type !== "generate_report" && (
          <label>{type === "request_host_isolation" ? "Host" : "Address"}
            <select value={target} onChange={(e) => setTarget(e.target.value)}>{(type === "request_host_isolation" ? hosts : ips).map((v) => <option key={v}>{v}</option>)}</select>
          </label>
        )}
        {type === "request_ip_block" && <label>Minutes<input type="number" min={1} max={10080} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} /></label>}
        {type !== "generate_report" && <label>Reason<input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} required /></label>}
        <button disabled={act.pending}>Propose</button>
      </form>
      <div className="row">
        <button className="secondary" disabled={act.pending} onClick={() => act.run(() => api.suggest(incident.id, false), (s) => { setSug(s); onChange(); })}>Suggest (policy)</button>
        <button className="secondary" disabled={act.pending} onClick={() => act.run(() => api.suggest(incident.id, true), (s) => { setSug(s); onChange(); })}>Suggest (AI)</button>
      </div>
      <Err msg={act.error} />
      {sug && (
        <div role="status" className="notice">
          {sug.created.length} proposed, {sug.existing.length} already proposed, {sug.denied.length} refused by policy{sug.dropped > 0 && `, ${sug.dropped} invalid model proposals dropped`}.
          {sug.error && ` Problem: ${sug.error}.`}
          <ul>{sug.denied.map((d, i) => <li key={i}>{d.type} {d.target}: {d.reasons.join("; ")}</li>)}</ul>
        </div>
      )}
    </div>
  );
}
