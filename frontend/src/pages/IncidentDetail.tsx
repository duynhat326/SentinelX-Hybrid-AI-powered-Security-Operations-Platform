import { useState } from "react";
import { ActionRow, ProposePanel } from "../ActionsPanel";
import { api, confirmationRequest } from "../api";
import { useAuth } from "../auth";
import { useAction, useApi } from "../hooks";
import { href } from "../router";
import type { AgentRun, EnrichOut } from "../types";
import { Card, Empty, Err, fmt, Loading, Page, Risk, Sev, Status, shortId } from "../ui";

function Enrich({ id, onDone }: { id: string; onDone: () => void }) {
  const [ask, setAsk] = useState<{ warning: string; providers: string[] } | null>(null);
  const [out, setOut] = useState<EnrichOut[] | null>(null);
  const act = useAction();
  const go = (confirm: boolean) => act.run(() => api.enrichIncident(id, confirm), (r) => { setOut(r.indicators); setAsk(null); onDone(); },
    (e) => { const c = confirmationRequest(e); if (c) setAsk(c); return c !== null; });
  return (
    <div>
      <button disabled={act.pending} onClick={() => go(false)}>Look up this incident's addresses</button>
      {ask && (
        <div role="alertdialog" aria-label="Confirm sending to third parties" className="notice">
          <p>{ask.warning}</p>
          <button disabled={act.pending} onClick={() => go(true)}>Send to {ask.providers.join(" and ")}</button>{" "}
          <button className="secondary" onClick={() => setAsk(null)}>Cancel</button>
        </div>
      )}
      <Err msg={act.error} />
      {out && <ul>{out.map((o) => <li key={o.indicator}><code>{o.indicator}</code>: {o.status}{o.note && ` (${o.note})`}{o.sources.map((s) => ` · ${s.source}: ${s.score ?? s.status}`).join("")}</li>)}</ul>}
    </div>
  );
}

function Runs({ runs, onChange, id }: { runs: AgentRun[]; onChange: () => void; id: string }) {
  const { can } = useAuth();
  const act = useAction();
  return (
    <div>
      {can("investigate") && <button disabled={act.pending} onClick={() => act.run(() => api.investigate(id), onChange)}>Run AI investigation</button>}
      <Err msg={act.error} />
      {runs.length === 0 && <Empty>No investigations yet. AI is off unless the server enables it.</Empty>}
      {runs.map((r) => (
        <details key={r.id} className="run">
          <summary>{fmt(r.created_at)} · {r.provider}/{r.model} · <Status s={r.status} />{r.output?.confidence && ` · confidence ${r.output.confidence}`}</summary>
          {r.error && <p className="error">{r.error}</p>}
          {[...(r.output?.findings ?? []), ...(r.output?.triage_claims ?? [])].map((c, i) => (
            <p key={i}>{c.text} <span className="muted">[{c.cites.map(shortId).join(", ")}]</span></p>
          ))}
          {r.output?.uncertainties?.map((u, i) => <p key={i} className="muted">Uncertain: {u}</p>)}
          {r.output?.next_steps?.map((n, i) => <p key={i}>Suggested: {n}</p>)}
          <p className="muted">Advisory only. {r.dropped_claims} claim(s) dropped for missing evidence; {r.rejected_tool_calls.length} tool request(s) refused.</p>
        </details>
      ))}
    </div>
  );
}

export default function IncidentDetail({ id }: { id: string }) {
  const { can } = useAuth();
  const inc = useApi(() => api.incident(id), [id]);
  const runs = useApi(() => api.runsFor(id), [id]);
  const acts = useApi(() => api.actions({ incident_id: id }), [id]);
  const d = inc.data;
  return (
    <Page title={d?.title ?? "Incident"} aside={<a href={href("incidents")}>← All incidents</a>}>
      <Err msg={inc.error} />
      {inc.loading && !d && <Loading />}
      {d && (
        <>
          <div className="row"><Sev s={d.severity} /><Status s={d.status} /><Risk n={d.risk_score} /><span className="muted">{fmt(d.first_seen)} → {fmt(d.last_seen)}</span></div>
          <div className="grid2">
            <Card title="How the risk score is made" id="rb">
              <table>
                <caption className="sr-only">Risk score components</caption>
                <thead><tr><th scope="col">Part</th><th scope="col">Points</th><th scope="col">Weight</th></tr></thead>
                <tbody>{Object.entries(d.risk_breakdown.components).map(([k, c]) => (
                  <tr key={k}><th scope="row">{k.replace("_", " ")}</th><td>{c.value ?? "unknown"}</td><td>{c.used ? `${Math.round((d.risk_breakdown.effective_weights[k] ?? 0) * 100)}%` : "not used"}</td></tr>
                ))}</tbody>
              </table>
              <p className="muted">Unknown parts are left out and the rest renormalised. The score is deterministic and no AI output changes it.</p>
            </Card>
            <Card title="Involved" id="ent">
              {Object.entries(d.entities).map(([k, v]) => <p key={k}><strong>{k}</strong>: {v.map((x) => <code key={x}>{x}</code>)}</p>)}
              <p>MITRE: {d.mitre.join(", ") || "none"}</p>
            </Card>
          </div>
          <Card title="Threat intelligence" id="ti">
            {d.intel.length === 0 && <Empty>No stored verdicts for this incident's addresses.</Empty>}
            <ul>{d.intel.map((i) => <li key={i.id}><code>{i.value}</code> scored {i.score}/100 by {i.source}: {i.summary}</li>)}</ul>
            {can("enrich") && <Enrich id={id} onDone={inc.reload} />}
          </Card>
          <Card title="Alerts" id="al">
            <div className="scroll"><table>
              <caption className="sr-only">Alerts in this incident</caption>
              <thead><tr><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Events</th><th scope="col">Grouped because</th></tr></thead>
              <tbody>{d.alerts.map((a) => <tr key={a.id}><td><Sev s={a.severity} /></td><td>{a.rule_id} {a.title}</td><td>{a.event_count}</td><td><code>{a.reason}</code></td></tr>)}</tbody>
            </table></div>
          </Card>
          <Card title={`Timeline (${d.timeline.length} of ${d.timeline_total} events)`} id="tl">
            <ol className="timeline">{d.timeline.map((t) => (
              <li key={t.event_id}>
                <time dateTime={t.timestamp}>{fmt(t.timestamp)}</time> <strong>{t.host}</strong> {t.category}/{t.action}
                {t.user && <> · user <code>{t.user}</code></>}
                {(t.src_ip || t.dst_ip) && <> · {t.src_ip ?? "?"} → {t.dst_ip ?? "?"}</>}
                {(t.process_name || t.registry_key) && <> · <code>{t.process_name ?? t.registry_key}</code></>}
                {t.command_line && <div className="cmd"><code>{t.command_line}</code></div>}
                <span className="muted"> · cited by {t.alert_ids.length} alert(s)</span>
              </li>
            ))}</ol>
          </Card>
          <Card title="AI investigation" id="ai"><Runs runs={runs.data ?? []} onChange={runs.reload} id={id} /></Card>
          <Card title="Response actions" id="ra">
            <Err msg={acts.error} />
            {acts.data?.length === 0 && <Empty>No actions proposed.</Empty>}
            <ul className="plain">{acts.data?.map((a) => <ActionRow key={a.id} a={a} onChange={() => { acts.reload(); inc.reload(); }} />)}</ul>
            <ProposePanel incident={d} onChange={acts.reload} />
          </Card>
        </>
      )}
    </Page>
  );
}
