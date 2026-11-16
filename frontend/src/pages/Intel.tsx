import { useState, type FormEvent } from "react";
import { api, confirmationRequest } from "../api";
import { useAuth } from "../auth";
import { useAction, useApi } from "../hooks";
import type { EnrichOut } from "../types";
import { Card, Empty, Err, fmt, Loading, Page } from "../ui";

function Lookup() {
  const [indicator, setIndicator] = useState("");
  const [ask, setAsk] = useState<{ warning: string; providers: string[] } | null>(null);
  const [out, setOut] = useState<EnrichOut | null>(null);
  const act = useAction();
  const go = (confirm: boolean) => act.run(() => api.enrich(indicator.trim(), confirm), (r) => { setOut(r); setAsk(null); },
    (e) => { const c = confirmationRequest(e); if (c) setAsk(c); return c !== null; });
  return (
    <Card title="Look up an indicator" id="lk">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); setOut(null); go(false); }}>
        <label>IP address, domain or SHA-256<input value={indicator} onChange={(e) => setIndicator(e.target.value)} required maxLength={300} /></label>
        <button disabled={act.pending}>Look up</button>
      </form>
      <p className="muted">Answers come from the local table first. Anything that would be sent to a third party asks you to confirm first.</p>
      {ask && (
        <div role="alertdialog" aria-label="Confirm sending to third parties" className="notice">
          <p>{ask.warning}</p>
          <button disabled={act.pending} onClick={() => go(true)}>Send to {ask.providers.join(" and ")}</button>{" "}
          <button className="secondary" onClick={() => setAsk(null)}>Cancel</button>
        </div>
      )}
      <Err msg={act.error} />
      {out && (
        <div role="status">
          <p><code>{out.indicator}</code> ({out.kind}): <strong>{out.status}</strong>{out.note && ` — ${out.note}`}</p>
          <ul>{out.sources.map((s) => <li key={s.source}>{s.source}: {s.status}{s.score !== null && ` · score ${s.score}/100`}{s.summary && ` · ${s.summary}`}{s.cached && " · from cache"}</li>)}</ul>
        </div>
      )}
    </Card>
  );
}

function AddIoc({ onDone }: { onDone: () => void }) {
  const [v, setV] = useState({ indicator: "", score: 80, summary: "" });
  const act = useAction();
  return (
    <Card title="Add to the local IOC table" id="add">
      <form onSubmit={(e) => { e.preventDefault(); act.run(() => api.addIoc(v.indicator.trim(), v.score, v.summary.trim()), () => { setV({ indicator: "", score: 80, summary: "" }); onDone(); }); }}>
        <label>Indicator<input value={v.indicator} onChange={(e) => setV({ ...v, indicator: e.target.value })} required /></label>
        <label>Score (0 clean to 100 malicious)<input type="number" min={0} max={100} value={v.score} onChange={(e) => setV({ ...v, score: Number(e.target.value) })} /></label>
        <label>Why<input value={v.summary} onChange={(e) => setV({ ...v, summary: e.target.value })} required maxLength={500} /></label>
        <button disabled={act.pending}>Add</button>
      </form>
      <Err msg={act.error} />
    </Card>
  );
}

export default function Intel() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi(() => api.iocs(200));
  const del = useAction();
  return (
    <Page title="Threat intelligence">
      {can("enrich") && <Lookup />}
      {can("manage_iocs") && <AddIoc onDone={reload} />}
      <Card title="Stored verdicts" id="st">
        <Err msg={error ?? del.error} />
        {loading && !data ? <Loading /> : data?.length === 0 ? <Empty>No verdicts stored yet.</Empty> : (
          <div className="scroll"><table>
            <caption className="sr-only">Stored indicator verdicts</caption>
            <thead><tr><th scope="col">Indicator</th><th scope="col">Kind</th><th scope="col">Score</th><th scope="col">Source</th><th scope="col">Summary</th><th scope="col">Checked</th><th scope="col">Expires</th>{can("manage_iocs") && <th scope="col">Remove</th>}</tr></thead>
            <tbody>{data?.map((i) => (
              <tr key={i.id}><td><code>{i.value}</code></td><td>{i.kind}</td><td>{i.score}</td><td>{i.source}</td><td>{i.summary}</td><td>{fmt(i.checked_at)}</td><td>{i.expires_at ? fmt(i.expires_at) : "never"}</td>
                {can("manage_iocs") && <td><button className="secondary" disabled={del.pending} aria-label={`Remove ${i.value} from ${i.source}`} onClick={() => del.run(() => api.deleteIoc(i.id), reload)}>Remove</button></td>}</tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
    </Page>
  );
}
