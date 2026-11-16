import { useState } from "react";
import { api } from "../api";
import { useApi } from "../hooks";
import { href, queryOf } from "../router";
import { Empty, Err, fmt, Loading, Page, Sev } from "../ui";

export default function Alerts() {
  const { data, error, loading } = useApi(() => api.alerts(200));
  const [sev, setSev] = useState(() => queryOf().get("severity") ?? "");
  const [q, setQ] = useState(() => queryOf().get("q") ?? "");
  const rows = (data ?? []).filter((a) => (!sev || a.severity === sev) && (!q || `${a.host} ${a.title} ${a.rule_id} ${a.mitre.join(" ")}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <Page title="Alerts">
      <div className="filters">
        <label>Severity<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">all</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></label>
        <label>Search<input value={q} onChange={(e) => setQ(e.target.value)} placeholder="host, rule, title or technique" /></label>
      </div>
      <Err msg={error} />
      {loading && !data ? <Loading /> : rows.length === 0 ? <Empty>No alerts match.</Empty> : (
        <div className="scroll"><table>
          <caption className="sr-only">Alerts, newest first (at most 200)</caption>
          <thead><tr><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Title</th><th scope="col">Host</th><th scope="col">MITRE</th><th scope="col">Events</th><th scope="col">Last seen</th><th scope="col">Incident</th></tr></thead>
          <tbody>{rows.map((a) => (
            <tr key={a.id}><td><Sev s={a.severity} /></td><td>{a.rule_id}</td><td>{a.title}</td><td>{a.host}</td><td>{a.mitre.join(", ")}</td><td>{a.event_count}</td><td>{fmt(a.last_event_at)}</td>
              <td>{a.incident_id ? <a href={href(`incidents/${a.incident_id}`)}>open</a> : "—"}</td></tr>
          ))}</tbody>
        </table></div>
      )}
    </Page>
  );
}
