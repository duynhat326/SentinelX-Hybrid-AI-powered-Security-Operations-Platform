import { useState } from "react";
import { api } from "../api";
import { useApi } from "../hooks";
import { href, queryOf } from "../router";
import { Empty, Err, fmt, Loading, Page, Risk, Sev } from "../ui";

export default function Incidents() {
  const [status, setStatus] = useState("open");
  const [minRisk, setMinRisk] = useState(() => Math.max(0, Math.min(100, Number(queryOf().get("min_risk")) || 0)));
  const [sev, setSev] = useState(() => queryOf().get("severity") ?? "");
  const { data, error, loading } = useApi(() => api.incidents({ status: status || undefined, min_risk: minRisk, limit: 200 }), [status, minRisk]);
  const shown = (data ?? []).filter((i) => !sev || i.severity === sev);
  return (
    <Page title="Incidents">
      <div className="filters">
        <label>Status<select value={status} onChange={(e) => setStatus(e.target.value)}><option value="open">open</option><option value="closed">closed</option><option value="">all</option></select></label>
        <label>Severity<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">all</option>{["critical", "high", "medium", "low"].map((x) => <option key={x}>{x}</option>)}</select></label>
        <label>Minimum risk<input type="number" min={0} max={100} value={minRisk} onChange={(e) => setMinRisk(Math.max(0, Math.min(100, Number(e.target.value) || 0)))} /></label>
      </div>
      <Err msg={error} />
      {loading && !data ? <Loading /> : shown.length === 0 ? <Empty>No incidents match.</Empty> : (
        <div className="scroll"><table>
          <caption className="sr-only">Incidents ordered by risk</caption>
          <thead><tr><th scope="col">Risk</th><th scope="col">Severity</th><th scope="col">Incident</th><th scope="col">Hosts</th><th scope="col">Alerts</th><th scope="col">MITRE</th><th scope="col">Last seen</th></tr></thead>
          <tbody>{shown.map((i) => (
            <tr key={i.id}><td><Risk n={i.risk_score} /></td><td><Sev s={i.severity} /></td><td><a href={href(`incidents/${i.id}`)}>{i.title}</a></td>
              <td>{i.hosts.join(", ")}</td><td>{i.alert_count}</td><td>{i.mitre.join(", ")}</td><td>{fmt(i.last_seen)}</td></tr>
          ))}</tbody>
        </table></div>
      )}
    </Page>
  );
}
