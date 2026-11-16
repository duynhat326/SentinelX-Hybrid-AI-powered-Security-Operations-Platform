import { api } from "../api";
import { useApi } from "../hooks";
import { href } from "../router";
import { Card, Empty, Err, fmt, Loading, Page, Risk, Sev, SevBars } from "../ui";

export default function Overview() {
  const ov = useApi(() => api.overview());
  const inc = useApi(() => api.incidents({ limit: 5, status: "open" }));
  const al = useApi(() => api.alerts(8));
  return (
    <Page title="Overview">
      <Err msg={ov.error} />
      {ov.loading && !ov.data ? <Loading /> : ov.data && (
        <>
          <ul className="stats">
            <li><strong>{ov.data.events_total}</strong><span>events ingested</span></li>
            <li><strong>{Object.values(ov.data.open_incidents_by_severity).reduce((a, b) => a + b, 0)}</strong><span>open incidents</span></li>
            <li><a href={href("approvals")}><strong>{ov.data.pending_actions}</strong><span>actions awaiting approval</span></a></li>
            <li><strong>{ov.data.active_blocklist_entries}</strong><span>blocklisted addresses</span></li>
            <li><strong className="small">{fmt(ov.data.last_event_at)}</strong><span>last event</span></li>
          </ul>
          <div className="grid2">
            <Card title="Alerts by severity" id="ab"><SevBars counts={ov.data.alerts_by_severity} /></Card>
            <Card title="Open incidents by severity" id="ib"><SevBars counts={ov.data.open_incidents_by_severity} /></Card>
          </div>
        </>
      )}
      <Card title="Highest-risk open incidents" id="top">
        <Err msg={inc.error} />
        {inc.data?.length === 0 && <Empty>No open incidents.</Empty>}
        <ul className="plain">
          {inc.data?.map((i) => (
            <li key={i.id} className="row"><Sev s={i.severity} /><a href={href(`incidents/${i.id}`)}>{i.title}</a><span className="muted">{i.hosts.join(", ")}</span><Risk n={i.risk_score} /></li>
          ))}
        </ul>
      </Card>
      <Card title="Latest alerts" id="latest">
        <Err msg={al.error} />
        {al.data?.length === 0 && <Empty>No alerts yet.</Empty>}
        <ul className="plain">
          {al.data?.map((a) => (
            <li key={a.id} className="row"><Sev s={a.severity} /><span>{a.rule_id}</span><span>{a.title}</span><span className="muted">{a.host} · {fmt(a.last_event_at)}</span></li>
          ))}
        </ul>
      </Card>
    </Page>
  );
}
