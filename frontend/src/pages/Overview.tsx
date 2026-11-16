import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Donut, HBars, Kpi, RiskRing, Skeleton, SparkTable, TimeBars, Trend, Widget } from "../charts";
import { useApi, useNow } from "../hooks";
import { TECHNIQUES } from "../mitre";
import { href } from "../router";
import { RANGES, SEVS, bucketAlerts, inRange, riskHistogram, seriesBy, sum, topCounts, trend, type RangeKey } from "../stats";
import { Err, Sev, ago, fmt } from "../ui";

const REFRESH_MS = 30_000;
const RANGE_TEXT: Record<RangeKey, string> = { "6h": "6 hours", "24h": "24 hours", "7d": "7 days", all: "all time" };

/** Security posture, laid out the way Splunk's monitoring templates suggest: context and key numbers on top, the same numbers over time
 * and by category in the middle, the records to act on at the bottom, and global inputs that re-scope the view. */
export default function Overview() {
  const ov = useApi(() => api.overview());
  const inc = useApi(() => api.incidents({ status: "open", limit: 200 }));
  const al = useApi(() => api.alerts(200));
  const runs = useApi(() => api.runs(200));
  const acts = useApi(() => api.actions({ limit: 200 }));
  const [range, setRange] = useState<RangeKey>("all");
  const [sev, setSev] = useState("");
  const now = useNow();
  const reloadAll = () => { ov.reload(); inc.reload(); al.reload(); runs.reload(); acts.reload(); };
  useEffect(() => {
    const t = setInterval(() => { ov.reload(); inc.reload(); al.reload(); runs.reload(); acts.reload(); }, REFRESH_MS);
    return () => clearInterval(t);
  }, [ov.reload, inc.reload, al.reload, runs.reload, acts.reload]);

  const alerts = useMemo(() => (al.data ?? []).filter((a) => !sev || a.severity === sev), [al.data, sev]);
  const open = useMemo(() => (inc.data ?? []).filter((i) => !sev || i.severity === sev), [inc.data, sev]);
  const windowed = useMemo(() => inRange(alerts, range), [alerts, range]);
  const buckets = useMemo(() => bucketAlerts(alerts, range), [alerts, range]);
  const byRule = useMemo(() => seriesBy(alerts, range, (a) => [a.rule_id]), [alerts, range]);
  const byHost = useMemo(() => seriesBy(alerts, range, (a) => [a.host]), [alerts, range]);
  const byTech = useMemo(() => seriesBy(alerts, range, (a) => [...new Set(a.mitre)]), [alerts, range]);
  const o = ov.data;
  const updated = Math.max(0, ...[ov.at, inc.at, al.at].map((x) => x ?? 0));
  const avgRisk = open.length ? Math.round(open.reduce((n, i) => n + i.risk_score, 0) / open.length) : 0;
  const runList = runs.data ?? [], actList = acts.data ?? [];
  const tAll = trend(alerts, range), tSevere = trend(alerts, range, (a) => a.severity === "critical" || a.severity === "high");
  const label = RANGE_TEXT[range];

  return (
    <section className="dash">
      <div className="dash-head">
        <div>
          <h1>Security Posture</h1>
          <p className="muted">What is driving pressure on the SOC right now, how it is trending, and which incidents to open next. Tiles are exact; charts follow the inputs below.</p>
        </div>
        <div className="dash-actions">
          <span className="live" role="status"><i aria-hidden="true" />{updated ? `Updated ${ago(now - updated)}` : "Connecting…"}</span>
          <button type="button" className="secondary" onClick={reloadAll}>Refresh</button>
        </div>
      </div>

      <div className="inputs" role="group" aria-label="Dashboard inputs">
        <label>Time range<select value={range} onChange={(e) => setRange(e.target.value as RangeKey)}>{RANGES.map((r) => <option key={r.key} value={r.key}>{r.key === "all" ? "All time" : `Last ${RANGE_TEXT[r.key]}`}</option>)}</select></label>
        <label>Severity<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">All</option>{SEVS.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
        <p className="muted">Window ends at the newest alert{o?.last_event_at ? ` · last event ${fmt(o.last_event_at)}` : ""}</p>
      </div>

      <Err msg={ov.error} />
      {!o ? <Skeleton h={130} /> : (
        <ul className="kpis" aria-label="Key numbers">
          <Kpi i={0} label="events ingested" value={o.events_total} hint="all time, exact" />
          <Kpi i={1} label="alerts raised" value={sum(o.alerts_by_severity)} href={href("alerts")} spark={buckets.map((b) => b.total)}
            hint={`${o.alerts_by_severity.critical ?? 0} critical · ${o.alerts_by_severity.high ?? 0} high`} trend={tAll && <Trend {...tAll} label={label} />} />
          <Kpi i={2} label="critical and high alerts in window" value={windowed.filter((a) => a.severity === "critical" || a.severity === "high").length} href={href("alerts?severity=critical")}
            tone="crit" trend={tSevere && <Trend {...tSevere} label={label} />} />
          <Kpi i={3} label="open incidents" value={sum(o.open_incidents_by_severity)} href={href("incidents")} tone={(o.open_incidents_by_severity.critical ?? 0) > 0 ? "crit" : undefined}
            hint={`${o.open_incidents_by_severity.critical ?? 0} critical · ${o.open_incidents_by_severity.high ?? 0} high`} />
          <Kpi i={4} label="average risk of open incidents" value={avgRisk} hint={open.length ? `highest ${Math.max(...open.map((x) => x.risk_score))} of 100` : "no open incidents"} />
          <Kpi i={5} label="actions awaiting approval" value={o.pending_actions} href={href("approvals")} tone={o.pending_actions > 0 ? "warn" : undefined} hint={`${o.active_blocklist_entries} blocklisted addresses`} />
        </ul>
      )}

      <div className="widgets">
        <Widget id="w-time" i={0} wide title="Alerts over time by severity" sub={`${windowed.length} alert${windowed.length === 1 ? "" : "s"} in ${label}`} action={<a href={href("alerts")}>Open alerts</a>}>
          {al.loading && !al.data ? <Skeleton h={190} /> : <TimeBars buckets={buckets} />}
          <ul className="legend-row" aria-hidden="true">{SEVS.map((s) => <li key={s}><span className={`dot sev-${s}`} />{s}</li>)}</ul>
        </Widget>

        <Widget id="w-sev" i={1} title="Open incidents by severity" sub="Click a slice to see its incidents" action={<a href={href("incidents")}>Incident review</a>}>
          {!o ? <Skeleton h={150} /> : <Donut caption="open" total={sum(o.open_incidents_by_severity)}
            parts={SEVS.map((s) => ({ key: s, label: s, value: o.open_incidents_by_severity[s] ?? 0, href: href(`incidents?severity=${s}`) }))} />}
        </Widget>

        <Widget id="w-rule" i={2} title="Top detections" sub="Rules that fire most: candidates for tuning">
          <SparkTable caption="Alerts per rule" cols={["Rule", "Alerts"]} rows={topCounts(windowed.map((a) => a.rule_id), 6).map(([r, n]) => ({
            id: r, label: <><code>{r}</code> {windowed.find((a) => a.rule_id === r)?.title}</>, value: n, spark: byRule.get(r), href: href(`alerts?q=${r}`) }))} />
        </Widget>

        <Widget id="w-host" i={3} title="Top hosts" sub="Where the alerts come from">
          <SparkTable caption="Alerts per host" cols={["Host", "Alerts"]} rows={topCounts(windowed.map((a) => a.host), 6).map(([h, n]) => ({
            id: h, label: h, value: n, spark: byHost.get(h), href: href(`alerts?q=${encodeURIComponent(h)}`) }))} />
        </Widget>

        <Widget id="w-mitre" i={4} title="Top ATT&CK techniques" sub="Assigned by the rules" action={<a href={href("mitre")}>Matrix</a>}>
          <SparkTable caption="Alerts per technique" cols={["Technique", "Alerts"]} rows={topCounts(windowed.flatMap((a) => [...new Set(a.mitre)]), 6).map(([t, n]) => ({
            id: t, label: <><code>{t}</code> {TECHNIQUES[t]?.name.split(":")[0] ?? ""}</>, value: n, spark: byTech.get(t), href: href(`alerts?q=${t}`) }))} />
        </Widget>

        <Widget id="w-top" i={5} wide title="Incidents to review" sub="Open incidents by risk; open one for its evidence timeline" action={<a href={href("incidents")}>All incidents</a>}>
          <Err msg={inc.error} />
          {inc.loading && !inc.data ? <Skeleton h={180} /> : open.length === 0 ? <p className="muted pad">No open incidents.</p> : (
            <div className="table-wrap"><table className="review">
              <caption className="sr-only">Open incidents ordered by risk</caption>
              <thead><tr><th scope="col">Risk</th><th scope="col">Severity</th><th scope="col">Incident</th><th scope="col">Hosts</th><th scope="col" className="num">Alerts</th><th scope="col">Last seen</th></tr></thead>
              <tbody>{open.slice(0, 7).map((i) => (
                <tr key={i.id}><td><RiskRing n={i.risk_score} /></td><td><Sev s={i.severity} /></td>
                  <td><a href={href(`incidents/${i.id}`)}>{i.title}</a><span className="mitre">{i.mitre.slice(0, 4).map((m) => <code key={m}>{m}</code>)}</span></td>
                  <td>{i.hosts.join(", ")}</td><td className="num">{i.alert_count}</td><td>{fmt(i.last_seen)}</td></tr>
              ))}</tbody>
            </table></div>
          )}
        </Widget>

        <Widget id="w-risk" i={6} title="Risk score distribution" sub="Open incidents by band">
          <HBars empty="No open incidents." rows={riskHistogram(open).map((h) => ({ key: `${h.lo}`, label: `${h.lo}–${h.hi}`, value: h.count, cls: `sev-${h.cls}`, href: h.count ? href(`incidents?min_risk=${h.lo}`) : undefined }))} />
        </Widget>

        <Widget id="w-feed" i={7} wide title="Latest alerts" sub="Newest first" action={<a href={href("alerts")}>All alerts</a>}>
          <Err msg={al.error} />
          {al.loading && !al.data ? <Skeleton h={180} /> : alerts.length === 0 ? <p className="muted pad">No alerts yet.</p> : (
            <div className="table-wrap"><table>
              <caption className="sr-only">Latest alerts</caption>
              <thead><tr><th scope="col">Time</th><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Title</th><th scope="col">Host</th></tr></thead>
              <tbody>{alerts.slice(0, 8).map((a) => (
                <tr key={a.id}><td className="nowrap">{fmt(a.last_event_at)}</td><td><Sev s={a.severity} /></td><td><code>{a.rule_id}</code></td>
                  <td>{a.incident_id ? <a href={href(`incidents/${a.incident_id}`)}>{a.title}</a> : a.title}</td><td>{a.host}</td></tr>
              ))}</tbody>
            </table></div>
          )}
        </Widget>

        <Widget id="w-ai" i={8} title="Response and AI" sub="Approval pipeline and advisory runs" action={<a href={href("approvals")}>Approvals</a>}>
          <dl className="mini">
            <div><dt>Awaiting approval</dt><dd>{actList.filter((a) => a.status === "proposed").length}</dd></div>
            <div><dt>Executed or simulated</dt><dd>{actList.filter((a) => a.status === "executed" || a.status === "simulated").length}</dd></div>
            <div><dt>AI runs</dt><dd>{runList.length}</dd></div>
            <div><dt>Tool calls refused</dt><dd>{runList.reduce((n, r) => n + r.rejected_tool_calls.length, 0)}</dd></div>
          </dl>
          <p className="muted small">The AI only explains: claims without evidence are dropped ({runList.reduce((n, r) => n + r.dropped_claims, 0)} so far) and nothing it says changes a score.</p>
        </Widget>
      </div>
      <p className="muted foot">Tiles are exact server counts. Charts and tables use the latest 200 alerts and 200 open incidents, the window is measured back from the newest alert, and the page refreshes every 30 seconds.</p>
    </section>
  );
}
