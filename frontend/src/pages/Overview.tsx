import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Donut, Funnel, HBars, Kpi, RiskRing, Skeleton, TimeBars, Widget } from "../charts";
import { useApi, useNow } from "../hooks";
import { TECHNIQUES } from "../mitre";
import { href } from "../router";
import { RANGES, SEVS, bucketAlerts, inRange, riskHistogram, sum, topCounts, type RangeKey } from "../stats";
import { Err, Sev, ago, fmt } from "../ui";

const REFRESH_MS = 30_000;

export default function Overview() {
  const ov = useApi(() => api.overview());
  const inc = useApi(() => api.incidents({ status: "open", limit: 200 }));
  const al = useApi(() => api.alerts(200));
  const runs = useApi(() => api.runs(200));
  const acts = useApi(() => api.actions({ limit: 200 }));
  const [range, setRange] = useState<RangeKey>("all");
  const now = useNow();
  useEffect(() => {
    const t = setInterval(() => { ov.reload(); inc.reload(); al.reload(); runs.reload(); acts.reload(); }, REFRESH_MS);
    return () => clearInterval(t);
  }, [ov.reload, inc.reload, al.reload, runs.reload, acts.reload]);

  const alerts = useMemo(() => al.data ?? [], [al.data]);
  const open = useMemo(() => inc.data ?? [], [inc.data]);
  const windowed = useMemo(() => inRange(alerts, range), [alerts, range]);
  const buckets = useMemo(() => bucketAlerts(alerts, range), [alerts, range]);
  const hist = useMemo(() => riskHistogram(open), [open]);
  const o = ov.data;
  const updated = Math.max(0, ...[ov.at, inc.at, al.at].map((x) => x ?? 0));
  const avgRisk = open.length ? Math.round(open.reduce((n, i) => n + i.risk_score, 0) / open.length) : 0;
  const runList = runs.data ?? [], actList = acts.data ?? [];
  const byStatus = topCounts(actList.map((a) => a.status), 6);

  return (
    <section className="dash">
      <div className="dash-head">
        <div>
          <h1>Overview</h1>
          <p className="muted">SOC posture: what is driving pressure, what is trending, where to look next.</p>
        </div>
        <div className="dash-tools">
          <span className="live" role="status"><i aria-hidden="true" />{updated ? `Live · updated ${ago(now - updated)}` : "Connecting…"}{o?.last_event_at ? ` · last event ${fmt(o.last_event_at)}` : ""}</span>
          <div className="seg-control" role="group" aria-label="Time range for the charts">
            {RANGES.map((r) => <button key={r.key} type="button" className="secondary" aria-pressed={range === r.key} onClick={() => setRange(r.key)}>{r.label}</button>)}
          </div>
          <button type="button" className="secondary" onClick={() => { ov.reload(); inc.reload(); al.reload(); runs.reload(); acts.reload(); }}>Refresh</button>
        </div>
      </div>
      <Err msg={ov.error} />
      {!o ? <Skeleton h={110} /> : (
        <ul className="kpis" aria-label="Key numbers">
          <Kpi i={0} label="events ingested" value={o.events_total} />
          <Kpi i={1} label="alerts raised" value={sum(o.alerts_by_severity)} href={href("alerts")} spark={buckets.map((b) => b.total)}
            hint={`${o.alerts_by_severity.critical ?? 0} critical · ${o.alerts_by_severity.high ?? 0} high`} />
          <Kpi i={2} label="open incidents" value={sum(o.open_incidents_by_severity)} href={href("incidents")} tone={(o.open_incidents_by_severity.critical ?? 0) > 0 ? "crit" : undefined}
            hint={`${o.open_incidents_by_severity.critical ?? 0} critical · ${o.open_incidents_by_severity.high ?? 0} high`} />
          <Kpi i={3} label="average risk of open incidents" value={avgRisk} hint={open.length ? `highest ${Math.max(...open.map((x) => x.risk_score))} of 100` : "no open incidents"} />
          <Kpi i={4} label="actions awaiting approval" value={o.pending_actions} href={href("approvals")} tone={o.pending_actions > 0 ? "warn" : undefined} />
          <Kpi i={5} label="blocklisted addresses" value={o.active_blocklist_entries} />
        </ul>
      )}

      <div className="widgets">
        <Widget id="w-time" i={0} wide title="Alerts over time" sub={`${windowed.length} alert${windowed.length === 1 ? "" : "s"} in the selected window, by severity`}>
          {al.loading && !al.data ? <Skeleton h={190} /> : <TimeBars buckets={buckets} />}
          <ul className="legend-row" aria-hidden="true">{SEVS.map((s) => <li key={s}><span className={`dot sev-${s}`} />{s}</li>)}</ul>
        </Widget>

        <Widget id="w-sev" i={1} title="Open incidents by severity" sub="Click a slice to see its incidents" action={<a href={href("incidents")}>All</a>}>
          {!o ? <Skeleton h={150} /> : <Donut caption="open" total={sum(o.open_incidents_by_severity)}
            parts={SEVS.map((s) => ({ key: s, label: s, value: o.open_incidents_by_severity[s] ?? 0, href: href(`incidents?severity=${s}`) }))} />}
        </Widget>

        <Widget id="w-fun" i={2} title="From events to action" sub="How much raw data a person has to look at">
          {!o ? <Skeleton h={150} /> : <Funnel steps={[
            { key: "e", label: "Events ingested", value: o.events_total },
            { key: "a", label: "Alerts raised", value: sum(o.alerts_by_severity), href: href("alerts") },
            { key: "i", label: "Open incidents", value: sum(o.open_incidents_by_severity), href: href("incidents") },
            { key: "r", label: "AI investigations", value: runList.length, href: href("agent-runs") },
            { key: "p", label: "Response actions", value: actList.length, href: href("approvals") },
          ]} />}
        </Widget>

        <Widget id="w-risk" i={3} title="Risk distribution" sub="Open incidents by score band">
          <HBars empty="No open incidents." rows={hist.map((h) => ({ key: `${h.lo}`, label: `${h.lo}–${h.hi}`, value: h.count, cls: `sev-${h.cls}`, href: h.count ? href(`incidents?min_risk=${h.lo}`) : undefined }))} />
        </Widget>

        <Widget id="w-mitre" i={4} title="Top ATT&CK techniques" sub="Alerts in the selected window" action={<a href={href("mitre")}>Matrix</a>}>
          <HBars empty="No techniques in this window." rows={topCounts(windowed.flatMap((a) => [...new Set(a.mitre)]), 6).map(([id, n]) => ({
            key: id, label: <><code>{id}</code> {TECHNIQUES[id]?.name.split(":")[0] ?? ""}</>, value: n, href: href(`alerts?q=${id}`) }))} />
        </Widget>

        <Widget id="w-host" i={5} title="Busiest hosts" sub="Alerts in the selected window">
          <HBars empty="No alerts in this window." rows={topCounts(windowed.map((a) => a.host), 6).map(([h, n]) => ({ key: h, label: h, value: n, href: href(`alerts?q=${encodeURIComponent(h)}`) }))} />
        </Widget>

        <Widget id="w-rule" i={6} title="Noisiest rules" sub="Which detections fire most (candidates for tuning)">
          <HBars empty="No alerts in this window." rows={topCounts(windowed.map((a) => a.rule_id), 6).map(([r, n]) => ({ key: r, label: <><code>{r}</code> {windowed.find((a) => a.rule_id === r)?.title.slice(0, 34)}</>, value: n, href: href(`alerts?q=${r}`) }))} />
        </Widget>

        <Widget id="w-ai" i={7} title="AI and response" sub="Advisory runs and the approval pipeline" action={<a href={href("agent-runs")}>Runs</a>}>
          <dl className="mini">
            <div><dt>AI runs</dt><dd>{runList.length}</dd></div>
            <div><dt>Failed</dt><dd>{runList.filter((r) => r.status !== "ok").length}</dd></div>
            <div><dt>Claims dropped</dt><dd>{runList.reduce((n, r) => n + r.dropped_claims, 0)}</dd></div>
            <div><dt>Tool calls refused</dt><dd>{runList.reduce((n, r) => n + r.rejected_tool_calls.length, 0)}</dd></div>
          </dl>
          <ul className="chips">{byStatus.length === 0 ? <li className="muted">No response actions yet.</li> : byStatus.map(([s, n]) => <li key={s}><a href={href("approvals")}>{s.replace("_", " ")}<b>{n}</b></a></li>)}</ul>
        </Widget>

        <Widget id="w-top" i={8} wide title="Highest-risk open incidents" sub="Click an incident for its evidence timeline" action={<a href={href("incidents")}>All incidents</a>}>
          <Err msg={inc.error} />
          {inc.loading && !inc.data ? <Skeleton h={180} /> : open.length === 0 ? <p className="muted pad">No open incidents.</p> : (
            <ul className="cases">
              {open.slice(0, 6).map((i) => (
                <li key={i.id}>
                  <RiskRing n={i.risk_score} />
                  <div className="case-main"><a href={href(`incidents/${i.id}`)}>{i.title}</a><span className="muted">{i.hosts.join(", ")} · {i.alert_count} alert{i.alert_count === 1 ? "" : "s"} · {fmt(i.last_seen)}</span>
                    <span className="mitre">{i.mitre.slice(0, 5).map((m) => <code key={m}>{m}</code>)}</span></div>
                  <Sev s={i.severity} />
                </li>
              ))}
            </ul>
          )}
        </Widget>

        <Widget id="w-feed" i={9} title="Latest alerts" sub="Newest first" action={<a href={href("alerts")}>All alerts</a>}>
          <Err msg={al.error} />
          {al.loading && !al.data ? <Skeleton h={180} /> : alerts.length === 0 ? <p className="muted pad">No alerts yet.</p> : (
            <ol className="feed">
              {alerts.slice(0, 7).map((a) => (
                <li key={a.id}><Sev s={a.severity} /><div><span>{a.rule_id} · {a.title}</span><span className="muted">{a.host} · {fmt(a.last_event_at)}</span></div></li>
              ))}
            </ol>
          )}
        </Widget>
      </div>
      <p className="muted foot">The tiles are exact counts. The charts use the latest 200 alerts and 200 open incidents, and the time window is measured back from the newest alert. The page refreshes itself every 30 seconds.</p>
    </section>
  );
}
