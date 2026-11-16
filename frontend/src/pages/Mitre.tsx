import { api } from "../api";
import { useApi } from "../hooks";
import { groupByTactic, techniqueUrl } from "../mitre";
import { Card, Empty, Err, Loading, Page } from "../ui";

export default function Mitre() {
  const { data, error, loading } = useApi(() => api.alerts(200));
  const cols = groupByTactic(data ?? []);
  return (
    <Page title="MITRE ATT&CK coverage of alerts">
      <p className="muted">Techniques assigned by the detection rules to current alerts (latest 200), grouped by tactic. A technique that belongs to several tactics appears under each. Only the techniques the SentinelX rules use are named; anything else is shown as unmapped.</p>
      <Err msg={error} />
      {loading && !data ? <Loading /> : cols.length === 0 ? <Empty>No alerts carry a technique yet.</Empty> : (
        <div className="matrix">
          {cols.map((c) => (
            <Card key={c.tactic} title={c.tactic} id={`t-${c.tactic.replace(/\s+/g, "-")}`}>
              <ul className="plain">{c.techniques.map((t) => (
                <li key={t.id}><a href={techniqueUrl(t.id)} target="_blank" rel="noreferrer noopener">{t.id}</a> {t.name}<span className="tag">{t.alerts} alert{t.alerts === 1 ? "" : "s"}</span></li>
              ))}</ul>
            </Card>
          ))}
        </div>
      )}
    </Page>
  );
}
