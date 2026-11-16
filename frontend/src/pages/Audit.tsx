import { useState } from "react";
import { api } from "../api";
import { useApi } from "../hooks";
import { Empty, Err, fmt, Loading, Page } from "../ui";

export default function Audit() {
  const [f, setF] = useState({ action: "", actor: "", outcome: "" });
  const { data, error, loading } = useApi(() => api.audit({ ...f, limit: 200 }), [f.action, f.actor, f.outcome]);
  return (
    <Page title="Audit log">
      <div className="filters">
        <label>Action<input value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })} placeholder="e.g. response.approve" /></label>
        <label>Actor<input value={f.actor} onChange={(e) => setF({ ...f, actor: e.target.value })} placeholder="e.g. user:alice" /></label>
        <label>Outcome<select value={f.outcome} onChange={(e) => setF({ ...f, outcome: e.target.value })}><option value="">all</option><option>ok</option><option>denied</option><option>error</option></select></label>
      </div>
      <Err msg={error} />
      {loading && !data ? <Loading /> : data?.length === 0 ? <Empty>No entries match.</Empty> : (
        <div className="scroll"><table>
          <caption className="sr-only">Audit log, newest first (at most 200)</caption>
          <thead><tr><th scope="col">When</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Outcome</th><th scope="col">Target</th><th scope="col">Detail</th></tr></thead>
          <tbody>{data?.map((a) => (
            <tr key={a.id}><td>{fmt(a.ts)}</td><td>{a.actor}</td><td>{a.action}</td><td>{a.outcome}</td><td>{a.target_type && `${a.target_type} `}<code>{a.target_id}</code></td><td><code>{JSON.stringify(a.detail)}</code></td></tr>
          ))}</tbody>
        </table></div>
      )}
    </Page>
  );
}
