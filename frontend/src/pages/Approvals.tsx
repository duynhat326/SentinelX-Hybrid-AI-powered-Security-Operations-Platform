import { ActionRow } from "../ActionsPanel";
import { api } from "../api";
import { useApi } from "../hooks";
import { href } from "../router";
import { Card, Empty, Err, Loading, Page, shortId } from "../ui";

export default function Approvals() {
  const { data, error, loading, reload } = useApi(() => api.actions({ limit: 200 }));
  const pending = data?.filter((a) => a.status === "proposed") ?? [];
  const decided = data?.filter((a) => a.status !== "proposed").slice(0, 30) ?? [];
  return (
    <Page title="Approval queue">
      <p className="muted">Nothing here runs until someone other than the person who proposed it (or asked the assistant for it) approves. Approving is a dry run unless you tick "Run for real" and the server allows it.</p>
      <Err msg={error} />
      {loading && !data ? <Loading /> : (
        <>
          <Card title={`Waiting for a decision (${pending.length})`} id="pend">
            {pending.length === 0 && <Empty>Nothing is waiting.</Empty>}
            <ul className="plain">{pending.map((a) => (
              <div key={a.id}><p className="muted">Incident <a href={href(`incidents/${a.incident_id}`)}>{shortId(a.incident_id)}</a></p><ActionRow a={a} onChange={reload} /></div>
            ))}</ul>
          </Card>
          <Card title="Recently decided" id="dec">
            {decided.length === 0 && <Empty>No decisions yet.</Empty>}
            <ul className="plain">{decided.map((a) => <ActionRow key={a.id} a={a} onChange={reload} />)}</ul>
          </Card>
        </>
      )}
    </Page>
  );
}
