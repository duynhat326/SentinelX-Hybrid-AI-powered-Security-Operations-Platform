import { api } from "../api";
import { useApi } from "../hooks";
import { href } from "../router";
import { Empty, Err, fmt, Loading, Page, Status, shortId } from "../ui";

export default function AgentRuns() {
  const { data, error, loading } = useApi(() => api.runs(100));
  return (
    <Page title="AI agent runs">
      <p className="muted">Every AI investigation, with the model, prompt version and a hash of the exact context it saw. The assistant only explains; it cannot change a score or run an action.</p>
      <Err msg={error} />
      {loading && !data ? <Loading /> : data?.length === 0 ? <Empty>No runs yet. AI is off unless the server enables it.</Empty> : (
        <div className="scroll"><table>
          <caption className="sr-only">AI agent runs, newest first</caption>
          <thead><tr><th scope="col">When</th><th scope="col">Incident</th><th scope="col">Model</th><th scope="col">Prompt</th><th scope="col">Status</th><th scope="col">Time</th><th scope="col">Dropped claims</th><th scope="col">Refused tool calls</th><th scope="col">Input hash</th></tr></thead>
          <tbody>{data?.map((r) => (
            <tr key={r.id}><td>{fmt(r.created_at)}</td><td><a href={href(`incidents/${r.incident_id}`)}>{shortId(r.incident_id)}</a></td><td>{r.provider}/{r.model}</td><td>{r.prompt_version}</td>
              <td><Status s={r.status} />{r.error && <span className="muted"> {r.error}</span>}</td><td>{r.duration_ms ?? "—"} ms</td><td>{r.dropped_claims}</td><td>{r.rejected_tool_calls.length}</td><td><code>{r.input_sha256?.slice(0, 12) ?? "—"}</code></td></tr>
          ))}</tbody>
        </table></div>
      )}
    </Page>
  );
}
