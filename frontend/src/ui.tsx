import type { ReactNode } from "react";

export const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");
export const shortId = (id: string) => id.slice(0, 8);
export const newKey = () => globalThis.crypto?.randomUUID?.() ?? `k-${Date.now()}-${Math.random().toString(36).slice(2)}`;

/** Severity is always written out, never colour alone. */
export const Sev = ({ s }: { s: string }) => <span className={`sev sev-${s}`}>{s}</span>;
export const Status = ({ s }: { s: string }) => <span className={`tag status-${s}`}>{s.replace("_", " ")}</span>;

export const Risk = ({ n }: { n: number }) => (
  <span className="risk" title={`Risk score ${n} of 100`}>
    <span className="risk-bar" aria-hidden="true"><span style={{ width: `${Math.max(0, Math.min(100, n))}%` }} /></span>
    <strong>{n}</strong><span className="sr-only"> of 100</span>
  </span>
);

export const Err = ({ msg }: { msg: string | null | undefined }) => (msg ? <p role="alert" className="error">{msg}</p> : null);
export const Loading = () => <p className="muted" role="status">Loading…</p>;
export const Empty = ({ children }: { children: ReactNode }) => <p className="muted">{children}</p>;

const STEPS = ["Detect", "Investigate", "Understand", "Respond"];
/** Product line and the four stages; every stage is a deterministic step except the advisory AI explanation. */
export const Hero = () => (
  <div className="hero">
    <h1>SentinelX</h1>
    <p>Detect. Investigate. Understand. Respond. An analyst-assistance mini-SOC: rules decide, people approve, the AI only explains.</p>
    <ol className="steps" aria-label="Pipeline">{STEPS.map((s, i) => <li key={s}><b>{i + 1}</b>{s}</li>)}</ol>
  </div>
);

export function Page({ title, children, aside, hero }: { title: string; children: ReactNode; aside?: ReactNode; hero?: ReactNode }) {
  return (
    <section>
      {hero}
      <div className="page-head"><h1>{title}</h1>{aside}</div>
      {children}
    </section>
  );
}

export const Card = ({ title, children, id }: { title: string; children: ReactNode; id?: string }) => (
  <section className="card" aria-labelledby={id}>
    <h2 id={id}>{title}</h2>
    {children}
  </section>
);

/** Horizontal bars with the number written beside each, so the chart is readable without colour. */
export function SevBars({ counts }: { counts: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low"];
  const max = Math.max(1, ...order.map((s) => counts[s] ?? 0));
  return (
    <ul className="bars">
      {order.map((s) => (
        <li key={s}>
          <span className="bar-label">{s}</span>
          <span className="bar-track" aria-hidden="true"><span className={`bar-fill sev-${s}`} style={{ width: `${((counts[s] ?? 0) / max) * 100}%` }} /></span>
          <span className="bar-n">{counts[s] ?? 0}</span>
        </li>
      ))}
    </ul>
  );
}
