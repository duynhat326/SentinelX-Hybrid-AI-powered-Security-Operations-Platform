// Small SVG chart parts: no chart library, no inline script or style attributes (strict CSP), every number also written as text.
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { SEVS, bandOf, type Bucket } from "./stats";

const reduced = () => typeof matchMedia === "undefined" || matchMedia("(prefers-reduced-motion: reduce)").matches;
const css = (vars: Record<string, string | number>) => vars as CSSProperties;

/** Counts up to `n`; the real value is always in the text for screen readers, and motion is skipped when the user asks for none. */
export function Count({ n, ms = 900 }: { n: number; ms?: number }) {
  const [v, setV] = useState(() => (reduced() ? n : 0));
  const prev = useRef(reduced() ? n : 0);
  useEffect(() => {
    if (reduced()) { setV(n); prev.current = n; return; }
    const from = prev.current, t0 = performance.now();
    let raf = 0;
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / ms);
      setV(Math.round(from + (n - from) * (1 - (1 - p) ** 3)));
      if (p < 1) raf = requestAnimationFrame(step); else prev.current = n;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [n, ms]);
  return <><span aria-hidden="true">{v.toLocaleString()}</span><span className="sr-only">{n.toLocaleString()}</span></>;
}

export function Skeleton({ h = 120 }: { h?: number }) {
  return <div className="skel" role="status" aria-label="Loading" style={css({ "--h": `${h}px` })} />;
}

export function Widget({ title, sub, i = 0, wide, action, children, id }: { title: string; sub?: string; i?: number; wide?: boolean; action?: ReactNode; children: ReactNode; id: string }) {
  return (
    <section className={`widget${wide ? " wide" : ""}`} aria-labelledby={id} style={css({ "--i": i })}>
      <header><div><h2 id={id}>{title}</h2>{sub && <p className="muted">{sub}</p>}</div>{action}</header>
      {children}
    </section>
  );
}

export function Kpi({ label, value, hint, href, tone, spark, i = 0 }: { label: string; value: number; hint?: ReactNode; href?: string; tone?: string; spark?: number[]; i?: number }) {
  const body = (
    <>
      <strong><Count n={value} /></strong>
      <span className="kpi-label">{label}</span>
      {hint && <span className="kpi-hint">{hint}</span>}
      {spark && spark.some((v) => v > 0) && <Sparkline values={spark} label={`${label} over time`} />}
    </>
  );
  return <li className={`kpi${tone ? ` tone-${tone}` : ""}`} style={css({ "--i": i })}>{href ? <a href={href}>{body}</a> : <div>{body}</div>}</li>;
}

export function Sparkline({ values, label }: { values: number[]; label: string }) {
  if (values.length < 2) return null;
  const w = 120, h = 30, max = Math.max(1, ...values);
  const d = values.map((v, i) => `${i ? "L" : "M"}${((i / (values.length - 1)) * w).toFixed(1)} ${(h - 2 - (v / max) * (h - 5)).toFixed(1)}`).join(" ");
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label={label}>
      <path className="spark-area" d={`${d} L${w} ${h} L0 ${h} Z`} /><path className="spark-line" d={d} pathLength={1} />
    </svg>
  );
}

const when = (ms: number, span: number) => new Date(ms).toLocaleString(undefined, span > 36 * 3600e3 ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });

/** Stacked columns of alerts per time slice and severity. Each column has a native tooltip that spells out the numbers. */
export function TimeBars({ buckets }: { buckets: Bucket[] }) {
  if (buckets.length === 0) return <p className="muted pad">No alerts in this window.</p>;
  const W = 640, H = 190, L = 30, B = 22, T = 8;
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const bw = (W - L) / buckets.length, span = buckets[buckets.length - 1].end - buckets[0].start;
  const y = (v: number) => T + (H - T - B) * (1 - v / max);
  return (
    <svg className="timebars" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Alerts over time, busiest slice ${max}`}>
      {[0, 0.5, 1].map((f) => <g key={f}><line x1={L} x2={W} y1={y(max * f)} y2={y(max * f)} className="grid" /><text x={L - 6} y={y(max * f) + 4} textAnchor="end">{Math.round(max * f)}</text></g>)}
      {buckets.map((b, k) => {
        let top = 0;
        return (
          <g key={b.start} className="col" style={css({ "--k": k })}>
            <title>{`${when(b.start, span)}: ${b.total} alert${b.total === 1 ? "" : "s"}${SEVS.filter((s) => b.counts[s]).map((s) => `, ${b.counts[s]} ${s}`).join("")}`}</title>
            <rect className="hit" x={L + k * bw} y={T} width={bw} height={H - T - B} />
            {[...SEVS].reverse().map((s) => {
              const h = (b.counts[s] / max) * (H - T - B);
              top += h;
              return h > 0 ? <rect key={s} className={`seg sev-${s}`} x={L + k * bw + 1.5} y={H - B - top} width={Math.max(1, bw - 3)} height={h} rx={2} /> : null;
            })}
          </g>
        );
      })}
      <text x={L} y={H - 5}>{when(buckets[0].start, span)}</text><text x={W} y={H - 5} textAnchor="end">{when(buckets[buckets.length - 1].end, span)}</text>
    </svg>
  );
}

export interface Part { key: string; label: string; value: number; href?: string }

/** Donut: each arc is a link to the records behind it. The total is written in the middle and every value in the legend. */
export function Donut({ parts, total, caption }: { parts: Part[]; total: number; caption: string }) {
  const R = 42, C = 2 * Math.PI * R;
  let off = 0;
  return (
    <div className="donut-wrap">
      <svg className="donut" viewBox="0 0 120 120" role="img" aria-label={`${caption}: ${total}`}>
        <circle cx="60" cy="60" r={R} className="ring-bg" />
        {total > 0 && parts.filter((p) => p.value > 0).map((p) => {
          const len = (p.value / total) * C, o = off;
          off += len;
          const arc = <circle cx="60" cy="60" r={R} className={`arc sev-${p.key}`} strokeDasharray={`${Math.max(0, len - 1.5)} ${C}`} strokeDashoffset={-o} transform="rotate(-90 60 60)"><title>{`${p.label}: ${p.value}`}</title></circle>;
          return p.href ? <a key={p.key} href={p.href}>{arc}</a> : <g key={p.key}>{arc}</g>;
        })}
        <text x="60" y="58" textAnchor="middle" className="donut-n">{total}</text><text x="60" y="74" textAnchor="middle" className="donut-c">{caption}</text>
      </svg>
      <ul className="legend">
        {parts.map((p) => <li key={p.key}><span className={`dot sev-${p.key}`} aria-hidden="true" />{p.href ? <a href={p.href}>{p.label}</a> : p.label}<b>{p.value}</b></li>)}
      </ul>
    </div>
  );
}

export interface Row { key: string; label: ReactNode; value: number; href?: string; cls?: string }

export function HBars({ rows, empty = "Nothing yet." }: { rows: Row[]; empty?: string }) {
  if (rows.length === 0) return <p className="muted pad">{empty}</p>;
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="hbars">
      {rows.map((r, k) => (
        <li key={r.key} style={css({ "--k": k })}>
          <span className="hb-label">{r.href ? <a href={r.href}>{r.label}</a> : r.label}</span>
          <span className="hb-track" aria-hidden="true"><span className={`hb-fill ${r.cls ?? ""}`} style={css({ "--w": `${(r.value / max) * 100}%` })} /></span>
          <b>{r.value}</b>
        </li>
      ))}
    </ul>
  );
}

/** A score ring (0-100) coloured by band; the number is inside it, so colour is never the only signal. */
export function RiskRing({ n }: { n: number }) {
  const R = 16, C = 2 * Math.PI * R, v = Math.max(0, Math.min(100, n));
  return (
    <svg className={`ring band-${bandOf(v)}`} viewBox="0 0 40 40" role="img" aria-label={`Risk ${v} of 100`}>
      <circle cx="20" cy="20" r={R} className="ring-bg" />
      <circle cx="20" cy="20" r={R} className="ring-fg" strokeDasharray={`${(v / 100) * C} ${C}`} transform="rotate(-90 20 20)" />
      <text x="20" y="24" textAnchor="middle">{v}</text>
    </svg>
  );
}

export function Funnel({ steps }: { steps: { key: string; label: string; value: number; href?: string }[] }) {
  const max = Math.max(1, ...steps.map((s) => s.value));
  return (
    <ol className="funnel">
      {steps.map((s, k) => (
        <li key={s.key} style={css({ "--k": k, "--w": `${Math.max(6, (s.value / max) * 100)}%` })}>
          <span className="fn-bar" aria-hidden="true" /><span className="fn-label">{s.href ? <a href={s.href}>{s.label}</a> : s.label}</span><b>{s.value.toLocaleString()}</b>
        </li>
      ))}
    </ol>
  );
}
