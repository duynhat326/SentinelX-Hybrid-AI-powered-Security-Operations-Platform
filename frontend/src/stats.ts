// Pure aggregation behind the overview charts. Everything is computed from the lists the API already returns (capped at 200), so the
// charts are a view of the latest records; the tiles use the server's exact counts.
import type { Alert, IncidentSummary, Severity } from "./types";

export const SEVS: Severity[] = ["critical", "high", "medium", "low"];
export type RangeKey = "6h" | "24h" | "7d" | "all";
export const RANGES: { key: RangeKey; label: string }[] = [{ key: "6h", label: "6h" }, { key: "24h", label: "24h" }, { key: "7d", label: "7d" }, { key: "all", label: "All" }];
const SPAN: Record<Exclude<RangeKey, "all">, number> = { "6h": 6 * 3600e3, "24h": 24 * 3600e3, "7d": 7 * 24 * 3600e3 };

export interface Bucket { start: number; end: number; counts: Record<Severity, number>; total: number }

const t = (a: Alert) => Date.parse(a.last_event_at);

/** The window is measured back from the newest alert, not from the wall clock, so a lab with old data still shows something. */
export function windowOf(alerts: Alert[], range: RangeKey): [number, number] | null {
  const times = alerts.map(t).filter(Number.isFinite);
  if (times.length === 0) return null;
  const end = Math.max(...times) + 1;
  return [range === "all" ? Math.min(...times) : end - SPAN[range], end];
}

export function bucketAlerts(alerts: Alert[], range: RangeKey, n = 24): Bucket[] {
  const win = windowOf(alerts, range);
  if (!win) return [];
  const [start, end] = win;
  const size = Math.max(1000, (end - start) / n);
  const out: Bucket[] = Array.from({ length: n }, (_, i) => ({ start: start + i * size, end: start + (i + 1) * size, counts: { critical: 0, high: 0, medium: 0, low: 0 }, total: 0 }));
  for (const a of alerts) {
    const i = Math.floor((t(a) - start) / size);
    if (i < 0 || i >= n) continue;
    out[i].counts[a.severity] += 1;
    out[i].total += 1;
  }
  return out;
}

export function inRange(alerts: Alert[], range: RangeKey): Alert[] {
  const win = windowOf(alerts, range);
  return win ? alerts.filter((a) => t(a) >= win[0] && t(a) < win[1]) : [];
}

export function topCounts(items: string[], n = 6): [string, number][] {
  const m = new Map<string, number>();
  for (const i of items) m.set(i, (m.get(i) ?? 0) + 1);
  return [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n);
}

export const RISK_BANDS = [{ lo: 0, hi: 19, cls: "low" }, { lo: 20, hi: 39, cls: "low" }, { lo: 40, hi: 59, cls: "medium" }, { lo: 60, hi: 79, cls: "high" }, { lo: 80, hi: 100, cls: "critical" }];
export const bandOf = (risk: number) => (risk >= 80 ? "critical" : risk >= 60 ? "high" : risk >= 40 ? "medium" : "low");

export function riskHistogram(incidents: IncidentSummary[]) {
  return RISK_BANDS.map((b) => ({ ...b, count: incidents.filter((i) => i.risk_score >= b.lo && i.risk_score <= b.hi).length }));
}

export const sum = (r: Record<string, number> | undefined) => Object.values(r ?? {}).reduce((a, b) => a + b, 0);

/** Count in the selected window and in the window just before it, for a Splunk-style trend ("▲ 3 vs previous 24h"). None for "all". */
export function trend(alerts: Alert[], range: RangeKey, keep: (a: Alert) => boolean = () => true): { now: number; prev: number } | null {
  if (range === "all") return null;
  const win = windowOf(alerts, range);
  if (!win) return null;
  const span = win[1] - win[0];
  let now = 0, prev = 0;
  for (const a of alerts) {
    if (!keep(a)) continue;
    const x = t(a);
    if (x >= win[0] && x < win[1]) now += 1;
    else if (x >= win[0] - span && x < win[0]) prev += 1;
  }
  return { now, prev };
}

/** Per-key counts in `n` time slices of the window: the sparkline column of a "top N" table. */
export function seriesBy(alerts: Alert[], range: RangeKey, key: (a: Alert) => string[], n = 12): Map<string, number[]> {
  const out = new Map<string, number[]>();
  const win = windowOf(alerts, range);
  if (!win) return out;
  const size = Math.max(1000, (win[1] - win[0]) / n);
  for (const a of alerts) {
    const i = Math.floor((t(a) - win[0]) / size);
    if (i < 0 || i >= n) continue;
    for (const k of key(a)) {
      const s = out.get(k) ?? Array<number>(n).fill(0);
      s[i] += 1;
      out.set(k, s);
    }
  }
  return out;
}
