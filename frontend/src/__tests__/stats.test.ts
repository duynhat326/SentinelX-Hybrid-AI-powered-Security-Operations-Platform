import { describe, expect, it } from "vitest";
import { bandOf, bucketAlerts, inRange, riskHistogram, seriesBy, topCounts, trend } from "../stats";
import type { Alert, IncidentSummary } from "../types";

const alert = (iso: string, severity: Alert["severity"] = "high"): Alert => ({
  id: iso, rule_id: "SX-001", title: "t", severity, status: "open", host: "h", mitre: [], event_count: 1, first_event_at: iso, last_event_at: iso, incident_id: null,
});

describe("overview statistics", () => {
  it("buckets alerts by severity inside a window measured back from the newest alert", () => {
    const alerts = [alert("2026-11-15T10:00:00Z", "critical"), alert("2026-11-15T09:59:00Z"), alert("2026-11-14T00:00:00Z")];
    const b = bucketAlerts(alerts, "6h");
    expect(b).toHaveLength(24);
    expect(b.reduce((n, x) => n + x.total, 0)).toBe(2);  // the one from the day before is outside six hours
    expect(b[23].counts.critical).toBe(1);
    expect(bucketAlerts(alerts, "all").reduce((n, x) => n + x.total, 0)).toBe(3);
    expect(inRange(alerts, "6h")).toHaveLength(2);
    expect(bucketAlerts([], "24h")).toEqual([]);
  });

  it("counts, orders and breaks ties alphabetically", () => {
    expect(topCounts(["b", "a", "b", "c", "a"], 2)).toEqual([["a", 2], ["b", 2]]);
  });

  it("puts each risk score in exactly one band, with inclusive edges", () => {
    const inc = (risk_score: number) => ({ risk_score }) as IncidentSummary;
    const h = riskHistogram([inc(0), inc(19), inc(20), inc(79), inc(80), inc(100)]);
    expect(h.map((x) => x.count)).toEqual([2, 1, 0, 1, 2]);
    expect([bandOf(39), bandOf(40), bandOf(59), bandOf(60), bandOf(80)]).toEqual(["low", "medium", "medium", "high", "critical"]);
  });
});

describe("trend and per-key series", () => {
  const a = (iso: string, rule = "SX-001"): Alert => ({ id: iso + rule, rule_id: rule, title: "t", severity: "high", status: "open", host: "h", mitre: [], event_count: 1, first_event_at: iso, last_event_at: iso, incident_id: null });

  it("compares the window with the one just before it, and has none for all time", () => {
    const alerts = [a("2026-11-15T10:00:00Z"), a("2026-11-15T09:00:00Z"), a("2026-11-15T02:00:00Z"), a("2026-11-14T20:00:00Z")];
    expect(trend(alerts, "6h")).toEqual({ now: 2, prev: 1 });  // 04:00-10:00 holds two, 22:00-04:00 holds one
    expect(trend(alerts, "6h", (x) => x.id.startsWith("2026-11-15T10"))).toEqual({ now: 1, prev: 0 });
    expect(trend(alerts, "all")).toBeNull();
  });

  it("builds one series per key, each the same length, counting a key once per alert slice", () => {
    const s = seriesBy([a("2026-11-15T10:00:00Z"), a("2026-11-15T10:00:00Z", "SX-002"), a("2026-11-15T09:00:00Z")], "6h", (x) => [x.rule_id], 6);
    expect(s.get("SX-001")).toHaveLength(6);
    expect(s.get("SX-001")!.reduce((n, v) => n + v, 0)).toBe(2);
    expect(s.get("SX-002")!.reduce((n, v) => n + v, 0)).toBe(1);
  });
});
