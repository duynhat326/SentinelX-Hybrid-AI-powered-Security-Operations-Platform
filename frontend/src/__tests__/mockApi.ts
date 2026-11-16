import { vi } from "vitest";
import { setToken } from "../api";

export const ID = "11111111-2222-3333-4444-555555555555";
export interface Call { method: string; path: string; body: unknown; headers: Record<string, string> }
export const status = (code: number, body: unknown) => ({ __status: code, body });
type Handler = unknown | ((body: any, url: URL) => unknown);

/** Replaces fetch with a table keyed "METHOD /path". Unlisted routes answer 404 so a forgotten endpoint fails loudly. */
export function mockApi(routes: Record<string, Handler>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input, "http://localhost");
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path: url.pathname + url.search, body, headers: (init.headers ?? {}) as Record<string, string> });
    const h = routes[`${method} ${url.pathname}`];
    if (h === undefined) return new Response(JSON.stringify({ detail: "no mock" }), { status: 404 });
    const out = typeof h === "function" ? (h as (b: unknown, u: URL) => unknown)(body, url) : h;
    const s = out && typeof out === "object" && "__status" in out ? (out as { __status: number; body: unknown }) : { __status: 200, body: out };
    return s.__status === 204 ? new Response(null, { status: 204 }) : new Response(JSON.stringify(s.body), { status: s.__status });
  }));
  return calls;
}

export const me = (role: string, permissions: string[]) => ({ name: `user:${role}`, role, permissions });
export const PERMS = {
  viewer: ["read"], analyst: ["enrich", "investigate", "propose", "read"],
  approver: ["approve", "enrich", "investigate", "manage_iocs", "propose", "read"],
  admin: ["approve", "enrich", "investigate", "manage_iocs", "manage_users", "propose", "read", "read_audit"],
};

export const overview = { events_total: 42, last_event_at: "2026-11-15T10:00:00Z", alerts_by_severity: { high: 3, critical: 1 }, open_incidents_by_severity: { high: 2 }, pending_actions: 1, active_blocklist_entries: 0 };

export function incident(over: Record<string, unknown> = {}) {
  return {
    id: ID, title: "Repeated failed SSH logins from one source", severity: "high", status: "open", risk_score: 44, first_seen: "2026-11-15T10:00:00Z", last_seen: "2026-11-15T10:05:00Z",
    alert_count: 1, hosts: ["web01"], mitre: ["T1110"],
    risk_breakdown: { score: 44, components: { severity: { value: 75, weight: 0.4, used: true }, correlation: { value: 0, weight: 0.3, used: true }, threat_intel: { value: null, weight: 0.2, used: false }, asset: { value: 50, weight: 0.1, used: true } }, missing: ["threat_intel"], effective_weights: { severity: 0.5, correlation: 0.375, asset: 0.125 } },
    entities: { host: ["web01"], ip: ["203.0.113.50"], user: ["alice"] },
    alerts: [{ id: "a1", rule_id: "SX-001", title: "Repeated failed SSH logins from one source", severity: "high", mitre: ["T1110"], reason: "seed", first_event_at: "2026-11-15T10:00:00Z", last_event_at: "2026-11-15T10:05:00Z", event_count: 5 }],
    timeline: [{ event_id: "e1", timestamp: "2026-11-15T10:00:01Z", source: "linux_auth", host: "web01", category: "authentication", action: "failure", user: "alice", src_ip: "203.0.113.50", dst_ip: null, process_name: null, command_line: null, registry_key: null, alert_ids: ["a1"] }],
    timeline_total: 1, intel: [], ...over,
  };
}

export const action = (over: Record<string, unknown> = {}) => ({
  id: "act-1", incident_id: ID, type: "add_blocklist_entry", params: { ip: "203.0.113.50", reason: "brute force source" }, status: "proposed", source: "human",
  requested_by: "user:analyst", triggered_by: "user:analyst", requested_at: "2026-11-15T10:06:00Z", decided_by: null, decision_reason: null, dry_run: null, ...over,
});

/** The routes every signed-in page needs. */
export function session(role: keyof typeof PERMS, extra: Record<string, Handler> = {}) {
  setToken("tok-123");
  return mockApi({
    "GET /api/v1/auth/me": me(role, PERMS[role]), "GET /api/v1/overview": overview, "GET /api/v1/incidents": [], "GET /api/v1/alerts": [], ...extra,
  });
}
