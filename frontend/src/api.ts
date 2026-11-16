import type { AgentRun, Alert, AuditEntry, EnrichOut, IncidentDetail, IncidentSummary, Ioc, Me, Overview, ResponseAction, Suggestion } from "./types";

export class ApiError extends Error {
  constructor(public status: number, public detail: unknown) {
    super(typeof detail === "string" ? detail : `HTTP ${status}`);
  }
}

// shortcut: the token lives in sessionStorage (gone when the tab closes, readable by scripts on this origin). The nginx CSP and
// React's escaping are the defence; move to an HttpOnly cookie if the backend ever issues one.
const KEY = "sentinelx.token";
let token: string | null = typeof sessionStorage === "undefined" ? null : sessionStorage.getItem(KEY);
let onUnauthorized: () => void = () => {};

export const hasToken = () => token !== null;
export function setToken(t: string | null) {
  token = t;
  if (t) sessionStorage.setItem(KEY, t);
  else sessionStorage.removeItem(KEY);
}
export function setUnauthorizedHandler(fn: () => void) { onUnauthorized = fn; }

async function request<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (res.status === 401 && token) {  // an expired or revoked session: drop it and return to the sign-in page
    setToken(null);
    onUnauthorized();
  }
  if (!res.ok) throw new ApiError(res.status, data && typeof data === "object" && "detail" in data ? (data as { detail: unknown }).detail : data);
  return data as T;
}

const qs = (p: Record<string, string | number | undefined>) => {
  const s = new URLSearchParams(Object.entries(p).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])).toString();
  return s ? `?${s}` : "";
};

export const api = {
  login: (username: string, password: string) => request<{ token: string }>("POST", "/api/v1/auth/login", { username, password }),
  logout: () => request<unknown>("POST", "/api/v1/auth/logout"),
  me: () => request<Me>("GET", "/api/v1/auth/me"),
  overview: () => request<Overview>("GET", "/api/v1/overview"),
  alerts: (limit = 200) => request<Alert[]>("GET", `/api/v1/alerts${qs({ limit })}`),
  incidents: (p: { limit?: number; status?: string; min_risk?: number } = {}) => request<IncidentSummary[]>("GET", `/api/v1/incidents${qs(p)}`),
  incident: (id: string) => request<IncidentDetail>("GET", `/api/v1/incidents/${id}`),
  runsFor: (id: string) => request<AgentRun[]>("GET", `/api/v1/incidents/${id}/agent-runs`),
  runs: (limit = 50) => request<AgentRun[]>("GET", `/api/v1/agent-runs${qs({ limit })}`),
  investigate: (id: string) => request<AgentRun>("POST", `/api/v1/incidents/${id}/investigate`),
  enrichIncident: (id: string, confirm_external: boolean) => request<{ indicators: EnrichOut[]; risk_score: number }>("POST", `/api/v1/incidents/${id}/enrich`, { confirm_external }),
  enrich: (indicator: string, confirm_external: boolean) => request<EnrichOut>("POST", "/api/v1/enrich", { indicator, confirm_external }),
  iocs: (limit = 200) => request<Ioc[]>("GET", `/api/v1/iocs${qs({ limit })}`),
  addIoc: (indicator: string, score: number, summary: string) => request<Ioc>("POST", "/api/v1/iocs", { indicator, score, summary }),
  deleteIoc: (id: string) => request<void>("DELETE", `/api/v1/iocs/${id}`),
  actions: (p: { status?: string; incident_id?: string; limit?: number } = {}) => request<ResponseAction[]>("GET", `/api/v1/response-actions${qs(p)}`),
  action: (id: string) => request<ResponseAction>("GET", `/api/v1/response-actions/${id}`),
  // a fresh Idempotency-Key per form means a double click or a retry cannot create two proposals
  propose: (incident: string, body: Record<string, unknown>, key: string) =>
    request<ResponseAction>("POST", `/api/v1/incidents/${incident}/response-actions`, body, { "Idempotency-Key": key }),
  suggest: (incident: string, use_ai: boolean) => request<Suggestion>("POST", `/api/v1/incidents/${incident}/response-actions/suggest`, { use_ai }),
  approve: (id: string, real: boolean) => request<ResponseAction>("POST", `/api/v1/response-actions/${id}/approve`, { real }),
  reject: (id: string, reason: string) => request<ResponseAction>("POST", `/api/v1/response-actions/${id}/reject`, { reason }),
  rollback: (id: string) => request<ResponseAction>("POST", `/api/v1/response-actions/${id}/rollback`),
  blocklist: () => request<{ id: string; ip: string; active: boolean; created_by: string; created_at: string }[]>("GET", "/api/v1/blocklist?active_only=false"),
  audit: (p: { action?: string; actor?: string; outcome?: string; limit?: number } = {}) => request<AuditEntry[]>("GET", `/api/v1/audit-logs${qs(p)}`),
};

/** The server asks for explicit consent before sending an indicator to a third party. */
export function confirmationRequest(e: unknown): { warning: string; providers: string[] } | null {
  if (e instanceof ApiError && e.status === 409 && typeof e.detail === "object" && e.detail && (e.detail as { code?: string }).code === "confirmation_required") {
    const d = e.detail as { warning: string; providers: string[] };
    return { warning: d.warning, providers: d.providers };
  }
  return null;
}

/** A readable message from any failure, including the policy reasons the response API returns. */
export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    const d = e.detail as { message?: string; reasons?: string[] } | string | null;
    if (typeof d === "string") return d;
    if (d && typeof d === "object" && "message" in d) return [d.message, ...(d.reasons ?? [])].filter(Boolean).join(": ");
    if (Array.isArray(d)) return "The request was not valid.";
    return `Request failed (${e.status})`;
  }
  return e instanceof Error ? e.message : "Something went wrong";
}
