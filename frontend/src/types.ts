// Mirrors the backend's response models, only the fields the dashboard uses.
export type Severity = "low" | "medium" | "high" | "critical";

export interface Me { name: string; role: string; permissions: string[] }
export interface Overview {
  events_total: number; last_event_at: string | null; alerts_by_severity: Record<string, number>;
  open_incidents_by_severity: Record<string, number>; pending_actions: number; active_blocklist_entries: number;
}
export interface Alert {
  id: string; rule_id: string; title: string; severity: Severity; status: string; host: string; mitre: string[];
  event_count: number; first_event_at: string; last_event_at: string; incident_id: string | null;
}
export interface IncidentSummary {
  id: string; title: string; severity: Severity; status: string; risk_score: number; first_seen: string; last_seen: string;
  alert_count: number; hosts: string[]; mitre: string[];
}
export interface IncidentAlert {
  id: string; rule_id: string; title: string; severity: Severity; mitre: string[]; reason: string;
  first_event_at: string; last_event_at: string; event_count: number;
}
export interface TimelineEntry {
  event_id: string; timestamp: string; source: string; host: string; category: string; action: string; user: string | null;
  src_ip: string | null; dst_ip: string | null; process_name: string | null; command_line: string | null;
  registry_key: string | null; alert_ids: string[];
}
export interface Ioc {
  id: string; kind: string; value: string; source: string; score: number; summary: string; checked_at: string; expires_at: string | null;
}
export interface RiskComponent { value: number | null; weight: number; used: boolean }
export interface IncidentDetail extends IncidentSummary {
  risk_breakdown: { score: number; components: Record<string, RiskComponent>; missing: string[]; effective_weights: Record<string, number> };
  entities: Record<string, string[]>; alerts: IncidentAlert[]; timeline: TimelineEntry[]; timeline_total: number; intel: Ioc[];
}
export interface Claim { text: string; cites: string[] }
export interface AgentRun {
  id: string; incident_id: string; status: string; provider: string; model: string; prompt_version: string; input_sha256: string | null; duration_ms: number | null;
  dropped_claims: number; rejected_tool_calls: { name: string; args: string }[]; error: string | null; created_at: string;
  output: { suggested_priority?: string; confidence?: string; findings?: Claim[]; triage_claims?: Claim[]; next_steps?: string[]; uncertainties?: string[] } | null;
}
export interface ResponseAction {
  id: string; incident_id: string; type: string; params: Record<string, unknown>; status: string; source: string; requested_by: string;
  triggered_by: string; requested_at: string; decided_by: string | null; decision_reason: string | null; dry_run: boolean | null;
  result?: Record<string, unknown> | null; rollback_guidance?: string;
}
export interface SourceResult { source: string; status: string; score: number | null; summary: string | null; cached: boolean }
export interface EnrichOut { indicator: string; kind: string; status: string; sources: SourceResult[]; note: string | null }
export interface AuditEntry {
  id: string; ts: string; actor: string; role: string | null; action: string; target_type: string | null; target_id: string | null;
  outcome: string; ip: string | null; detail: Record<string, unknown>;
}
export interface Suggestion { source: string; created: ResponseAction[]; existing: ResponseAction[]; denied: { type: string; target: string | null; reasons: string[] }[]; dropped: number; error: string | null }
