// Only the techniques the SentinelX rules assign are named here (ATT&CK names and tactics as published); any other id is
// shown as "Unmapped" with its id, never guessed. There is no bundled ATT&CK data set.
export const TECHNIQUES: Record<string, { name: string; tactics: string[] }> = {
  T1110: { name: "Brute Force", tactics: ["Credential Access"] },
  "T1059.001": { name: "Command and Scripting Interpreter: PowerShell", tactics: ["Execution"] },
  "T1136.001": { name: "Create Account: Local Account", tactics: ["Persistence"] },
  T1098: { name: "Account Manipulation", tactics: ["Persistence", "Privilege Escalation"] },
  "T1547.001": { name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", tactics: ["Persistence", "Privilege Escalation"] },
  T1071: { name: "Application Layer Protocol", tactics: ["Command and Control"] },
  "T1204.002": { name: "User Execution: Malicious File", tactics: ["Execution"] },
  T1105: { name: "Ingress Tool Transfer", tactics: ["Command and Control"] },
  T1078: { name: "Valid Accounts", tactics: ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"] },
};

export const TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
  "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "Unmapped"];

export interface TechniqueCount { id: string; name: string; alerts: number }
export interface TacticColumn { tactic: string; techniques: TechniqueCount[] }

/** Alerts per technique, grouped under each tactic it belongs to (a technique can sit in several). Empty tactics are omitted. */
export function groupByTactic(alerts: { mitre: string[] }[]): TacticColumn[] {
  const counts = new Map<string, number>();
  for (const a of alerts) for (const t of new Set(a.mitre)) counts.set(t, (counts.get(t) ?? 0) + 1);
  const cols = new Map<string, TechniqueCount[]>();
  for (const [id, n] of counts) {
    const known = TECHNIQUES[id];
    for (const tactic of known ? known.tactics : ["Unmapped"]) cols.set(tactic, [...(cols.get(tactic) ?? []), { id, name: known?.name ?? "Not in the dashboard's technique list", alerts: n }]);
  }
  return TACTIC_ORDER.filter((t) => cols.has(t)).map((tactic) => ({ tactic, techniques: cols.get(tactic)!.sort((a, b) => b.alerts - a.alerts || a.id.localeCompare(b.id)) }));
}

export const techniqueUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
