import { describe, expect, it } from "vitest";
import { parseRoute } from "../router";
import { groupByTactic, techniqueUrl } from "../mitre";
import { ID } from "./mockApi";

describe("MITRE grouping", () => {
  it("counts alerts per technique and places each technique under every tactic it belongs to", () => {
    const cols = groupByTactic([{ mitre: ["T1110"] }, { mitre: ["T1110", "T1078"] }, { mitre: ["T1078"] }, { mitre: ["T1078", "T1078"] }]);
    const by = Object.fromEntries(cols.map((c) => [c.tactic, c.techniques]));
    expect(by["Credential Access"]).toEqual([{ id: "T1110", name: "Brute Force", alerts: 2 }]);
    expect(by["Persistence"][0]).toMatchObject({ id: "T1078", alerts: 3 }); // a duplicate inside one alert counts once
    expect(by["Initial Access"][0].id).toBe("T1078");
    expect(cols.map((c) => c.tactic)).toEqual(["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access"]);
  });

  it("never guesses: an unknown technique is shown as unmapped with its id", () => {
    const cols = groupByTactic([{ mitre: ["T9999"] }]);
    expect(cols).toEqual([{ tactic: "Unmapped", techniques: [{ id: "T9999", name: "Not in the dashboard's technique list", alerts: 1 }] }]);
    expect(groupByTactic([])).toEqual([]);
    expect(groupByTactic([{ mitre: [] }])).toEqual([]);
  });

  it("links sub-techniques to the right ATT&CK page", () => {
    expect(techniqueUrl("T1059.001")).toBe("https://attack.mitre.org/techniques/T1059/001/");
    expect(techniqueUrl("T1110")).toBe("https://attack.mitre.org/techniques/T1110/");
  });
});

describe("routes", () => {
  it("parses known pages and rejects anything else, including a malformed incident id", () => {
    expect(parseRoute("")).toEqual({ name: "overview" });
    expect(parseRoute("#/alerts")).toEqual({ name: "alerts" });
    expect(parseRoute("#/agent-runs")).toEqual({ name: "runs" });
    expect(parseRoute(`#/incidents/${ID}`)).toEqual({ name: "incident", id: ID });
    for (const bad of ["#/incidents/not-an-id", "#/incidents/../x", "#/nope", "#/alerts/extra"]) expect(parseRoute(bad)).toEqual({ name: "notfound" });
  });
});
