import { useEffect, useState } from "react";

export type Route =
  | { name: "overview" } | { name: "alerts" } | { name: "incidents" } | { name: "incident"; id: string } | { name: "mitre" }
  | { name: "intel" } | { name: "approvals" } | { name: "runs" } | { name: "audit" } | { name: "notfound" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseRoute(hash: string): Route {
  const [, a, b] = hash.replace(/^#/, "").split("?")[0].split("/");
  switch (a ?? "") {
    case "": return { name: "overview" };
    case "alerts": case "incidents": case "mitre": case "intel": case "approvals": case "audit":
      return b === undefined ? { name: a as "alerts" } : a === "incidents" && UUID.test(b) ? { name: "incident", id: b } : { name: "notfound" };
    case "agent-runs": return { name: "runs" };
    default: return { name: "notfound" };
  }
}

export function useRoute(): Route {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const on = () => setHash(window.location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return parseRoute(hash);
}

export const href = (path: string) => `#/${path}`;

/** Filters carried in the link (#/alerts?severity=high), so a chart can open the records behind it. */
export const queryOf = (hash = window.location.hash) => new URLSearchParams(hash.split("?")[1] ?? "");
