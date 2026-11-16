import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "./auth";
import AgentRuns from "./pages/AgentRuns";
import Alerts from "./pages/Alerts";
import Approvals from "./pages/Approvals";
import Audit from "./pages/Audit";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Intel from "./pages/Intel";
import Login from "./pages/Login";
import Mitre from "./pages/Mitre";
import Overview from "./pages/Overview";
import { href, useRoute, type Route } from "./router";

const NAV: { name: Route["name"]; path: string; label: string; perm?: string }[] = [
  { name: "overview", path: "", label: "Overview" }, { name: "alerts", path: "alerts", label: "Alerts" }, { name: "incidents", path: "incidents", label: "Incidents" },
  { name: "mitre", path: "mitre", label: "MITRE" }, { name: "intel", path: "intel", label: "Threat intel" }, { name: "approvals", path: "approvals", label: "Approvals" },
  { name: "runs", path: "agent-runs", label: "AI runs" }, { name: "audit", path: "audit", label: "Audit log", perm: "read_audit" },
];

function Page({ route }: { route: Route }): ReactNode {
  switch (route.name) {
    case "overview": return <Overview />;
    case "alerts": return <Alerts />;
    case "incidents": return <Incidents />;
    case "incident": return <IncidentDetail id={route.id} />;
    case "mitre": return <Mitre />;
    case "intel": return <Intel />;
    case "approvals": return <Approvals />;
    case "runs": return <AgentRuns />;
    case "audit": return <Audit />;
    default: return <p>Page not found. <a href={href("")}>Back to the overview</a>.</p>;
  }
}

function Shell() {
  const { me, ready, can, logout } = useAuth();
  const route = useRoute();
  if (!ready) return <p className="muted" role="status">Loading…</p>;
  if (!me) return <Login />;
  const active = route.name === "incident" ? "incidents" : route.name;
  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="top">
        <strong className="brand">SentinelX</strong>
        <nav aria-label="Main"><ul>{NAV.filter((n) => !n.perm || can(n.perm)).map((n) => <li key={n.name}><a href={href(n.path)} aria-current={active === n.name ? "page" : undefined}>{n.label}</a></li>)}</ul></nav>
        <span className="who">{me.name} ({me.role}) <button className="link" onClick={logout}>Sign out</button></span>
      </header>
      <main id="main"><Page route={route} /></main>
    </>
  );
}

export default function App() {
  return <AuthProvider><Shell /></AuthProvider>;
}
