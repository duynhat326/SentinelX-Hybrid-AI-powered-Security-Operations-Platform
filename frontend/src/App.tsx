import { useEffect, useState, type ReactNode } from "react";
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

// Two bars like a SIEM console: a system bar (product, search, user) and an app bar (the views of this app).
const NAV: { name: Route["name"]; path: string; label: string; perm?: string }[] = [
  { name: "overview", path: "", label: "Security Posture" }, { name: "incidents", path: "incidents", label: "Incident Review" }, { name: "alerts", path: "alerts", label: "Alerts" },
  { name: "mitre", path: "mitre", label: "ATT&CK" }, { name: "intel", path: "intel", label: "Threat Intel" }, { name: "approvals", path: "approvals", label: "Approvals" },
  { name: "runs", path: "agent-runs", label: "AI Runs" }, { name: "audit", path: "audit", label: "Audit log", perm: "read_audit" },
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

/** auto follows the system; the choice is remembered in this browser only. */
function ThemeToggle() {
  const [t, setT] = useState(() => { try { return localStorage.getItem("sentinelx.theme") ?? ""; } catch { return ""; } });
  useEffect(() => {
    if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
    try { if (t) localStorage.setItem("sentinelx.theme", t); else localStorage.removeItem("sentinelx.theme"); } catch { /* private mode: the choice just is not remembered */ }
  }, [t]);
  return <button type="button" className="secondary theme" onClick={() => setT(t === "dark" ? "light" : t === "light" ? "" : "dark")}>Theme: {t || "auto"}</button>;
}

/** "Find" in the system bar: a quick search that opens the alerts list filtered by host, rule, title or technique. */
function Find() {
  const [q, setQ] = useState("");
  return (
    <form className="find" role="search" onSubmit={(e) => { e.preventDefault(); if (q.trim()) window.location.hash = `#/alerts?q=${encodeURIComponent(q.trim())}`; }}>
      <label className="sr-only" htmlFor="find">Find alerts</label>
      <input id="find" type="search" placeholder="Find: host, rule or technique" value={q} onChange={(e) => setQ(e.target.value)} />
    </form>
  );
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
      <header className="sysbar">
        <a className="brand" href={href("")}><img src="/brand/mark.png" alt="" width="30" height="30" />SentinelX<span className="app-name">Security Operations</span></a>
        <Find />
        <details className="menu">
          <summary>{me.name.replace(/^user:/, "")}<span className="role">{me.role}</span></summary>
          <div className="menu-pop"><ThemeToggle /><button type="button" className="secondary" onClick={logout}>Sign out</button></div>
        </details>
      </header>
      <nav className="appbar" aria-label="Main"><ul>{NAV.filter((n) => !n.perm || can(n.perm)).map((n) => <li key={n.name}><a href={href(n.path)} aria-current={active === n.name ? "page" : undefined}>{n.label}</a></li>)}</ul></nav>
      {/* keyed by the full hash so a filtered link (#/alerts?q=...) re-reads its filters even from the same page */}
      <main id="main" key={window.location.hash}><Page route={route} /></main>
    </>
  );
}

export default function App() {
  return <AuthProvider><Shell /></AuthProvider>;
}
