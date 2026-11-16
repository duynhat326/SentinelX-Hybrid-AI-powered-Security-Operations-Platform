import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { setToken } from "../api";
import App from "../App";
import { ID, PERMS, action, incident, me, mockApi, overview, session, status } from "./mockApi";

const open = (hash: string) => { window.location.hash = hash; };
const incidentRoutes = (acts: unknown[] = [action()], inc = incident()) => ({
  [`GET /api/v1/incidents/${ID}`]: inc, [`GET /api/v1/incidents/${ID}/agent-runs`]: [], "GET /api/v1/response-actions": acts,
});
const enrichRoute = (body: { confirm_external: boolean }) => body.confirm_external
  ? { incident_id: ID, risk_score: 55, indicators: [{ indicator: "203.0.113.50", kind: "ip", status: "found", note: null, sources: [{ source: "virustotal", status: "found", score: 60, summary: "5 malicious", cached: false }] }] }
  : status(409, { detail: { code: "confirmation_required", indicator: "203.0.113.50", providers: ["virustotal"], warning: "This sends '203.0.113.50' to third parties (virustotal)." } });

beforeEach(() => setToken(null));

describe("signing in", () => {
  it("signs in with a username and password and lands on the overview", async () => {
    const calls = mockApi({ "POST /api/v1/auth/login": { token: "tok-new" }, "GET /api/v1/auth/me": me("analyst", PERMS.analyst), "GET /api/v1/overview": overview, "GET /api/v1/incidents": [], "GET /api/v1/alerts": [] });
    const user = userEvent.setup();
    render(<App />);
    await user.type(screen.getByLabelText("Username"), "alice");
    await user.type(screen.getByLabelText("Password"), "a perfectly fine pass");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/v1/auth/login", body: { username: "alice", password: "a perfectly fine pass" } });
    expect(sessionStorage.getItem("sentinelx.token")).toBe("tok-new");
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("shows a failed sign-in as an alert and keeps no token", async () => {
    mockApi({ "POST /api/v1/auth/login": status(401, { detail: "invalid credentials" }) });
    const user = userEvent.setup();
    render(<App />);
    await user.type(screen.getByLabelText("Username"), "alice");
    await user.type(screen.getByLabelText("Password"), "wrong wrong wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid credentials");
    expect(sessionStorage.getItem("sentinelx.token")).toBeNull();
  });

  it("returns to the sign-in page with a notice when the session ends mid-use", async () => {
    session("viewer", { "GET /api/v1/overview": status(401, { detail: "invalid or expired token" }) });
    render(<App />);
    expect(await screen.findByText(/session ended/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(sessionStorage.getItem("sentinelx.token")).toBeNull();
  });
});

describe("pages", () => {
  it("writes the chart numbers out, not just colours", async () => {
    session("viewer");
    render(<App />);
    const region = await screen.findByRole("region", { name: "Alerts by severity" });
    expect(within(region).getByText("critical").parentElement).toHaveTextContent("1");
    expect(within(region).getByText("high").parentElement).toHaveTextContent("3");
    expect(screen.getByText("actions awaiting approval").closest("a")).toHaveAttribute("href", "#/approvals");
  });

  it("shows a failed request as an alert", async () => {
    session("viewer", { "GET /api/v1/incidents": status(500, null) });
    open("#/incidents");
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed (500)");
  });

  it("offers the audit log only to those who may read it", async () => {
    session("viewer");
    const { unmount } = render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    expect(screen.queryByRole("link", { name: "Audit log" })).toBeNull();
    unmount();
    setToken(null);
    session("admin");
    render(<App />);
    expect(await screen.findByRole("link", { name: "Audit log" })).toBeInTheDocument();
  });

  it("marks the current page for assistive technology", async () => {
    session("viewer");
    open("#/alerts");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Alerts" })).toHaveAttribute("aria-current", "page");
  });
});

describe("incident page: what each role is offered", () => {
  it("shows a viewer the facts but no controls", async () => {
    session("viewer", incidentRoutes());
    open(`#/incidents/${ID}`);
    render(<App />);
    expect(await screen.findByRole("heading", { name: incident().title })).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument(); // the threat-intel part of the risk score is unknown, and says so
    expect(screen.queryByText("Propose an action")).toBeNull();
    expect(screen.queryByRole("button", { name: /Run AI investigation/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Look up this incident/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Approve/ })).toBeNull();
  });

  it("lets an analyst propose, investigate and look up, but not approve", async () => {
    session("analyst", incidentRoutes());
    open(`#/incidents/${ID}`);
    render(<App />);
    expect(await screen.findByText("Propose an action")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run AI investigation/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Look up this incident/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Approve/ })).toBeNull();
  });

  it("gives an approver a dry run by default and runs for real only when asked", async () => {
    const calls = session("approver", { ...incidentRoutes(), "POST /api/v1/response-actions/act-1/approve": action({ status: "simulated", dry_run: true }) });
    open(`#/incidents/${ID}`);
    const user = userEvent.setup();
    render(<App />);
    const box = await screen.findByRole("checkbox", { name: /Run for real/ });
    expect(box).not.toBeChecked();
    await user.click(screen.getByRole("button", { name: "Approve (dry run)" }));
    await waitFor(() => expect(calls.find((c) => c.path.endsWith("/approve"))?.body).toEqual({ real: false }));
  });

  it("sends real: true only after the box is ticked", async () => {
    const calls = session("approver", { ...incidentRoutes(), "POST /api/v1/response-actions/act-1/approve": action({ status: "executed", dry_run: false }) });
    open(`#/incidents/${ID}`);
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("checkbox", { name: /Run for real/ }));
    await user.click(screen.getByRole("button", { name: "Approve and run" }));
    await waitFor(() => expect(calls.find((c) => c.path.endsWith("/approve"))?.body).toEqual({ real: true }));
  });

  it("asks before anything is sent to a third party, and sends nothing until confirmed", async () => {
    const calls = session("analyst", { ...incidentRoutes(), [`POST /api/v1/incidents/${ID}/enrich`]: enrichRoute });
    open(`#/incidents/${ID}`);
    const user = userEvent.setup();
    render(<App />);
    await user.click(await screen.findByRole("button", { name: /Look up this incident/ }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("third parties");
    const sent = () => calls.filter((c) => c.path.endsWith("/enrich")).map((c) => (c.body as { confirm_external: boolean }).confirm_external);
    expect(sent()).toEqual([false]);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(sent()).toEqual([false]); // cancelling sent nothing
    await user.click(screen.getByRole("button", { name: /Look up this incident/ }));
    await user.click(await screen.findByRole("button", { name: "Send to virustotal" }));
    expect(await screen.findByText(/virustotal: 60/)).toBeInTheDocument();
    expect(sent()).toEqual([false, false, true]);
  });

  it("proposes with one idempotency key per form and shows the server's policy reasons", async () => {
    const calls = session("analyst", { ...incidentRoutes([]), [`POST /api/v1/incidents/${ID}/response-actions`]: () => status(422, { detail: { message: "policy violation", reasons: ["the address is on the protected list"] } }) });
    open(`#/incidents/${ID}`);
    const user = userEvent.setup();
    render(<App />);
    await user.type(await screen.findByLabelText("Reason"), "scanner");
    await user.click(screen.getByRole("button", { name: "Propose" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("policy violation: the address is on the protected list");
    await user.click(screen.getByRole("button", { name: "Propose" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST" && c.path.endsWith("/response-actions")).length).toBe(2));
    const [a, b] = calls.filter((c) => c.method === "POST" && c.path.endsWith("/response-actions"));
    expect(a.body).toEqual({ type: "add_blocklist_entry", ip: "203.0.113.50", reason: "scanner" });
    expect(a.headers["Idempotency-Key"]).toBeTruthy();
    expect(b.headers["Idempotency-Key"]).toBe(a.headers["Idempotency-Key"]); // a retry of the same form is the same request
  });

  it("renders log text as text, never as markup", async () => {
    const hostile = incident({
      title: "<b>bold</b> incident",
      timeline: [{ ...incident().timeline[0], user: '<img src=x onerror="window.__xss=1">', command_line: "<script>window.__xss=2</script>" }],
    });
    session("viewer", incidentRoutes([], hostile));
    open(`#/incidents/${ID}`);
    render(<App />);
    expect(await screen.findByText('<img src=x onerror="window.__xss=1">')).toBeInTheDocument();
    expect(screen.getByText("<script>window.__xss=2</script>")).toBeInTheDocument();
    const main = document.querySelector("main")!;
    expect(main.querySelector("img, script, b")).toBeNull();
    expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
  });
});

describe("approval queue and threat intel", () => {
  it("will not reject without a reason, then sends it", async () => {
    const calls = session("approver", { "GET /api/v1/response-actions": [action()], "POST /api/v1/response-actions/act-1/reject": action({ status: "rejected" }) });
    open("#/approvals");
    const user = userEvent.setup();
    render(<App />);
    const reject = await screen.findByRole("button", { name: "Reject" });
    expect(reject).toBeDisabled();
    await user.type(screen.getByLabelText("Reason to reject"), "our own scanner");
    await user.click(reject);
    await waitFor(() => expect(calls.find((c) => c.path.endsWith("/reject"))?.body).toEqual({ reason: "our own scanner" }));
  });

  it("shows the IOC form only to those who may write IOCs", async () => {
    session("analyst", { "GET /api/v1/iocs": [] });
    open("#/intel");
    const { unmount } = render(<App />);
    expect(await screen.findByRole("heading", { name: "Look up an indicator" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Add to the local IOC table" })).toBeNull();
    unmount();
    setToken(null);
    session("approver", { "GET /api/v1/iocs": [] });
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Add to the local IOC table" })).toBeInTheDocument();
  });
});
