# Dashboard

A React and TypeScript single-page app in `frontend/` (Vite, no UI library, no chart library). In Docker it is served by nginx on <http://localhost:8080>, which also proxies `/api` to the backend, so the browser only ever talks to one origin.

| Overview | Overview widgets | Incident detail | MITRE |
|---|---|---|---|
| ![Overview](screenshots/overview.jpg) | ![Widgets](screenshots/overview-widgets.jpg) | ![Incident](screenshots/incident.jpg) | ![MITRE](screenshots/mitre.jpg) |

Screenshots show lab data seeded from the test corpus.

## Pages
| Page | What it shows | Needs |
|---|---|---|
| Overview | a SOC-posture console: six exact KPI tiles (events, alerts, open incidents, average risk, approvals waiting, blocklist) with counting numbers and a sparkline; alerts over time stacked by severity; open incidents by severity (donut); an events → alerts → incidents → AI runs → actions funnel; risk distribution; top ATT&CK techniques, busiest hosts and noisiest rules; AI and response status; highest-risk incidents with a score ring; latest alerts. A 6h / 24h / 7d / All switch scopes the charts and the page refreshes itself every 30 s. Every tile, slice and bar links to the records behind it (`#/alerts?q=...`, `#/incidents?severity=...`) | read |
| Alerts | filterable table (severity, host, rule), link to the incident | read |
| Incidents, incident detail | ranked by risk; detail has the risk-score breakdown, entities, threat-intel verdicts, alerts with why they were grouped, the evidence timeline with how many alerts cite each event, AI runs, response actions | read |
| MITRE | techniques of current alerts grouped by tactic | read |
| Threat intel | local IOC table, indicator lookup, add or remove IOCs | read; lookup needs `enrich`; IOC writes need `manage_iocs` |
| Approvals | proposals waiting for a decision and the recently decided | read; deciding needs `approve` |
| AI runs | every investigation with model, prompt version, duration, dropped claims, refused tool calls, input hash | read |
| Audit log | filter by action, actor, outcome | `read_audit` (admin) |

## What it does for safety
- **Controls follow permissions.** `/api/v1/auth/me` returns the caller's permissions and the UI hides what they may not do. This is convenience only; the server still enforces every permission, and the 403 is shown if something slips through.
- **Consent before anything leaves the network.** A threat-intel lookup that would contact a provider first shows the server's warning and sends nothing until the person clicks "Send to ...". Cancelling sends nothing.
- **Approving is a dry run unless asked otherwise.** "Run for real" is unticked by default; the server decides whether real actions are allowed. Proposals carry one `Idempotency-Key` per form, so a double click or a retry cannot create two.
- **Log text is data.** Nothing uses `dangerouslySetInnerHTML`; hostile text in a log (`<img onerror=...>`, `<script>`) is rendered as text (tested). A generated report is shown in a `<pre>`, not rendered as markdown.
- **Strict headers.** nginx sends a Content-Security-Policy with no inline script or style and `connect-src 'self'`, plus `nosniff`, `X-Frame-Options: DENY`, no referrer. The page loads and runs with no console errors under it.
- **The session token is in `sessionStorage`** (gone when the tab closes, readable by scripts of this origin). The CSP and React's escaping are the defence. An expired or revoked session returns you to the sign-in page. Moving to an HttpOnly cookie would need backend support.
- **The client address is not spoofable through the dashboard.** nginx *sets* `X-Forwarded-For` to the real peer, so per-IP rate limits and audit rows see the real address (checked: a forged header was ignored). The backend trusts that header from any peer (`FORWARDED_ALLOW_IPS=*`), which is only safe because its port is published on the loopback interface alone; anyone with local access to port 8000 could forge it.

## Run it
```bash
docker compose up --build            # dashboard on http://localhost:8080, API on 127.0.0.1:8000
docker compose exec backend .venv/bin/python -m app.manage create-user alice admin   # first user, see security-model.md
```
Development with hot reload (API on :8000, e.g. from `docker compose up backend db`):
```bash
cd frontend && npm ci && npm run dev    # http://localhost:5173, /api proxied to :8000
```
Checks, also run in CI: `npm run typecheck`, `npm test`, `npm run build`.

## Tests
27 tests (Vitest, Testing Library, a mocked `fetch`) cover the API client (bearer header, 401 handling, idempotency key, error text), the MITRE grouping and the router, and the flows that matter: sign-in and failure, session expiry, what each role is offered, the consent flow, dry run versus real, policy reasons from the server, log text rendered as text, the audit link hidden from non-admins. Each safety property was broken on purpose (11 times) and a test failed every time.

## Limits
- Not tested with a screen reader; the markup uses landmarks, table captions, labelled controls, `aria-current`, `role="alert"` and a skip link, and severity is always written out, but this is not an accessibility audit.
- No ESLint (the project relies on `tsc --strict` and the tests).
- MITRE names exist only for the techniques the rules assign; others show as unmapped. There is no bundled ATT&CK data set.
- Lists are capped (alerts 200, incidents 200, audit 200) with no pagination; the overview counts are exact.
- The overview and lists are loaded on demand: there is no live push, reload the page or revisit it to refresh.
- Timestamps use the browser's locale and time zone.

## Look and fonts
The overview follows the cases-dashboard idea of modern SOC tools (KPIs, trends, severity mix, workload, then a click through to the cases behind a number); the look is a dark graphite console with the logo's electric blue as the accent, severity colours that are always paired with text, and a light theme (a Theme button switches auto, dark and light and is remembered in this browser). Type and motion follow Apple's style: large tight headings, translucent blurred sticky bar, pill tabs and buttons, springy easing, light and dark by `prefers-color-scheme`, everything still at rest under `prefers-reduced-motion`. Effects are CSS only (glow in the overview hero and sign-in page, rising cards, bars that grow), so the strict CSP is unchanged; severity and scores are still written as text.
**Font:** SF Compact (Text 400/500/600, Display 700), subset to Latin (about 60 KB each) and served from `/fonts`. Apple's licence does not allow redistributing it, so `frontend/public/fonts/` is git-ignored: copy the files in locally (a clone without them falls back to the system UI font, and the dashboard works the same). Do not publish a build that contains them.
Dev against another backend port: `API_URL=http://127.0.0.1:8001 npm run dev`.

**Charts are a view of the latest records.** They use the newest 200 alerts and 200 open incidents (the API caps lists), and the time window is measured back from the newest alert so a lab with old data still draws something; the tiles are exact server counts. Not built: per-role dashboard templates, saved or custom widgets, a mean-time-to-resolve chart (incidents cannot be closed from the product yet).

**Brand files.** The logo, cover and icon supplied in `frontend/assets/` (about 1.5 MB each) are served as small copies in `frontend/public/brand/` (logo 560 px, a 128 px cropped mark for the top bar, the cover as a 1600 px JPEG used behind the sign-in page, the Apple touch icon) plus `public/favicon.ico`; `index.html` links the icons and share tags. The Dockerfile now copies `public/` (it did not before, so the fonts and these files would not have reached the image). `docs/banner.jpg` is the cover used at the top of the README.
