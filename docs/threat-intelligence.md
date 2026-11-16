# Threat intelligence

A local IOC table, optional lookups at VirusTotal and AbuseIPDB, and the stored verdicts feeding the incident risk score. Everything works with no provider configured; external lookups are opt-in at three levels.

## Where a verdict comes from
`iocs` holds one verdict per (indicator, source): `manual` rows are the **local IOC database** (written by an approver or admin, no expiry); `virustotal` and `abuseipdb` rows are a **cache** with `expires_at` (`SENTINELX_TI_CACHE_TTL_HOURS`, default 24). Indicators are IPv4/IPv6 addresses, domains and SHA-256 hashes, canonicalised on the way in. Anything else is a 422: the value goes into provider URLs, so paths, ports, spaces, `%` scope ids and the like cannot get through.

## Nothing leaves without three yeses
A lookup that would contact a provider is sent **only if all hold**:
1. `SENTINELX_TI_EXTERNAL_ENABLED=true` (default `false`) and that provider has a key (`SENTINELX_VT_API_KEY`, `SENTINELX_ABUSEIPDB_API_KEY`; an empty value counts as unset).
2. The request carries `confirm_external: true`. Without it the API answers **409** with a warning naming the indicator and the providers, and sends nothing.
3. The indicator is a **public** address, a domain or a hash. Private, loopback, link-local, multicast and documentation addresses are never sent, even when confirmed.

Each call that is made is audited as `ti.external_lookup` with the caller, provider, indicator and outcome (never the key), so there is a trail of what was disclosed to whom. Answers already in the cache or local table are returned without any of this. Redirects are not followed, so a provider cannot send the request on to another host.

## Never fabricate
- A provider that times out, errors, answers 401/403/5xx, is rate limited, returns something that is not the expected shape, or a number outside its range gives `unavailable` or `rate_limited`, and **nothing is stored**.
- VirusTotal answering 404 means it has never seen the indicator: `not_found`, not stored, and not "clean". AbuseIPDB answers 200 with score 0 for unknown addresses, which is stored as its real answer.
- Provider text is never copied: stored and returned summaries are sentences built from numbers (`5 malicious and 2 suspicious of 87 engines`). A hostile or compromised provider cannot put words in front of an analyst or a language model.
- Each provider has its own in-process rate limit (`SENTINELX_TI_EXTERNAL_RATE_PER_MINUTE`, default 4, the free VirusTotal tier); a call over the limit is refused locally and not sent. Calls time out after `SENTINELX_TI_TIMEOUT_SECONDS` (5).

## Scores
| Source | Score (0 clean to 100 malicious) |
|---|---|
| AbuseIPDB | its abuse confidence score, as given |
| VirusTotal | `min(100, 10 * malicious engines + 5 * suspicious engines)` |
| manual | whatever the analyst enters |

The VirusTotal scale is **illustrative and uncalibrated**. A low score from one provider is not "safe".

## In the risk score
For an incident, the threat-intelligence component is the **highest** non-expired score among the incident's IP addresses.
- **No stored verdict at all** (or no address): the component is *unknown*, dropped, and the other weights renormalized, exactly as before.
- **A stored verdict of 0** is *information*: "checked and clean". It counts, and so lowers the score below the unknown case (a high incident with no other signals: unknown 44, clean 35, known-malicious 55).
Adding or deleting an IOC, or a confirmed lookup that stores something, recomputes every open incident involving that address immediately. `GET /api/v1/incidents/{id}` lists the verdicts under `intel`.

## API
| Method | Path | Needs |
|---|---|---|
| POST | `/api/v1/enrich` `{indicator, confirm_external}` | `enrich` (analyst and up) |
| POST | `/api/v1/incidents/{id}/enrich` `{confirm_external}` | `enrich`; looks up the incident's addresses (at most 10) |
| GET | `/api/v1/iocs` | `read` |
| POST / DELETE | `/api/v1/iocs`, `/api/v1/iocs/{id}` | `manage_iocs` (approver, admin); audited as `ioc.create` / `ioc.delete` |

The incident-level lookup is the "threat intelligence agent": deterministic code, with no language model, because nothing in it needs one.

## Not verified, not done
- **The provider calls were never made against the real services.** The adapters follow the providers' public documentation as I know it (AbuseIPDB v2 `check`, VirusTotal v3 `ip_addresses`, `domains`, `files`) and are tested against a fake HTTP transport only. Field names or limits may differ or have changed; check with a throwaway key before relying on them.
- A verdict that expires is ignored by the incident view immediately, but the incident's stored `risk_score` is only recomputed on its next change or enrichment, so it can be stale until then.
- Incident enrichment looks up addresses only; domains and hashes are looked up by hand with `POST /api/v1/enrich`.
- No MITRE ATT&CK data set, feed import, or periodic refresh. ATT&CK technique ids still come from the detection rules.
- Rate limiting is per process.
