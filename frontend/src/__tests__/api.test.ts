import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, confirmationRequest, describeError, setToken, setUnauthorizedHandler } from "../api";
import { ID, mockApi, status } from "./mockApi";

beforeEach(() => { setToken(null); setUnauthorizedHandler(() => {}); });

describe("api client", () => {
  it("sends the bearer token and a JSON body, and nothing sensitive in the URL", async () => {
    const calls = mockApi({ "POST /api/v1/enrich": { ok: true } });
    setToken("tok-abc");
    await api.enrich("8.8.8.8", false);
    expect(calls[0].headers.Authorization).toBe("Bearer tok-abc");
    expect(calls[0].headers["content-type"]).toBe("application/json");
    expect(calls[0].body).toEqual({ indicator: "8.8.8.8", confirm_external: false });
    expect(calls[0].path).toBe("/api/v1/enrich");
  });

  it("drops the session and signals once on a 401 with a token, but not on a failed login", async () => {
    mockApi({ "GET /api/v1/overview": status(401, { detail: "invalid or expired token" }), "POST /api/v1/auth/login": status(401, { detail: "invalid credentials" }) });
    const onOut = vi.fn();
    setUnauthorizedHandler(onOut);
    await expect(api.login("a", "b")).rejects.toBeInstanceOf(ApiError);
    expect(onOut).not.toHaveBeenCalled();
    setToken("tok");
    await expect(api.overview()).rejects.toMatchObject({ status: 401 });
    expect(onOut).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem("sentinelx.token")).toBeNull();
  });

  it("keeps the token in session storage only", () => {
    setToken("tok-1");
    expect(sessionStorage.getItem("sentinelx.token")).toBe("tok-1");
    expect(localStorage.getItem("sentinelx.token")).toBeNull();
  });

  it("proposes with an Idempotency-Key so a retry cannot duplicate", async () => {
    const calls = mockApi({ [`POST /api/v1/incidents/${ID}/response-actions`]: { id: "x" } });
    await api.propose(ID, { type: "generate_report" }, "key-1");
    expect(calls[0].headers["Idempotency-Key"]).toBe("key-1");
  });

  it("returns undefined for 204 and builds query strings without empty values", async () => {
    const calls = mockApi({ "DELETE /api/v1/iocs/i1": status(204, null), "GET /api/v1/audit-logs": [] });
    expect(await api.deleteIoc("i1")).toBeUndefined();
    await api.audit({ action: "", actor: "user:a", limit: 5 });
    expect(calls[1].path).toBe("/api/v1/audit-logs?actor=user%3Aa&limit=5");
  });
});

describe("error helpers", () => {
  it("recognises the confirmation request and nothing else", () => {
    const ok = new ApiError(409, { code: "confirmation_required", warning: "sends it out", providers: ["virustotal"] });
    expect(confirmationRequest(ok)).toEqual({ warning: "sends it out", providers: ["virustotal"] });
    expect(confirmationRequest(new ApiError(409, { message: "x" }))).toBeNull();
    expect(confirmationRequest(new ApiError(422, { code: "confirmation_required" }))).toBeNull();
    expect(confirmationRequest(new Error("x"))).toBeNull();
  });

  it("shows the policy reasons the server gives", () => {
    expect(describeError(new ApiError(422, { message: "policy violation", reasons: ["the address is on the protected list"] }))).toBe("policy violation: the address is on the protected list");
    expect(describeError(new ApiError(403, "insufficient role"))).toBe("insufficient role");
    expect(describeError(new ApiError(422, [{ loc: ["body"] }]))).toBe("The request was not valid.");
    expect(describeError(new ApiError(500, null))).toBe("Request failed (500)");
  });
});
