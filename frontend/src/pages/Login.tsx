import { useState, type FormEvent } from "react";
import { useAuth } from "../auth";
import { Err } from "../ui";

export default function Login() {
  const { login, notice } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(await login(String(f.get("username")), String(f.get("password"))));
    setBusy(false);
  }
  return (
    <main className="login">
      <h1>SentinelX</h1>
      <p className="muted">Detect. Investigate. Understand. Respond.</p>
      {notice && <p role="status" className="notice">{notice}</p>}
      <form onSubmit={submit}>
        <label>Username<input name="username" autoComplete="username" required autoFocus /></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
        <Err msg={error} />
        <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </main>
  );
}
