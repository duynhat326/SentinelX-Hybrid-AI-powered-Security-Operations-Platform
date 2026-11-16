import { useCallback, useEffect, useState } from "react";
import { describeError } from "./api";

/** Re-renders every `ms` so "updated 12 s ago" stays true. */
export function useNow(ms = 5000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(t); }, [ms]);
  return now;
}

export function useApi<T>(load: () => Promise<T>, deps: unknown[] = []) {
  const [state, setState] = useState<{ data?: T; error?: string; loading: boolean; at?: number }>({ loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true }));
    load().then((data) => live && setState({ data, loading: false, at: Date.now() }), (e) => live && setState({ error: describeError(e), loading: false }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: useCallback(() => setTick((t) => t + 1), []) };
}

/** Runs an action, tracks pending and error, and calls `then` on success. `handled` may claim an error (return true) to stop it showing as a failure. */
export function useAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async <T,>(fn: () => Promise<T>, then?: (r: T) => void, handled?: (e: unknown) => boolean) => {
    setPending(true); setError(null);
    try { const r = await fn(); then?.(r); return r; } catch (e) { if (!handled?.(e)) setError(describeError(e)); return undefined; } finally { setPending(false); }
  };
  return { pending, error, setError, run };
}
