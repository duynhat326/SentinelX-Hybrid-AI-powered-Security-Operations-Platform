import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, hasToken, setToken, setUnauthorizedHandler, describeError } from "./api";
import type { Me } from "./types";

interface AuthState {
  me: Me | null; ready: boolean; notice: string | null;
  can: (permission: string) => boolean;
  login: (username: string, password: string) => Promise<string | null>;
  logout: () => Promise<void>;
}
const Ctx = createContext<AuthState | null>(null);
export const useAuth = () => { const c = useContext(Ctx); if (!c) throw new Error("AuthProvider missing"); return c; };

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(!hasToken());
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => {
    setUnauthorizedHandler(() => { setMe(null); setNotice("Your session ended. Please sign in again."); });
    if (hasToken()) api.me().then(setMe, () => setToken(null)).finally(() => setReady(true));
  }, []);
  const value: AuthState = {
    me, ready, notice,
    can: (p) => !!me?.permissions.includes(p),
    async login(username, password) {
      try {
        setToken((await api.login(username, password)).token);
        setMe(await api.me()); setNotice(null);
        return null;
      } catch (e) {
        setToken(null);
        return describeError(e);
      }
    },
    async logout() { try { await api.logout(); } catch { /* the session is dropped locally either way */ } setToken(null); setMe(null); setNotice(null); },
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
