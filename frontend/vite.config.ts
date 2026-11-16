import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

// In development the API is on :8000; in Docker, nginx serves this app and proxies /api, so the browser only ever talks to one origin.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: { proxy: { "/api": loadEnv(mode, ".", "").API_URL ?? "http://localhost:8000" } },
  test: { environment: "jsdom", setupFiles: ["./src/__tests__/setup.ts"], css: false },
}));
