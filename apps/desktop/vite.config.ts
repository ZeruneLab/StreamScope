import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  resolve: {
    alias: { "@streamscope/application": fileURLToPath(new URL(mode === "core" ? "./src/CoreApp.tsx" : "./src/App.tsx", import.meta.url)) },
  },
  build: { outDir: mode === "core" ? "dist-core" : "dist" },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
}));
