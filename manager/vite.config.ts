import { defineConfig } from "vite";

// Tauri expects a fixed dev port and serves the built assets from `dist-web`.
// The final OS executables produced by build.sh land in `dist/`, so the web
// bundle is kept in a separate directory to avoid clobbering them.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  clearScreen: false,
  build: {
    outDir: "dist-web",
    emptyOutDir: true,
    target: "es2020",
  },
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: {
      // Tauri owns the Rust side; don't let Vite watch it.
      ignored: ["**/src-tauri/**"],
    },
  },
});
