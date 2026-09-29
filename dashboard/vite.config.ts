import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The engine is a CLI, not a server. The report is a file on disk, and the
    // console reads it. Serving the workspace root means `npm run sync` can
    // drop a fresh report into public/ and the page picks it up on reload.
    fs: { allow: [".."] },
  },
  build: {
    target: "es2020",
    outDir: "dist",
    sourcemap: true,
  },
});
