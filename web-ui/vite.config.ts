import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { browserLicenseNotices } from "./build/browser-license-notices.mjs";

export default defineConfig({
  base: "/ui/",
  plugins: [react(), browserLicenseNotices()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    manifest: true,
    target: "es2022",
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
