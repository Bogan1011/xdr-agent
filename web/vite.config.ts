import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the API runs separately on :8080.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/pki": "http://localhost:8080",
      "/install.sh": "http://localhost:8080",
    },
  },
});
