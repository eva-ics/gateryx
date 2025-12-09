import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  base: "/.gateryx/auth",
  plugins: [react()],
  resolve: {
    alias: {
      "@sass": "/src/sass"
    }
  }
});
