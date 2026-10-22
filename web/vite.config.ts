import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/cytoscape")) return "graph-vendor";
          if (id.includes("node_modules/chart.js") || id.includes("node_modules/react-chartjs-2")) return "charts-vendor";
        },
      },
    },
  },
});
