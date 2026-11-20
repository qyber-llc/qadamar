import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const BACKEND_TARGET = process.env.PDP_URL ?? 'http://127.0.0.1:8787';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/admin': {
        target: BACKEND_TARGET,
        changeOrigin: false,
      },
      '/access': {
        target: BACKEND_TARGET,
        changeOrigin: false,
      },
      '/x': {
        target: BACKEND_TARGET,
        changeOrigin: false,
      },
      '/.well-known': {
        target: BACKEND_TARGET,
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
});
