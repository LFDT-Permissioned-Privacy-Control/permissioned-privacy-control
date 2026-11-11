import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'

// A separate entry prevents the legacy AuthProvider, refresh-token storage,
// external fonts and directory UI from entering the V2 browser graph.
export default defineConfig({
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: 'dist-v2', assetsDir: 'assets-v2', emptyOutDir: true,
    rollupOptions: { input: resolve(__dirname, 'index-v2.html') },
  },
})
