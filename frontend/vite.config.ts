import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import type { RollupLog } from 'rollup'

function isThirdPartyPureAnnotationWarning(warning: RollupLog): boolean {
  if (warning.code !== 'INVALID_ANNOTATION') return false
  if (!warning.message?.includes('contains an annotation that Rollup cannot interpret')) return false
  const id = 'id' in warning ? warning.id : undefined
  return typeof id === 'string' && id.includes('/node_modules/')
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Wallet SDK dependencies are intentionally large; this threshold avoids
    // noisy warnings while still surfacing genuinely abnormal growth.
    chunkSizeWarningLimit: 2000,
    rollupOptions: {
      onwarn(warning, warn) {
        if (isThirdPartyPureAnnotationWarning(warning)) return
        warn(warning)
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    host: '0.0.0.0',
    // Allow all hosts in development for ngrok/external access
    allowedHosts: true,
    proxy: {
      '/api': {
        // Default to localhost:8080 for local development
        // Docker sets VITE_API_TARGET=http://proxy-backend:8080
        // For Tailscale/remote access, create .env.local with:
        //   VITE_API_TARGET=http://your-hostname:8080
        target: process.env.VITE_API_TARGET || 'http://localhost:8080',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            // Forward original host so backend can build correct callback URLs.
            const originalHost = req.headers.host;
            if (originalHost) {
              proxyReq.setHeader('X-Forwarded-Host', originalHost);
            }
            // Pass through the protocol ngrok/cloudflare set (https), not
            // a hardcoded 'http' which would cause backend to build http:// URLs.
            const originalProto = req.headers['x-forwarded-proto'];
            if (originalProto) {
              proxyReq.setHeader('X-Forwarded-Proto', originalProto);
            }
          });
        },
      },
      // Proxy OAuth endpoints to backend (for OAuth login flow)
      '/oauth': {
        target: process.env.VITE_API_TARGET || 'http://localhost:8080',
        changeOrigin: true,
      },
      // Proxy JSON-RPC requests to backend
      '/rpc': {
        target: process.env.VITE_API_TARGET || 'http://localhost:8080',
        changeOrigin: true,
      },
      // Proxy Privado wallet callback (POST /auth/callback) to backend.
      // Must NOT match /auth/azure/callback — that's a frontend SPA route.
      '/auth/callback': {
        target: process.env.VITE_API_TARGET || 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
