import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': resolve(__dirname, 'src') } },
  test: {
    include: ['src/v2/**/*.test.{ts,tsx}'], environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'https://ops.test' } },
  },
})
