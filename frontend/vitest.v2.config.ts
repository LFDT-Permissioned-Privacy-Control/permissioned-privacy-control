import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/v2/**/*.test.ts'], environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'https://ops.test' } },
  },
})
