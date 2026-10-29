import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  cacheDir: '../.tools/cache/vite',
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/docs': 'http://127.0.0.1:8000',
      '/openapi.json': 'http://127.0.0.1:8000',
    },
  },
  build: {
    outDir: '../vulnarena/web',
    emptyOutDir: true,
  },
  test: {
    environment: 'jsdom',
    clearMocks: true,
    include: ['src/**/*.test.js'],
  },
})
