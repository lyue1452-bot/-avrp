import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 与 config.py 中 RAYSCAN_API_PORT 默认 6666 保持一致
const API_TARGET = process.env.RAYSCAN_API_TARGET || 'http://127.0.0.1:6666'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 3002,
    proxy: {
      '/api': { target: API_TARGET, changeOrigin: true },
      '/import': { target: API_TARGET, changeOrigin: true },
      '/fix': { target: API_TARGET, changeOrigin: true },
      '/rules': { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})