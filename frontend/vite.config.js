import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 3002,
    proxy: {
      '/api': { target: 'http://localhost:5555', changeOrigin: true },
      '/import': { target: 'http://localhost:5555', changeOrigin: true },
      '/fix': { target: 'http://localhost:5555', changeOrigin: true },
      '/rules': { target: 'http://localhost:5555', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})