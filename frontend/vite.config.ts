import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/mcp': {
        target: 'http://localhost:9090',
        changeOrigin: true,
      },
    },
  },
})
