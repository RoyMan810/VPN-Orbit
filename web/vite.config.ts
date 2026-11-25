import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    rolldownOptions: {
      onLog(level, log, handler) {
        // Mantine's client directives are handled by this browser-only bundle.
        if (log.code === 'MODULE_LEVEL_DIRECTIVE' && log.message.includes('node_modules/@mantine/')) return
        handler(level, log)
      },
    },
  },
})
