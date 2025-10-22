import { defineConfig } from 'vite';
import path from 'node:path';

export default defineConfig({
  plugins: [],
  resolve: {
    alias: {
      '@board-app/shared': path.resolve(__dirname, '../packages/shared/src')
    }
  },
  build: {
    rollupOptions: {
      input: path.resolve(__dirname, 'src/index.ts')
    }
  }
});
