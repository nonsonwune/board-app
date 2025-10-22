import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    environment: 'node'
  },
  resolve: {
    alias: {
      '@board-app/shared': path.resolve(__dirname, '../packages/shared/src')
    }
  },
  esbuild: {
    loader: {
      '.sql': 'text'
    }
  }
});
