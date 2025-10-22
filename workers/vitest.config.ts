import { defineConfig } from 'vitest/config';
import path from 'node:path';
import fs from 'node:fs';
import type { Plugin } from 'vite';

const rawSqlPlugin: Plugin = {
  name: 'vitest-raw-sql-loader',
  enforce: 'pre',
  load(id) {
    if (id.endsWith('.sql')) {
      const sql = fs.readFileSync(id, 'utf-8');
      return {
        code: `export default ${JSON.stringify(sql)};`
      };
    }
    return null;
  }
};

export default defineConfig({
  test: {
    environment: 'node'
  },
  plugins: [rawSqlPlugin],
  resolve: {
    alias: {
      '@board-app/shared': path.resolve(__dirname, '../packages/shared/src')
    }
  }
});
