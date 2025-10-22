import { defineConfig } from '@playwright/test';

const workerBaseUrl = process.env.WORKER_BASE_URL ?? 'http://localhost:8788';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 20_000,
  use: {
    baseURL: workerBaseUrl
  }
});
